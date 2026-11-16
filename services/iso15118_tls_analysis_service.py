from collections import defaultdict
from pathlib import Path
import hashlib
import ipaddress

import dpkt
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa


class Iso15118TlsAnalysisService:
    TLS_TYPES = {20: "ChangeCipherSpec", 21: "Alert", 22: "Handshake", 23: "ApplicationData"}
    HANDSHAKE_TYPES = {
        1: "ClientHello",
        2: "ServerHello",
        11: "Certificate",
        12: "ServerKeyExchange",
        13: "CertificateRequest",
        14: "ServerHelloDone",
        15: "CertificateVerify",
        16: "ClientKeyExchange",
        20: "Finished",
    }

    def analyze(self, pcap_path):
        path = Path(pcap_path)
        if not path.exists():
            raise FileNotFoundError(path)

        flows = defaultdict(list)
        with path.open("rb") as handle:
            reader = self._open_reader(handle)
            for packet_number, (_, raw) in enumerate(reader, start=1):
                for segment in self._iter_ipv6_tcp(raw):
                    if segment["payload"]:
                        flow = (segment["src"], segment["sport"], segment["dst"], segment["dport"])
                        flows[flow].append((packet_number, segment["seq"], segment["payload"]))

        records = []
        handshakes = []
        certificates = []
        for flow, segments in flows.items():
            stream, ranges = self._reassemble(segments)
            for record in self._tls_records(stream, ranges):
                record["flow"] = flow
                records.append(record)
                if record["type"] != 22:
                    continue
                for handshake_type, body in self._handshakes(record["fragment"]):
                    item = {
                        "packet": record["packet"],
                        "flow": flow,
                        "type": handshake_type,
                        "name": self.HANDSHAKE_TYPES.get(handshake_type, f"Handshake({handshake_type})"),
                    }
                    if handshake_type == 1:
                        item.update(self._parse_client_hello(body))
                    elif handshake_type == 2:
                        item.update(self._parse_server_hello(body))
                    elif handshake_type == 11:
                        for der in self._certificate_list(body):
                            certificates.append(self._certificate_metadata(der, record["packet"], flow))
                    handshakes.append(item)

        records.sort(key=lambda item: (item["packet"] if item["packet"] is not None else 10**12, item["type"]))
        handshakes.sort(key=lambda item: item["packet"] if item["packet"] is not None else 10**12)
        tls_records = [item for item in records if item["packet"] is not None]
        first_application = next((item for item in tls_records if item["type"] == 23), None)
        client_hello = next((item for item in handshakes if item["type"] == 1), None)
        server_hello = next((item for item in handshakes if item["type"] == 2), None)
        certificate_request = next((item for item in handshakes if item["type"] == 13), None)
        client_certificate = self._find_client_certificate(handshakes, certificates, client_hello)

        result = {
            "pcap": str(path),
            "tls_detected": bool(tls_records),
            "first_tls_packet": tls_records[0]["packet"] if tls_records else None,
            "last_tls_packet": tls_records[-1]["packet"] if tls_records else None,
            "first_application_data_packet": first_application["packet"] if first_application else None,
            "client": self._endpoint(client_hello["flow"], True) if client_hello else None,
            "server": self._endpoint(client_hello["flow"], False) if client_hello else None,
            "tls_version": self._tls_version(server_hello or client_hello),
            "offered_cipher_suites": client_hello.get("cipher_suites", []) if client_hello else [],
            "selected_cipher_suite": server_hello.get("cipher_suite") if server_hello else None,
            "handshake_anchors": [{"packet": item["packet"], "name": item["name"]} for item in handshakes],
            "certificate_request_seen": certificate_request is not None,
            "tls_client_certificate_seen": client_certificate,
            "server_certificates": certificates,
            "certificate_chain_relationships": self._chain_relationships(certificates),
            "application_encrypted": first_application is not None,
            "decryption_keys_available": False,
            "iso15118_application_decoding_available": False,
        }
        return result

    def _open_reader(self, handle):
        try:
            return dpkt.pcap.Reader(handle)
        except (ValueError, dpkt.dpkt.NeedData):
            handle.seek(0)
            return dpkt.pcapng.Reader(handle)

    def _iter_ipv6_tcp(self, raw):
        seen = set()
        for start in range(max(0, len(raw) - 40)):
            if raw[start] >> 4 != 6 or raw[start + 6] != 6:
                continue
            payload_length = int.from_bytes(raw[start + 4:start + 6], "big")
            end = start + 40 + payload_length
            if end > len(raw):
                continue
            tcp = start + 40
            if tcp + 20 > end:
                continue
            header_length = (raw[tcp + 12] >> 4) * 4
            if header_length < 20 or tcp + header_length > end:
                continue
            key = (start, tcp, end)
            if key in seen:
                continue
            seen.add(key)
            yield {
                "src": str(ipaddress.IPv6Address(raw[start + 8:start + 24])),
                "dst": str(ipaddress.IPv6Address(raw[start + 24:start + 40])),
                "sport": int.from_bytes(raw[tcp:tcp + 2], "big"),
                "dport": int.from_bytes(raw[tcp + 2:tcp + 4], "big"),
                "seq": int.from_bytes(raw[tcp + 4:tcp + 8], "big"),
                "payload": raw[tcp + header_length:end],
            }

    def _reassemble(self, segments):
        by_seq = {}
        packet_by_seq = {}
        for packet, seq, payload in segments:
            if payload and (seq not in by_seq or len(payload) > len(by_seq[seq])):
                by_seq[seq] = payload
                packet_by_seq[seq] = packet
        if not by_seq:
            return b"", []
        output = bytearray()
        ranges = []
        cursor = min(by_seq)
        for seq in sorted(by_seq):
            payload = by_seq[seq]
            if seq > cursor:
                output.extend(b"\x00" * (seq - cursor))
                cursor = seq
            overlap = max(0, cursor - seq)
            if overlap >= len(payload):
                continue
            start = len(output)
            output.extend(payload[overlap:])
            end = len(output)
            ranges.append((start, end, packet_by_seq[seq]))
            cursor = seq + len(payload)
        return bytes(output), ranges

    def _packet_for_offset(self, ranges, offset):
        for start, end, packet in ranges:
            if start <= offset < end:
                return packet
        return None

    def _tls_records(self, stream, ranges):
        records = []
        pos = 0
        while pos + 5 <= len(stream):
            content_type, major, minor = stream[pos], stream[pos + 1], stream[pos + 2]
            if content_type not in self.TLS_TYPES or major != 3 or minor not in {0, 1, 2, 3, 4}:
                pos += 1
                continue
            length = int.from_bytes(stream[pos + 3:pos + 5], "big")
            end = pos + 5 + length
            if end > len(stream):
                break
            records.append({
                "packet": self._packet_for_offset(ranges, pos),
                "type": content_type,
                "name": self.TLS_TYPES[content_type],
                "major": major,
                "minor": minor,
                "length": length,
                "fragment": stream[pos + 5:end],
            })
            pos = end
        return records

    def _handshakes(self, fragment):
        pos = 0
        while pos + 4 <= len(fragment):
            handshake_type = fragment[pos]
            length = int.from_bytes(fragment[pos + 1:pos + 4], "big")
            end = pos + 4 + length
            if end > len(fragment):
                break
            yield handshake_type, fragment[pos + 4:end]
            pos = end

    def _parse_client_hello(self, body):
        result = {"legacy_version": None, "cipher_suites": []}
        if len(body) < 35:
            return result
        result["legacy_version"] = (body[0], body[1])
        pos = 34
        session_id_length = body[pos]
        pos += 1 + session_id_length
        if pos + 2 > len(body):
            return result
        suites_length = int.from_bytes(body[pos:pos + 2], "big")
        pos += 2
        for index in range(pos, min(pos + suites_length, len(body) - 1), 2):
            result["cipher_suites"].append(f"0x{int.from_bytes(body[index:index + 2], 'big'):04x}")
        return result

    def _parse_server_hello(self, body):
        result = {"legacy_version": None, "cipher_suite": None}
        if len(body) < 38:
            return result
        result["legacy_version"] = (body[0], body[1])
        pos = 34
        session_id_length = body[pos]
        pos += 1 + session_id_length
        if pos + 2 <= len(body):
            result["cipher_suite"] = f"0x{int.from_bytes(body[pos:pos + 2], 'big'):04x}"
        return result

    def _certificate_list(self, body):
        if len(body) < 3:
            return []
        total = int.from_bytes(body[:3], "big")
        pos = 3
        limit = min(len(body), 3 + total)
        result = []
        while pos + 3 <= limit:
            length = int.from_bytes(body[pos:pos + 3], "big")
            pos += 3
            end = pos + length
            if end > limit:
                break
            result.append(body[pos:end])
            pos = end
        return result

    def _certificate_metadata(self, der, packet, flow):
        cert = x509.load_der_x509_certificate(der)
        basic = self._extension(cert, x509.BasicConstraints)
        key_usage = self._extension(cert, x509.KeyUsage)
        extended_key_usage = self._extension(cert, x509.ExtendedKeyUsage)
        subject_key_id = self._extension(cert, x509.SubjectKeyIdentifier)
        authority_key_id = self._extension(cert, x509.AuthorityKeyIdentifier)
        return {
            "packet": packet,
            "flow": flow,
            "der_length": len(der),
            "sha256": hashlib.sha256(der).hexdigest(),
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "serial_number": f"0x{cert.serial_number:x}",
            "not_valid_before": cert.not_valid_before_utc.isoformat(),
            "not_valid_after": cert.not_valid_after_utc.isoformat(),
            "signature_algorithm_oid": cert.signature_algorithm_oid.dotted_string,
            "signature_algorithm": cert.signature_algorithm_oid._name or "unknown",
            "public_key": self._public_key_description(cert),
            "self_issued": cert.subject == cert.issuer,
            "is_ca": basic.ca if basic else None,
            "path_length": basic.path_length if basic else None,
            "key_usage": self._key_usage(key_usage),
            "extended_key_usage": [oid.dotted_string for oid in extended_key_usage] if extended_key_usage else [],
            "subject_key_id": subject_key_id.digest.hex() if subject_key_id else None,
            "authority_key_id": authority_key_id.key_identifier.hex() if authority_key_id and authority_key_id.key_identifier else None,
        }

    def _extension(self, cert, cls):
        try:
            return cert.extensions.get_extension_for_class(cls).value
        except x509.ExtensionNotFound:
            return None

    def _public_key_description(self, cert):
        key = cert.public_key()
        if isinstance(key, ec.EllipticCurvePublicKey):
            return {"algorithm": "EC", "curve": key.curve.name, "key_size": key.key_size}
        if isinstance(key, rsa.RSAPublicKey):
            return {"algorithm": "RSA", "key_size": key.key_size}
        if isinstance(key, dsa.DSAPublicKey):
            return {"algorithm": "DSA", "key_size": key.key_size}
        return {"algorithm": type(key).__name__}

    def _key_usage(self, usage):
        if not usage:
            return []
        enabled = []
        for name in ("digital_signature", "content_commitment", "key_encipherment", "data_encipherment", "key_agreement", "key_cert_sign", "crl_sign"):
            if getattr(usage, name):
                enabled.append(name)
        if usage.key_agreement:
            if usage.encipher_only:
                enabled.append("encipher_only")
            if usage.decipher_only:
                enabled.append("decipher_only")
        return enabled

    def _chain_relationships(self, certificates):
        result = []
        for index in range(len(certificates) - 1):
            child = certificates[index]
            issuer = certificates[index + 1]
            result.append({
                "child_index": index + 1,
                "issuer_index": index + 2,
                "issuer_subject_match": child["issuer"] == issuer["subject"],
                "authority_subject_key_id_match": bool(child["authority_key_id"] and issuer["subject_key_id"] and child["authority_key_id"] == issuer["subject_key_id"]),
            })
        return result

    def _find_client_certificate(self, handshakes, certificates, client_hello):
        if not client_hello:
            return False
        client_flow = client_hello["flow"]
        return any(cert["flow"] == client_flow for cert in certificates)

    def _endpoint(self, flow, source):
        if source:
            return {"ip": flow[0], "port": flow[1]}
        return {"ip": flow[2], "port": flow[3]}

    def _tls_version(self, hello):
        if not hello or not hello.get("legacy_version"):
            return None
        major, minor = hello["legacy_version"]
        mapping = {(3, 0): "SSL 3.0", (3, 1): "TLS 1.0", (3, 2): "TLS 1.1", (3, 3): "TLS 1.2", (3, 4): "TLS 1.3"}
        return mapping.get((major, minor), f"{major}.{minor}")
