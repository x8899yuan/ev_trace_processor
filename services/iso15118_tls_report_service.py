from pathlib import Path

from services.iso15118_tls_analysis_service import Iso15118TlsAnalysisService


class Iso15118TlsReportService:
    DEFAULT_OUTPUT_DIR = Path(r"reports\pcap\iso15118")

    def __init__(self, analysis_service=None):
        self.analysis_service = analysis_service or Iso15118TlsAnalysisService()

    def generate(self, pcap_path, output_dir=None):
        pcap = Path(pcap_path)
        analysis = self.analysis_service.analyze(pcap)
        destination = Path(output_dir) if output_dir else self.DEFAULT_OUTPUT_DIR
        destination.mkdir(parents=True, exist_ok=True)

        reports = {
            "analysis_report": destination / "iso15118_tls_analysis_report.txt",
            "certificate_inventory": destination / "iso15118_tls_certificate_inventory.txt",
            "statistics": destination / "iso15118_tls_statistics.txt",
            "case_summary": destination / "iso15118_tls_case_summary.txt",
        }

        reports["analysis_report"].write_text(self._analysis_report(analysis), encoding="utf-8")
        reports["certificate_inventory"].write_text(self._certificate_inventory(analysis), encoding="utf-8")
        reports["statistics"].write_text(self._statistics(analysis), encoding="utf-8")
        reports["case_summary"].write_text(self._case_summary(analysis), encoding="utf-8")
        return reports

    def _analysis_report(self, a):
        lines = [
            "ISO 15118 TLS Analysis Report",
            "============================",
            "",
            f"Capture: {a['pcap']}",
            "Capture scope: standalone TLS/V2G evidence; no cross-trace vehicle correlation is assumed.",
            "",
            "TLS Session",
            "-----------",
            f"TLS detected: {a['tls_detected']}",
            f"TLS version: {a['tls_version'] or 'unknown'}",
            f"First TLS packet: {self._value(a['first_tls_packet'])}",
            f"Last TLS packet: {self._value(a['last_tls_packet'])}",
            f"First encrypted application-data packet: {self._value(a['first_application_data_packet'])}",
            f"Client: {self._endpoint(a['client'])}",
            f"Server: {self._endpoint(a['server'])}",
            f"Offered cipher suites: {', '.join(a['offered_cipher_suites']) or 'none recovered'}",
            f"Selected cipher suite: {a['selected_cipher_suite'] or 'unknown'}",
            "",
            "Handshake Anchors",
            "-----------------",
        ]
        lines.extend(f"Packet {item['packet']}: {item['name']}" for item in a["handshake_anchors"])
        lines.extend([
            "",
            "Authentication Observations",
            "---------------------------",
            f"TLS CertificateRequest seen: {a['certificate_request_seen']}",
            f"TLS client certificate seen: {a['tls_client_certificate_seen']}",
            f"Server certificates recovered: {len(a['server_certificates'])}",
            "The recovered certificates are TLS server-side certificate evidence and are not classified as ISO 15118 contract certificates.",
            "",
            "Application Visibility",
            "----------------------",
            f"TLS application data encrypted: {a['application_encrypted']}",
            f"Decryption keys available: {a['decryption_keys_available']}",
            f"ISO 15118 application decoding available: {a['iso15118_application_decoding_available']}",
            "Encrypted ISO 15118 application messages are not inferred or assigned message types without decryption evidence.",
            "",
        ])
        return "\n".join(lines)

    def _certificate_inventory(self, a):
        lines = [
            "ISO 15118 TLS Certificate Inventory",
            "===================================",
            "",
            f"Capture: {a['pcap']}",
            f"Certificates recovered: {len(a['server_certificates'])}",
            "Certificate role: TLS server/SECC-side chain evidence; not an ISO 15118 contract-certificate inventory.",
        ]
        for index, cert in enumerate(a["server_certificates"], start=1):
            public_key = cert.get("public_key") or {}
            public_key_text = public_key.get("algorithm", "unknown")
            if public_key.get("curve"):
                public_key_text += f" curve={public_key['curve']}"
            if public_key.get("key_size"):
                public_key_text += f" key_size={public_key['key_size']}"
            lines.extend([
                "",
                f"Certificate {index}",
                "-------------",
                f"TLS packet: {self._value(cert.get('packet'))}",
                f"DER length: {cert.get('der_length')}",
                f"SHA-256: {cert.get('sha256')}",
                f"Subject: {cert.get('subject')}",
                f"Issuer: {cert.get('issuer')}",
                f"Serial number: {cert.get('serial_number')}",
                f"Not valid before: {cert.get('not_valid_before')}",
                f"Not valid after: {cert.get('not_valid_after')}",
                f"Signature algorithm: {cert.get('signature_algorithm')} ({cert.get('signature_algorithm_oid')})",
                f"Public key: {public_key_text}",
                f"Self-issued: {cert.get('self_issued')}",
                f"CA: {cert.get('is_ca')}",
                f"Path length: {self._value(cert.get('path_length'))}",
                f"Key usage: {', '.join(cert.get('key_usage') or []) or 'not present'}",
                f"Extended key usage: {', '.join(cert.get('extended_key_usage') or []) or 'not present'}",
                f"Subject key ID: {cert.get('subject_key_id') or 'not present'}",
                f"Authority key ID: {cert.get('authority_key_id') or 'not present'}",
            ])
        lines.extend(["", "Chain Relationships", "-------------------"])
        for relationship in a["certificate_chain_relationships"]:
            lines.append(
                f"Certificate {relationship['child_index']} -> Certificate {relationship['issuer_index']}: "
                f"issuer_subject_match={relationship['issuer_subject_match']}, "
                f"authority_subject_key_id_match={relationship['authority_subject_key_id_match']}"
            )
        if not a["certificate_chain_relationships"]:
            lines.append("No transmitted certificate-to-certificate relationships recovered.")
        lines.extend(["", "No private keys or full certificate contents are included.", ""])
        return "\n".join(lines)

    def _statistics(self, a):
        ca_count = sum(cert.get("is_ca") is True for cert in a["server_certificates"])
        leaf_count = sum(cert.get("is_ca") is False for cert in a["server_certificates"])
        complete_links = sum(
            item["issuer_subject_match"] and item["authority_subject_key_id_match"]
            for item in a["certificate_chain_relationships"]
        )
        lines = [
            "ISO 15118 TLS Statistics",
            "========================",
            "",
            f"Capture: {a['pcap']}",
            f"TLS detected: {a['tls_detected']}",
            f"TLS version: {a['tls_version'] or 'unknown'}",
            f"First TLS packet: {self._value(a['first_tls_packet'])}",
            f"Last TLS packet: {self._value(a['last_tls_packet'])}",
            f"Handshake anchors recovered: {len(a['handshake_anchors'])}",
            f"Server certificates recovered: {len(a['server_certificates'])}",
            f"Leaf certificates: {leaf_count}",
            f"CA certificates: {ca_count}",
            f"Validated transmitted chain links: {complete_links}/{len(a['certificate_chain_relationships'])}",
            f"TLS CertificateRequest seen: {a['certificate_request_seen']}",
            f"TLS client certificate seen: {a['tls_client_certificate_seen']}",
            f"TLS application data encrypted: {a['application_encrypted']}",
            f"Decryption keys available: {a['decryption_keys_available']}",
            f"ISO 15118 application decoding available: {a['iso15118_application_decoding_available']}",
            "",
        ]
        return "\n".join(lines)

    def _case_summary(self, a):
        chain = a["server_certificates"]
        leaf = chain[0] if chain else None
        tls_status = "CONFIRMED" if a["tls_detected"] else "NOT OBSERVED"
        client_cert_status = "CONFIRMED" if a["tls_client_certificate_seen"] else "NOT OBSERVED"
        visibility_status = "CONFIRMED" if a["iso15118_application_decoding_available"] else "INDETERMINATE"
        lines = [
            "ISO 15118 TLS Case Summary",
            "==========================",
            "",
            f"Capture: {a['pcap']}",
            "This capture is analyzed as an independent vehicle/test source. No relationship to the project's BLF, DLT, or other same-vehicle traces is assumed.",
            "",
            "What We Can Conclude",
            "--------------------",
            f"Secure TLS session established: {tls_status}",
            f"TLS version: {a['tls_version'] or 'unknown'}",
            f"Selected cipher suite: {a['selected_cipher_suite'] or 'unknown'}",
            f"TLS session packet range: {self._value(a['first_tls_packet'])}..{self._value(a['last_tls_packet'])}",
            f"First encrypted application-data packet: {self._value(a['first_application_data_packet'])}",
            "",
            "A secure TLS connection was established between the two V2G endpoints. The charging-station side presented a three-certificate server chain.",
        ]
        if leaf:
            lines.extend([
                f"TLS server leaf: {leaf['subject']}",
                f"TLS server issuer: {leaf['issuer']}",
                f"TLS server leaf SHA-256: {leaf['sha256']}",
            ])
        lines.extend([
            "The recovered TLS server chain is separate from an ISO 15118 vehicle contract-certificate chain.",
            "",
            "What The Capture Cannot Show",
            "----------------------------",
            "After the TLS handshake, charging communication continues inside encrypted TLS application data.",
            "No TLS session keys were found with the capture, so the encrypted ISO 15118 application messages cannot be decoded.",
            "Therefore PaymentDetails, Authorization, contract-certificate exchange, and Plug & Charge authorization cannot be confirmed or ruled out from this ciphertext alone.",
            "",
            "Engineering Conclusions",
            "-----------------------",
            f"TLS session established: {tls_status}",
            "TLS server certificate chain observed: CONFIRMED" if chain else "TLS server certificate chain observed: NOT OBSERVED",
            f"TLS client certificate used: {client_cert_status}",
            f"ISO 15118 application messages readable: {visibility_status}",
            "PaymentDetails observed: INDETERMINATE",
            "Contract certificate exchanged: INDETERMINATE",
            "PnC authorization completed: INDETERMINATE",
            "",
            "Overall Conclusion",
            "------------------",
            "The capture demonstrates a TLS-protected V2G charging session with charging-station-side certificate authentication.",
            "The encrypted application traffic prevents confirmation of the ISO 15118 Plug & Charge authentication sequence.",
            "PnC status: INDETERMINATE FROM AVAILABLE EVIDENCE",
            "Reason: TLS application data is encrypted and no TLS decryption keys are available.",
            "",
        ])
        return "\n".join(lines)

    def _endpoint(self, endpoint):
        if not endpoint:
            return "unknown"
        return f"{endpoint['ip']}:{endpoint['port']}"

    def _value(self, value):
        return "unknown" if value is None else str(value)
