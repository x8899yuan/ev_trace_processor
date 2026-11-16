from pathlib import Path
import dpkt

ROOT = Path(r"data\pcap")
V2GTP_VERSION = 0x01
V2GTP_INVERSE_VERSION = 0xFE
V2GTP_EXI = 0x8001
SAP_PREFIX = bytes.fromhex("80 00 db ab")
DIN_PREFIX = bytes.fromhex("80 98")


def extract_v2gtp(buf):
    messages = []
    for offset in range(max(0, len(buf) - 7)):
        if buf[offset] != V2GTP_VERSION or buf[offset + 1] != V2GTP_INVERSE_VERSION:
            continue
        payload_type = int.from_bytes(buf[offset + 2:offset + 4], "big")
        payload_length = int.from_bytes(buf[offset + 4:offset + 8], "big")
        end = offset + 8 + payload_length
        if end > len(buf):
            continue
        messages.append((offset, payload_type, buf[offset + 8:end]))
    return messages


def tcp_payloads_from_ipv6(buf):
    payloads = []
    for start in range(max(0, len(buf) - 40)):
        if buf[start] >> 4 != 6:
            continue
        payload_length = int.from_bytes(buf[start + 4:start + 6], "big")
        if buf[start + 6] != 6:
            continue
        ipv6_end = start + 40 + payload_length
        if ipv6_end > len(buf):
            continue
        tcp_start = start + 40
        if tcp_start + 20 > ipv6_end:
            continue
        data_offset = (buf[tcp_start + 12] >> 4) * 4
        if data_offset < 20:
            continue
        data_start = tcp_start + data_offset
        if data_start > ipv6_end:
            continue
        payload = buf[data_start:ipv6_end]
        if payload:
            payloads.append(payload)
    return payloads


def is_tls_record(payload):
    if len(payload) < 5:
        return False
    if payload[0] not in {20, 21, 22, 23}:
        return False
    if payload[1] != 3 or payload[2] not in {0, 1, 2, 3, 4}:
        return False
    length = int.from_bytes(payload[3:5], "big")
    return length <= len(payload) - 5


def open_reader(path):
    f = path.open("rb")
    try:
        try:
            return f, dpkt.pcap.Reader(f)
        except (ValueError, dpkt.dpkt.NeedData):
            f.seek(0)
            return f, dpkt.pcapng.Reader(f)
    except Exception:
        f.close()
        raise


def classify(exi, sap_packets, din_packets, non_din_packets, tls_packets):
    if not exi:
        return "NO_V2GTP_EXI"
    if sap_packets and din_packets and not non_din_packets:
        return "DIN_70121_LIKELY"
    if sap_packets and non_din_packets:
        return "NON_DIN_SESSION_CANDIDATE"
    if tls_packets:
        return "TLS_V2G_CANDIDATE"
    if din_packets and not sap_packets:
        return "DIN_TRAFFIC_NO_SAP_ANCHOR"
    return "UNCLASSIFIED_V2G_EXI"


def scan(path):
    exi = []
    tls_packets = []
    packet_count = 0
    handle, reader = open_reader(path)
    try:
        for packet_number, (_, raw) in enumerate(reader, start=1):
            packet_count = packet_number
            if any(is_tls_record(payload) for payload in tcp_payloads_from_ipv6(raw)):
                tls_packets.append(packet_number)
            for _, payload_type, payload in extract_v2gtp(raw):
                if payload_type == V2GTP_EXI:
                    exi.append((packet_number, payload))
    finally:
        handle.close()

    sap_packets = [packet for packet, payload in exi if payload.startswith(SAP_PREFIX)]
    din_packets = [packet for packet, payload in exi if payload.startswith(DIN_PREFIX)]
    first_sap = min(sap_packets) if sap_packets else None
    non_din_packets = [
        packet
        for packet, payload in exi
        if first_sap is not None and packet > first_sap and not payload.startswith(DIN_PREFIX) and len(payload) > 4
    ]
    likely = classify(exi, sap_packets, din_packets, non_din_packets, tls_packets)
    interesting = sorted(set(sap_packets + non_din_packets[:12] + tls_packets[:12]))
    return {
        "file": str(path),
        "packets": packet_count,
        "v2gtp": len(exi),
        "sap": sap_packets,
        "din": din_packets,
        "non_din": non_din_packets,
        "tls": tls_packets,
        "likely": likely,
        "interesting": interesting,
    }


def fmt_packets(values, limit=12):
    if not values:
        return "-"
    text = ",".join(str(v) for v in values[:limit])
    return text + (",..." if len(values) > limit else "")


def main():
    if not ROOT.exists():
        raise SystemExit(f"PCAP directory not found: {ROOT}")

    files = sorted(set(ROOT.rglob("*.pcap")) | set(ROOT.rglob("*.pcapng")))
    if not files:
        raise SystemExit(f"No .pcap or .pcapng files found under {ROOT}")

    results = []
    failures = []
    for path in files:
        try:
            results.append(scan(path))
        except Exception as exc:
            failures.append((path, f"{type(exc).__name__}: {exc}"))

    print(f"PCAP root: {ROOT}")
    print(f"Capture files: {len(files)}")
    print(f"Scanned: {len(results)}")
    print(f"Failures: {len(failures)}")
    print()
    print("=== V2G PROTOCOL SESSION INVENTORY ===")

    for result in results:
        print()
        print(f"PCAP          : {result['file']}")
        print(f"Packets       : {result['packets']}")
        print(f"V2GTP EXI     : {result['v2gtp']}")
        print(f"SAP candidates: {len(result['sap'])} [{fmt_packets(result['sap'])}]")
        print(f"DIN candidates: {len(result['din'])} [{fmt_packets(result['din'])}]")
        print(f"Non-DIN cand. : {len(result['non_din'])} [{fmt_packets(result['non_din'])}]")
        print(f"TLS candidates: {len(result['tls'])} [{fmt_packets(result['tls'])}]")
        print(f"Likely        : {result['likely']}")
        print(f"Interesting   : [{fmt_packets(result['interesting'], 24)}]")

    print()
    print("=== ISO 15118-2 / NON-DIN CANDIDATES ===")
    candidates = [r for r in results if r["likely"] in {"NON_DIN_SESSION_CANDIDATE", "TLS_V2G_CANDIDATE", "UNCLASSIFIED_V2G_EXI"}]
    if not candidates:
        print("No capture was automatically classified as a non-DIN or TLS V2G candidate.")
    else:
        for result in candidates:
            print(f"{result['likely']:26s} {result['file']}")
            print(f"  interesting packets: {fmt_packets(result['interesting'], 24)}")

    if failures:
        print()
        print("=== SCAN FAILURES ===")
        for path, error in failures:
            print(f"{path}: {error}")


if __name__ == "__main__":
    main()
