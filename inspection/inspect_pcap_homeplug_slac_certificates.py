from collections import Counter
from hashlib import sha256
from pathlib import Path
import re

from readers.pcap_reader import PcapReader


PCAP_FILE = Path(
    r"data\pcap\20250401105700-700006-40-G4-PWR-LOSS-OLD-SOFT-raw.pcap"
)

SLAC_MMTYPES = {
    0x6064: "CM_SLAC_PARM.REQ",
    0x6065: "CM_SLAC_PARM.CNF",
    0x6068: "CM_START_ATTEN_CHAR.IND",
    0x606C: "CM_ATTEN_CHAR.IND",
    0x606D: "CM_ATTEN_CHAR.RSP",
    0x6076: "CM_SLAC_MATCH.REQ",
    0x6077: "CM_SLAC_MATCH.CNF",
    0x607C: "CM_SLAC_MATCH.REQ",
    0x607D: "CM_SLAC_MATCH.CNF",
    0x6086: "CM_SET_KEY.REQ",
    0x6087: "CM_SET_KEY.CNF",
    0x6090: "CM_MNBC_SOUND.IND",
    0x6094: "CM_VALIDATE.REQ",
    0x6095: "CM_VALIDATE.CNF",
}

ASN1_CERT_SEQUENCE = re.compile(rb"\x30\x82(..)", re.DOTALL)
PEM_CERTIFICATE = re.compile(
    rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.DOTALL,
)


def mac_text(value: bytes) -> str:
    return ":".join(f"{part:02x}" for part in value)


def printable_strings(data: bytes, minimum_length: int = 6) -> list[str]:
    results = []
    current = bytearray()

    for value in data:
        if 32 <= value <= 126:
            current.append(value)
        else:
            if len(current) >= minimum_length:
                results.append(current.decode("ascii", errors="ignore"))
            current.clear()

    if len(current) >= minimum_length:
        results.append(current.decode("ascii", errors="ignore"))

    return results


def certificate_candidates(data: bytes) -> list[dict]:
    results = []

    for match in ASN1_CERT_SEQUENCE.finditer(data):
        length = int.from_bytes(match.group(1), "big")
        total_length = length + 4
        start = match.start()
        end = start + total_length

        if total_length < 128 or end > len(data):
            continue

        candidate = data[start:end]
        results.append(
            {
                "encoding": "DER-candidate",
                "offset": start,
                "length": total_length,
                "sha256": sha256(candidate).hexdigest(),
            }
        )

    for match in PEM_CERTIFICATE.finditer(data):
        candidate = match.group(0)
        results.append(
            {
                "encoding": "PEM-candidate",
                "offset": match.start(),
                "length": len(candidate),
                "sha256": sha256(candidate).hexdigest(),
            }
        )

    return results


def homeplug_candidates(data: bytes) -> list[tuple[int, int, int, str | None]]:
    results = []

    for offset in range(min(len(data), 32)):
        if offset + 3 > len(data):
            break

        mmv = data[offset]
        mmtype = int.from_bytes(data[offset + 1:offset + 3], "little")

        if mmv > 2:
            continue

        name = SLAC_MMTYPES.get(mmtype)

        if name is not None or 0x6000 <= mmtype <= 0x60FF:
            results.append((offset, mmv, mmtype, name))

    return results


def main() -> None:
    trace = PcapReader().read(PCAP_FILE)

    homeplug_packets = 0
    raw_src_dst = Counter()
    mmtype_counts = Counter()
    mmtype_offsets = Counter()
    recognized_slac = Counter()
    unknown_homeplug = Counter()
    cert_hits = []
    interesting_strings = Counter()

    for index, event in enumerate(trace.events):
        payload = event.payload

        if payload.get("protocol") != "HOMEPLUG_AV":
            continue

        homeplug_packets += 1
        src_mac = payload.get("src_mac")
        dst_mac = payload.get("dst_mac")
        raw_src_dst[(src_mac, dst_mac)] += 1

        data = payload.get("ethernet_payload")

        if not isinstance(data, bytes):
            continue

        candidates = homeplug_candidates(data)

        if candidates:
            offset, mmv, mmtype, name = candidates[0]
            mmtype_counts[mmtype] += 1
            mmtype_offsets[offset] += 1

            if name:
                recognized_slac[name] += 1
            else:
                unknown_homeplug[mmtype] += 1

        for text in printable_strings(data):
            upper = text.upper()
            if any(
                token in upper
                for token in (
                    "SLAC",
                    "CERT",
                    "CONTRACT",
                    "EMAID",
                    "ISO15118",
                    "V2G",
                    "IOTECHA",
                    "SNIFFER",
                    "VEHICLE",
                    "EVSE",
                )
            ):
                interesting_strings[text] += 1

        for cert in certificate_candidates(data):
            cert_hits.append(
                {
                    "packet_index": index,
                    "timestamp": event.timestamp.isoformat(),
                    "src_mac": src_mac,
                    "dst_mac": dst_mac,
                    **cert,
                }
            )

    print("File:", PCAP_FILE)
    print("Packets:", trace.event_count)
    print("HomePlug AV packets:", homeplug_packets)
    print()

    print("Endpoint pairs")
    for (src, dst), count in raw_src_dst.most_common():
        print(f"  {src} -> {dst}: {count:,}")

    print()
    print("HomePlug candidate MMTYPEs")
    if not mmtype_counts:
        print("  None detected with current heuristic")
    else:
        for mmtype, count in mmtype_counts.most_common():
            name = SLAC_MMTYPES.get(mmtype, "unmapped")
            print(f"  0x{mmtype:04X}: {count:,} | {name}")

    print()
    print("Candidate HomePlug header offsets")
    if mmtype_offsets:
        for offset, count in mmtype_offsets.most_common():
            print(f"  offset {offset}: {count:,}")
    else:
        print("  None")

    print()
    print("Recognized SLAC candidates")
    if recognized_slac:
        for name, count in recognized_slac.most_common():
            print(f"  {name}: {count:,}")
    else:
        print("  None")

    print()
    print("Interesting printable strings")
    if interesting_strings:
        for text, count in interesting_strings.most_common(50):
            print(f"  {count:,} | {text}")
    else:
        print("  None")

    print()
    print("Certificate structure candidates")
    if cert_hits:
        for item in cert_hits[:50]:
            print(
                "  "
                f"packet={item['packet_index']} | "
                f"time={item['timestamp']} | "
                f"{item['src_mac']} -> {item['dst_mac']} | "
                f"{item['encoding']} | "
                f"offset={item['offset']} | "
                f"length={item['length']} | "
                f"sha256={item['sha256']}"
            )

        if len(cert_hits) > 50:
            print(f"  ... {len(cert_hits) - 50:,} additional candidates omitted")
    else:
        print("  None")

    print()
    print("Certificate candidate count:", len(cert_hits))


if __name__ == "__main__":
    main()
