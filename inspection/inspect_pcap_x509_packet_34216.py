from hashlib import sha256
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from readers.pcap_reader import PcapReader


PCAP_FILE = Path(
    r"data\pcap\20250401105700-700006-40-G4-PWR-LOSS-OLD-SOFT-raw.pcap"
)
PACKET_INDEX = 34216
CERT_OFFSET = 184
CERT_LENGTH = 369


def public_key_description(certificate: x509.Certificate) -> str:
    key = certificate.public_key()

    if isinstance(key, rsa.RSAPublicKey):
        return f"RSA {key.key_size} bits"

    if isinstance(key, ec.EllipticCurvePublicKey):
        return f"EC {key.curve.name} {key.key_size} bits"

    return type(key).__name__


def extension_value(certificate: x509.Certificate, extension_type):
    try:
        return certificate.extensions.get_extension_for_class(extension_type).value
    except x509.ExtensionNotFound:
        return None


def main() -> None:
    trace = PcapReader().read(PCAP_FILE)

    if PACKET_INDEX < 0 or PACKET_INDEX >= len(trace.events):
        raise IndexError(
            f"Packet index {PACKET_INDEX} outside trace range 0..{len(trace.events) - 1}"
        )

    event = trace.events[PACKET_INDEX]
    payload = event.payload
    data = payload.get("ethernet_payload")

    if not isinstance(data, bytes):
        raise ValueError("Selected packet has no HomePlug Ethernet payload bytes")

    end = CERT_OFFSET + CERT_LENGTH
    if end > len(data):
        raise ValueError(
            f"Certificate candidate exceeds payload: offset={CERT_OFFSET}, "
            f"length={CERT_LENGTH}, payload_length={len(data)}"
        )

    candidate = data[CERT_OFFSET:end]

    print("File:", PCAP_FILE)
    print("Packet index:", PACKET_INDEX)
    print("Timestamp:", event.timestamp.isoformat())
    print("Source MAC:", payload.get("src_mac"))
    print("Destination MAC:", payload.get("dst_mac"))
    print("Candidate offset:", CERT_OFFSET)
    print("Candidate length:", len(candidate))
    print("Candidate SHA-256:", sha256(candidate).hexdigest())
    print()

    try:
        certificate = x509.load_der_x509_certificate(candidate)
    except ValueError as exc:
        print("X.509 parse result: INVALID")
        print("Parser error:", str(exc))
        return

    print("X.509 parse result: VALID")
    print("Subject:", certificate.subject.rfc4514_string() or "<empty>")
    print("Issuer:", certificate.issuer.rfc4514_string() or "<empty>")
    print("Serial number:", hex(certificate.serial_number))

    not_before = getattr(
        certificate,
        "not_valid_before_utc",
        certificate.not_valid_before,
    )
    not_after = getattr(
        certificate,
        "not_valid_after_utc",
        certificate.not_valid_after,
    )

    print("Not before:", not_before.isoformat())
    print("Not after:", not_after.isoformat())
    print("Public key:", public_key_description(certificate))
    print("Signature algorithm OID:", certificate.signature_algorithm_oid.dotted_string)
    print("Signature algorithm:", certificate.signature_algorithm_oid._name)
    print("Certificate SHA-256:", certificate.fingerprint(hashes.SHA256()).hex())
    print()

    basic_constraints = extension_value(certificate, x509.BasicConstraints)
    if basic_constraints is not None:
        print(
            "Basic constraints:",
            f"CA={basic_constraints.ca}, path_length={basic_constraints.path_length}",
        )
    else:
        print("Basic constraints: Not present")

    key_usage = extension_value(certificate, x509.KeyUsage)
    if key_usage is not None:
        values = []
        for name in (
            "digital_signature",
            "content_commitment",
            "key_encipherment",
            "data_encipherment",
            "key_agreement",
            "key_cert_sign",
            "crl_sign",
        ):
            if getattr(key_usage, name):
                values.append(name)
        print("Key usage:", ", ".join(values) if values else "None")
    else:
        print("Key usage: Not present")

    extended_key_usage = extension_value(certificate, x509.ExtendedKeyUsage)
    if extended_key_usage is not None:
        print("Extended key usage:")
        for oid in extended_key_usage:
            print(f"  {oid.dotted_string} | {oid._name}")
    else:
        print("Extended key usage: Not present")

    san = extension_value(certificate, x509.SubjectAlternativeName)
    if san is not None:
        print("Subject alternative names:")
        for item in san:
            print(f"  {type(item).__name__}: {item.value}")
    else:
        print("Subject alternative names: Not present")

    ski = extension_value(certificate, x509.SubjectKeyIdentifier)
    print(
        "Subject key identifier:",
        ski.digest.hex() if ski is not None else "Not present",
    )

    aki = extension_value(certificate, x509.AuthorityKeyIdentifier)
    print(
        "Authority key identifier:",
        aki.key_identifier.hex()
        if aki is not None and aki.key_identifier is not None
        else "Not present",
    )

    policies = extension_value(certificate, x509.CertificatePolicies)
    if policies is not None:
        print("Certificate policies:")
        for policy in policies:
            print(f"  {policy.policy_identifier.dotted_string}")
    else:
        print("Certificate policies: Not present")


if __name__ == "__main__":
    main()
