import pytest

from services.iotecha_embedded_frame_classifier import (
    EmbeddedProtocol,
    IoTechaEmbeddedFrameClassifier,
)


@pytest.fixture
def classifier():
    return IoTechaEmbeddedFrameClassifier()


def build_ethernet_frame(
    payload: bytes,
    ethertype: int,
    destination: bytes = bytes.fromhex("001122334455"),
    source: bytes = bytes.fromhex("66778899aabb"),
) -> bytes:
    return destination + source + ethertype.to_bytes(2, "big") + payload


def build_homeplug_payload(
    mmtype: int,
    mmv: int = 0x01,
    payload: bytes = b"",
) -> bytes:
    return bytes([mmv]) + mmtype.to_bytes(2, "little") + payload


@pytest.mark.parametrize(
    ("mmtype", "expected_subtype"),
    [
        (0x6064, "CM_SLAC_PARM.REQ"),
        (0x6065, "CM_SLAC_PARM.CNF"),
        (0x606A, "CM_START_ATTEN_CHAR.IND"),
        (0x606E, "CM_ATTEN_CHAR.IND"),
        (0x606F, "CM_ATTEN_CHAR.RSP"),
        (0x6076, "CM_MNBC_SOUND.IND"),
        (0x607C, "CM_SLAC_MATCH.REQ"),
        (0x607D, "CM_SLAC_MATCH.CNF"),
        (0x6008, "CM_SET_KEY.REQ"),
        (0x6009, "CM_SET_KEY.CNF"),
    ],
)
def test_classifies_known_slac_messages(classifier, mmtype, expected_subtype):
    homeplug_payload = build_homeplug_payload(mmtype)
    frame = build_ethernet_frame(payload=homeplug_payload, ethertype=0x88E1)

    result = classifier.classify(frame)

    assert result.protocol == EmbeddedProtocol.SLAC
    assert result.confidence == 1.0
    assert result.offset == 0
    assert result.length == len(frame)
    assert result.subtype == expected_subtype

    evidence = {item.pattern: item.value for item in result.evidence}

    assert evidence["destination_mac"] == "00:11:22:33:44:55"
    assert evidence["source_mac"] == "66:77:88:99:aa:bb"
    assert evidence["ethertype"] == "0x88E1"
    assert evidence["homeplug_mmv"] == "0x01"
    assert evidence["homeplug_mmtype"] == f"0x{mmtype:04X}"


def test_classifies_unknown_homeplug_mmtype(classifier):
    mmtype = 0x1234
    frame = build_ethernet_frame(
        payload=build_homeplug_payload(mmtype),
        ethertype=0x88E1,
    )

    result = classifier.classify(frame)

    assert result.protocol == EmbeddedProtocol.HOMEPLUG
    assert result.confidence == 0.9
    assert result.subtype == "MMTYPE_0x1234"

    evidence = {item.pattern: item.value for item in result.evidence}

    assert evidence["ethertype"] == "0x88E1"
    assert evidence["homeplug_mmtype"] == "0x1234"


def test_classifies_non_homeplug_ethernet(classifier):
    frame = build_ethernet_frame(
        payload=bytes.fromhex("600000000000"),
        ethertype=0x86DD,
    )

    result = classifier.classify(frame)

    assert result.protocol == EmbeddedProtocol.ETHERNET
    assert result.confidence == 1.0
    assert result.subtype == "ETHERTYPE_0x86DD"


def test_classifies_truncated_ethernet_as_unknown(classifier):
    frame = bytes.fromhex("001122334455667788")

    result = classifier.classify(frame)

    assert result.protocol == EmbeddedProtocol.UNKNOWN
    assert result.confidence == 0.0
    assert result.subtype == "TRUNCATED_ETHERNET"
    assert result.length == len(frame)


def test_classifies_truncated_homeplug(classifier):
    frame = build_ethernet_frame(payload=b"\x01\x64", ethertype=0x88E1)

    result = classifier.classify(frame)

    assert result.protocol == EmbeddedProtocol.HOMEPLUG
    assert result.confidence == 0.7
    assert result.subtype == "TRUNCATED_HOMEPLUG"


def test_classifies_vlan_homeplug_slac(classifier):
    destination = bytes.fromhex("001122334455")
    source = bytes.fromhex("66778899aabb")
    vlan_tci = 0x0064
    inner_ethertype = 0x88E1
    homeplug_payload = build_homeplug_payload(0x607C)

    frame = (
        destination
        + source
        + (0x8100).to_bytes(2, "big")
        + vlan_tci.to_bytes(2, "big")
        + inner_ethertype.to_bytes(2, "big")
        + homeplug_payload
    )

    result = classifier.classify(frame)

    assert result.protocol == EmbeddedProtocol.SLAC
    assert result.confidence == 1.0
    assert result.subtype == "CM_SLAC_MATCH.REQ"

    evidence = {item.pattern: item.value for item in result.evidence}

    assert evidence["ethertype"] == "0x8100"
    assert evidence["vlan_tci"] == "0x0064"
    assert evidence["inner_ethertype"] == "0x88E1"
    assert evidence["homeplug_mmtype"] == "0x607C"


def test_classifies_qinq_homeplug_slac(classifier):
    destination = bytes.fromhex("001122334455")
    source = bytes.fromhex("66778899aabb")

    frame = (
        destination
        + source
        + (0x88A8).to_bytes(2, "big")
        + (0x0001).to_bytes(2, "big")
        + (0x88E1).to_bytes(2, "big")
        + build_homeplug_payload(0x6064)
    )

    result = classifier.classify(frame)

    assert result.protocol == EmbeddedProtocol.SLAC
    assert result.subtype == "CM_SLAC_PARM.REQ"


def test_classifies_truncated_vlan(classifier):
    destination = bytes.fromhex("001122334455")
    source = bytes.fromhex("66778899aabb")

    frame = destination + source + (0x8100).to_bytes(2, "big") + b"\x00"

    result = classifier.classify(frame)

    assert result.protocol == EmbeddedProtocol.ETHERNET
    assert result.confidence == 0.7
    assert result.subtype == "TRUNCATED_VLAN"


def test_preserves_external_offset(classifier):
    frame = build_ethernet_frame(
        payload=build_homeplug_payload(0x607D),
        ethertype=0x88E1,
    )

    result = classifier.classify(frame, offset=128)

    assert result.offset == 128

    evidence = {item.pattern: item.offset for item in result.evidence}

    assert evidence["destination_mac"] == 128
    assert evidence["source_mac"] == 134
    assert evidence["ethertype"] == 140
    assert evidence["homeplug_mmv"] == 142
    assert evidence["homeplug_mmtype"] == 143


def test_accepts_bytearray_input(classifier):
    frame = bytearray(
        build_ethernet_frame(
            payload=build_homeplug_payload(0x607C),
            ethertype=0x88E1,
        )
    )

    result = classifier.classify(frame)

    assert result.protocol == EmbeddedProtocol.SLAC
    assert result.subtype == "CM_SLAC_MATCH.REQ"
