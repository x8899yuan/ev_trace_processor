from __future__ import annotations

import struct
from pathlib import Path

import pytest

from services.din70121_exi_grammar import DIN_NAMESPACE
from services.v2g_exi_decoder_service import V2GExiDecoderService


PCAP = Path("data/pcap/20250401122302-700006-18-G3-PWR-LOSS-OLD-SOFT-msduEx.pcap")
V2GTP_EXI_PAYLOAD_TYPE = 0x8001

EXPECTED = {
    93: "SupportedAppProtocolReq",
    95: "SupportedAppProtocolRes",
    98: "SessionSetupReq",
    100: "SessionSetupRes",
    103: "ServiceDiscoveryReq",
    105: "ServiceDiscoveryRes",
    108: "ServicePaymentSelectionReq",
    110: "ServicePaymentSelectionRes",
    113: "ContractAuthenticationReq",
    115: "ContractAuthenticationRes",
    156: "ChargeParameterDiscoveryReq",
    158: "ChargeParameterDiscoveryRes",
    224: "CableCheckReq",
    228: "CableCheckRes",
    909: "PreChargeReq",
    911: "PreChargeRes",
    1027: "PowerDeliveryReq",
    1029: "PowerDeliveryRes",
    1032: "CurrentDemandReq",
    1034: "CurrentDemandRes",
}


def _read_endian(stream) -> str:
    header = stream.read(24)
    if len(header) != 24:
        raise ValueError("PCAP global header is incomplete")
    mapping = {
        b"\xd4\xc3\xb2\xa1": "<",
        b"\xa1\xb2\xc3\xd4": ">",
        b"\x4d\x3c\xb2\xa1": "<",
        b"\xa1\xb2\x3c\x4d": ">",
    }
    endian = mapping.get(header[:4])
    if endian is None:
        raise ValueError(f"Unsupported PCAP magic: {header[:4].hex()}")
    return endian


def _extract_target_payloads(path: Path, targets: set[int]) -> dict[int, bytes]:
    payloads = {}
    with path.open("rb") as stream:
        endian = _read_endian(stream)
        packet_number = 0
        while True:
            header = stream.read(16)
            if not header:
                break
            if len(header) != 16:
                raise ValueError("PCAP packet header is incomplete")
            _, _, captured_length, _ = struct.unpack(f"{endian}IIII", header)
            data = stream.read(captured_length)
            if len(data) != captured_length:
                raise ValueError("PCAP packet data is incomplete")
            packet_number += 1
            if packet_number not in targets:
                continue
            offset = 0
            while True:
                offset = data.find(b"\x01\xfe", offset)
                if offset < 0:
                    break
                if offset + 8 <= len(data):
                    payload_type = int.from_bytes(data[offset + 2:offset + 4], "big")
                    payload_length = int.from_bytes(data[offset + 4:offset + 8], "big")
                    begin = offset + 8
                    end = begin + payload_length
                    if payload_type == V2GTP_EXI_PAYLOAD_TYPE and payload_length and end <= len(data):
                        payloads[packet_number] = data[begin:end]
                        break
                offset += 2
    return payloads


@pytest.fixture(scope="module")
def real_payloads():
    if not PCAP.is_file():
        pytest.skip(f"Real MSDU PCAP not available: {PCAP}")
    payloads = _extract_target_payloads(PCAP, set(EXPECTED))
    assert set(payloads) == set(EXPECTED)
    return payloads


def test_real_msdu_negotiation_selects_din(real_payloads):
    decoder = V2GExiDecoderService()
    request = decoder.decode(real_payloads[93])
    response = decoder.decode(real_payloads[95])
    selected = decoder.resolve_selected_protocol(request, response)
    assert request.kind == "SupportedAppProtocolReq"
    assert response.kind == "SupportedAppProtocolRes"
    assert selected is not None
    assert selected.namespace == DIN_NAMESPACE


@pytest.mark.parametrize("packet_number", [98, 100, 103, 105, 108, 110, 113, 115, 156, 158, 224, 228, 909, 911, 1027, 1029, 1032, 1034])
def test_real_msdu_validated_din_anchor(real_payloads, packet_number):
    decoder = V2GExiDecoderService()
    request = decoder.decode(real_payloads[93])
    response = decoder.decode(real_payloads[95])
    result = decoder.inspect_with_negotiation(real_payloads[packet_number], request, response)
    assert result.kind == EXPECTED[packet_number]
    assert result.status == "decoded"
    assert result.protocol == "DIN 70121"
    assert result.selected_namespace == DIN_NAMESPACE


def test_real_msdu_corrected_precharge_vectors_match_capture(real_payloads):
    decoder = V2GExiDecoderService()
    assert real_payloads[909] == decoder._din_grammar.PRE_CHARGE_REQ_VECTOR
    assert real_payloads[911] == decoder._din_grammar.PRE_CHARGE_RES_VECTOR


def test_real_msdu_corrected_power_delivery_vectors_match_capture(real_payloads):
    decoder = V2GExiDecoderService()
    assert real_payloads[1027] == decoder._din_grammar.POWER_DELIVERY_REQ_VECTOR
    assert real_payloads[1029] == decoder._din_grammar.POWER_DELIVERY_RES_VECTOR


def test_real_msdu_current_demand_vectors_match_capture(real_payloads):
    decoder = V2GExiDecoderService()
    assert real_payloads[1032] == decoder._din_grammar.CURRENT_DEMAND_REQ_VECTOR
    assert real_payloads[1034] == decoder._din_grammar.CURRENT_DEMAND_RES_VECTOR
