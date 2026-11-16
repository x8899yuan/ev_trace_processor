import pytest

from services.din70121_exi_grammar import DIN_NAMESPACE
from services.v2g_exi_decoder_service import V2GExiDecoderService


@pytest.fixture
def decoder():
    return V2GExiDecoderService()


def test_supported_app_protocol_request(decoder):
    result = decoder.decode(decoder.PACKET_93_REQUEST)
    assert result.kind == "SupportedAppProtocolReq"
    assert result.status == "decoded"
    assert result.protocol == decoder.APP_PROTOCOL_NAMESPACE
    assert [candidate.namespace for candidate in result.protocols] == [
        DIN_NAMESPACE,
        decoder.ISO_15118_2_NAMESPACE,
    ]


def test_supported_app_protocol_response_selects_din(decoder):
    result = decoder.decode(decoder.PACKET_95_RESPONSE)
    assert result.kind == "SupportedAppProtocolRes"
    assert result.status == "decoded"
    assert result.response_code == "OK_SuccessfulNegotiation"
    assert result.selected_schema_id == 0
    assert result.selected_namespace == DIN_NAMESPACE


def test_resolve_selected_protocol_returns_din(decoder):
    request = decoder.decode(decoder.PACKET_93_REQUEST)
    response = decoder.decode(decoder.PACKET_95_RESPONSE)
    selected = decoder.resolve_selected_protocol(request, response)
    assert selected is not None
    assert selected.namespace == DIN_NAMESPACE
    assert selected.schema_id == 0


@pytest.mark.parametrize(
    ("payload_hex", "message_name"),
    [
        ("80 98 00 40 11 D0 19 20 C4 CC 00 10 C0 00", "SessionSetupReq"),
        ("80 98 02 0B 2A 48 8B 85 3E C0 68 11 E0 20 0C 00 80", "SessionSetupRes"),
        ("80 98 02 0B 2A 48 8B 85 3E C0 68 11 B8", "ServiceDiscoveryReq"),
        ("80 98 02 0B 2A 48 8B 85 3E C0 68 11 C0 01 20 04 82 03 20 01 14 51 00", "ServiceDiscoveryRes"),
        ("80 98 02 0B 2A 48 8B 85 3E C0 68 11 32 00 12 80", "ServicePaymentSelectionReq"),
        ("80 98 02 0B 2A 48 8B 85 3E C0 68 11 40 00", "ServicePaymentSelectionRes"),
        ("80 98 02 0B 2A 48 8B 85 3E C0 68 10 08", "ContractAuthenticationReq"),
        ("80 98 02 0B 2A 48 8B 85 3E C0 68 10 10 01 00", "ContractAuthenticationRes"),
        ("80 98 02 0B 2A 48 8B 85 3E C0 68 10 94 C8 00 00 00 B8 08 30 88 27 11 08 1E 03 E4 00", "ChargeParameterDiscoveryReq"),
        ("80 98 02 0B 2A 48 8B 85 3E C0 68 10 A0 01 00 12 00 00 20 28 C1 41 85 0C C0 10 AA 00 00 04 08 10 61 10 4E 0C 28 66 00 81 08 1E 03 E0 41 81 90 10 81 A0 1E 02 0C 05 00 83 01 40 30 C1 F4 02 00", "ChargeParameterDiscoveryRes"),
        ("80 98 02 0B 2A 48 8B 85 3E C0 68 10 31 00 17 00", "CableCheckReq"),
        ("80 98 02 0B 2A 48 8B 85 3E C0 68 10 40 00 00 00 20 41 00", "CableCheckRes"),
        ("80 98 02 0B 2A 48 8B 85 3E C0 68 11 71 00 17 01 08 18 03 60 41 80 A0 00", "PreChargeReq"),
        ("80 98 02 0B 2A 48 8B 85 3E C0 68 11 80 00 00 00 20 40 84 00 00 00", "PreChargeRes"),
        ("80 98 02 0B 2A 48 8B 85 3E C0 68 11 50 01 22 20 02 E1 00", "PowerDeliveryReq"),
        ("80 98 02 0B 2A 48 8B 85 3E C0 68 11 60 04 00 00 10 20", "PowerDeliveryRes"),
        ("80 98 02 0B 2A 48 8B 85 3E C0 68 10 D1 00 17 01 06 00 00 10 81 E0 3E 01 06 11 04 E4 02 04 00 00 40 80 00 08 40 F0 1F 00", "CurrentDemandReq"),
        ("80 98 02 0B 2A 48 8B 85 3E C0 68 10 E0 00 00 00 20 40 84 0B 61 B0 20 C0 00 00 00 21 03 C0 7C 04 18 44 13 81 85 0C C0 10 03 00 01 28", "CurrentDemandRes"),
    ],
)
def test_validated_din_vectors_decode_through_service(decoder, payload_hex, message_name):
    result = decoder.decode(bytes.fromhex(payload_hex), DIN_NAMESPACE)
    assert result.kind == message_name
    assert result.status == "decoded"
    assert result.protocol == "DIN 70121"
    assert result.selected_namespace == DIN_NAMESPACE
    assert result.exi_profile_candidate is True
    assert result.confidence in {
        "captured-vector",
        "sequence-correlated-captured-vector",
    }


def test_unknown_din_payload_preserves_grammar_pending(decoder):
    payload = bytes.fromhex("80 98 02 0B 2A 48 8B 85 3E C0 68 10 10 00 00")
    result = decoder.decode(payload, DIN_NAMESPACE)
    assert result.kind == "DIN_EXI"
    assert result.status == "grammar_pending"
    assert result.confidence == "context-proven"
    assert result.protocol == "DIN 70121"
    assert result.selected_namespace == DIN_NAMESPACE


def test_din_payload_without_protocol_context_is_not_assumed_din(decoder):
    payload = bytes.fromhex("80 98 02 0B 2A 48 8B 85 3E C0 68 11 B8")
    result = decoder.decode(payload)
    assert result.kind == "V2G_EXI"
    assert result.protocol is None
    assert result.selected_namespace is None


def test_inspect_with_negotiation_decodes_din_application_message(decoder):
    request = decoder.decode(decoder.PACKET_93_REQUEST)
    response = decoder.decode(decoder.PACKET_95_RESPONSE)
    payload = bytes.fromhex("80 98 02 0B 2A 48 8B 85 3E C0 68 11 71 00 17 01 08 18 03 60 41 80 A0 00")
    result = decoder.inspect_with_negotiation(payload, request, response)
    assert result.kind == "PreChargeReq"
    assert result.status == "decoded"
    assert result.protocol == "DIN 70121"
    assert result.selected_namespace == DIN_NAMESPACE


def test_empty_payload(decoder):
    result = decoder.decode(b"")
    assert result.kind == "unknown"
    assert result.status == "empty"
    assert result.payload_length == 0
    assert result.header_byte is None
