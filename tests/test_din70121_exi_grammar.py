import pytest

from services.din70121_exi_grammar import Din70121ExiGrammar


@pytest.fixture
def grammar():
    return Din70121ExiGrammar()


def test_session_setup_req_captured_vector(grammar):
    payload = bytes.fromhex("80 98 00 40 11 D0 19 20 C4 CC 00 10 C0 00")
    result = grammar.decode(payload)
    assert result.protocol == "DIN 70121"
    assert result.version == "2.0"
    assert result.status == "vector_identified"
    assert result.confidence == "captured-vector"
    assert result.payload_length == 14
    assert result.header_byte == 0x80
    assert result.next_bit_position == 8
    assert result.message_name == "SessionSetupReq"
    assert result.session_id_hex is None
    assert result.body_choice_value is None
    assert "packet 98".lower() in result.diagnostic.lower()


def test_session_setup_res_captured_vector(grammar):
    payload = bytes.fromhex("80 98 02 0B 2A 48 8B 85 3E C0 68 11 E0 20 0C 00 80")
    result = grammar.decode(payload)
    assert result.status == "vector_identified"
    assert result.confidence == "captured-vector"
    assert result.payload_length == 17
    assert result.message_name == "SessionSetupRes"
    assert result.session_id_hex is None
    assert result.body_choice_value is None
    assert "packet 100".lower() in result.diagnostic.lower()


def test_service_discovery_req_sequence_correlated_vector(grammar):
    payload = bytes.fromhex("80 98 02 0B 2A 48 8B 85 3E C0 68 11 B8")
    result = grammar.decode(payload)
    assert result.status == "vector_identified"
    assert result.confidence == "sequence-correlated-captured-vector"
    assert result.payload_length == 13
    assert result.message_name == "ServiceDiscoveryReq"
    assert "packet 103".lower() in result.diagnostic.lower()


def test_service_discovery_res_sequence_correlated_vector(grammar):
    payload = bytes.fromhex("80 98 02 0B 2A 48 8B 85 3E C0 68 11 C0 01 20 04 82 03 20 01 14 51 00")
    result = grammar.decode(payload)
    assert result.status == "vector_identified"
    assert result.confidence == "sequence-correlated-captured-vector"
    assert result.payload_length == 23
    assert result.message_name == "ServiceDiscoveryRes"
    assert "packet 105".lower() in result.diagnostic.lower()


def test_service_payment_selection_req_sequence_correlated_vector(grammar):
    payload = bytes.fromhex("80 98 02 0B 2A 48 8B 85 3E C0 68 11 32 00 12 80")
    result = grammar.decode(payload)
    assert result.status == "vector_identified"
    assert result.confidence == "sequence-correlated-captured-vector"
    assert result.payload_length == 16
    assert result.header_byte == 0x80
    assert result.next_bit_position == 8
    assert result.message_name == "ServicePaymentSelectionReq"
    assert result.session_id_hex is None
    assert result.body_choice_value is None
    assert "packet 108".lower() in result.diagnostic.lower()
    assert "ServiceDiscovery".lower() in result.diagnostic.lower()


def test_service_payment_selection_res_sequence_correlated_vector(grammar):
    payload = bytes.fromhex("80 98 02 0B 2A 48 8B 85 3E C0 68 11 40 00")
    result = grammar.decode(payload)
    assert result.status == "vector_identified"
    assert result.confidence == "sequence-correlated-captured-vector"
    assert result.payload_length == 14
    assert result.header_byte == 0x80
    assert result.next_bit_position == 8
    assert result.message_name == "ServicePaymentSelectionRes"
    assert result.session_id_hex is None
    assert result.body_choice_value is None
    assert "packet 110".lower() in result.diagnostic.lower()
    assert "ServicePaymentSelectionReq".lower() in result.diagnostic.lower()


def test_contract_authentication_req_sequence_correlated_vector(grammar):
    payload = bytes.fromhex("80 98 02 0B 2A 48 8B 85 3E C0 68 10 08")
    result = grammar.decode(payload)
    assert result.status == "vector_identified"
    assert result.confidence == "sequence-correlated-captured-vector"
    assert result.payload_length == 13
    assert result.header_byte == 0x80
    assert result.next_bit_position == 8
    assert result.message_name == "ContractAuthenticationReq"
    assert result.session_id_hex is None
    assert result.body_choice_value is None
    assert "packet 113".lower() in result.diagnostic.lower()
    assert "repeated-pair support".lower() in result.diagnostic.lower()


def test_contract_authentication_res_sequence_correlated_vector(grammar):
    payload = bytes.fromhex("80 98 02 0B 2A 48 8B 85 3E C0 68 10 10 01 00")
    result = grammar.decode(payload)
    assert result.status == "vector_identified"
    assert result.confidence == "sequence-correlated-captured-vector"
    assert result.payload_length == 15
    assert result.header_byte == 0x80
    assert result.next_bit_position == 8
    assert result.message_name == "ContractAuthenticationRes"
    assert result.session_id_hex is None
    assert result.body_choice_value is None
    assert "packet 115".lower() in result.diagnostic.lower()
    assert "packet 153 differs".lower() in result.diagnostic.lower()


def test_charge_parameter_discovery_req_sequence_correlated_vector(grammar):
    payload = bytes.fromhex(
        "80 98 02 0B 2A 48 8B 85 3E C0 68 10 94 C8 00 00 00 B8 08 30 88 27 11 08 1E 03 E4 00"
    )
    result = grammar.decode(payload)
    assert result.status == "vector_identified"
    assert result.confidence == "sequence-correlated-captured-vector"
    assert result.payload_length == 28
    assert result.header_byte == 0x80
    assert result.next_bit_position == 8
    assert result.message_name == "ChargeParameterDiscoveryReq"
    assert result.session_id_hex is None
    assert result.body_choice_value is None
    assert "packet 156".lower() in result.diagnostic.lower()
    assert "packet 161".lower() in result.diagnostic.lower()


def test_charge_parameter_discovery_res_sequence_correlated_vector(grammar):
    payload = bytes.fromhex(
        "80 98 02 0B 2A 48 8B 85 3E C0 68 10 A0 01 00 12 00 00 20 28 C1 41 85 0C C0 10 AA 00 00 04 08 10 61 10 4E 0C 28 66 00 81 08 1E 03 E0 41 81 90 10 81 A0 1E 02 0C 05 00 83 01 40 30 C1 F4 02 00"
    )
    result = grammar.decode(payload)
    assert result.status == "vector_identified"
    assert result.confidence == "sequence-correlated-captured-vector"
    assert result.payload_length == 63
    assert result.header_byte == 0x80
    assert result.next_bit_position == 8
    assert result.message_name == "ChargeParameterDiscoveryRes"
    assert result.session_id_hex is None
    assert result.body_choice_value is None
    assert "packet 158".lower() in result.diagnostic.lower()
    assert "packet 163".lower() in result.diagnostic.lower()


def test_cable_check_req_sequence_correlated_vector(grammar):
    payload = bytes.fromhex("80 98 02 0B 2A 48 8B 85 3E C0 68 10 31 00 17 00")
    result = grammar.decode(payload)
    assert result.status == "vector_identified"
    assert result.confidence == "sequence-correlated-captured-vector"
    assert result.payload_length == 16
    assert result.header_byte == 0x80
    assert result.next_bit_position == 8
    assert result.message_name == "CableCheckReq"
    assert result.session_id_hex is None
    assert result.body_choice_value is None
    assert "packet 224".lower() in result.diagnostic.lower()
    assert "packet 248".lower() in result.diagnostic.lower()


def test_cable_check_res_sequence_correlated_vector(grammar):
    payload = bytes.fromhex("80 98 02 0B 2A 48 8B 85 3E C0 68 10 40 00 00 00 20 41 00")
    result = grammar.decode(payload)
    assert result.status == "vector_identified"
    assert result.confidence == "sequence-correlated-captured-vector"
    assert result.payload_length == 19
    assert result.header_byte == 0x80
    assert result.next_bit_position == 8
    assert result.message_name == "CableCheckRes"
    assert result.session_id_hex is None
    assert result.body_choice_value is None
    assert "packet 228".lower() in result.diagnostic.lower()
    assert "packet 249".lower() in result.diagnostic.lower()


def test_pre_charge_req_sequence_correlated_vector(grammar):
    payload = bytes.fromhex(
        "80 98 02 0B 2A 48 8B 85 3E C0 68 11 71 00 17 01 08 18 03 60 41 80 A0 00"
    )
    result = grammar.decode(payload)
    assert result.status == "vector_identified"
    assert result.confidence == "sequence-correlated-captured-vector"
    assert result.payload_length == 24
    assert result.header_byte == 0x80
    assert result.next_bit_position == 8
    assert result.message_name == "PreChargeReq"
    assert result.session_id_hex is None
    assert result.body_choice_value is None
    assert "packet 909" in result.diagnostic.lower()
    assert "packet 904" in result.diagnostic.lower()
    assert "packet 906" in result.diagnostic.lower()
    assert "1024" in result.diagnostic.lower()


def test_pre_charge_res_sequence_correlated_vector(grammar):
    payload = bytes.fromhex(
        "80 98 02 0B 2A 48 8B 85 3E C0 68 11 80 00 00 00 20 40 84 00 00 00"
    )
    result = grammar.decode(payload)
    assert result.status == "vector_identified"
    assert result.confidence == "sequence-correlated-captured-vector"
    assert result.payload_length == 22
    assert result.header_byte == 0x80
    assert result.next_bit_position == 8
    assert result.message_name == "PreChargeRes"
    assert result.session_id_hex is None
    assert result.body_choice_value is None
    assert "packet 911" in result.diagnostic.lower()
    assert "1024" in result.diagnostic.lower()


def test_power_delivery_req_sequence_correlated_vector(grammar):
    payload = bytes.fromhex(
        "80 98 02 0B 2A 48 8B 85 3E C0 68 11 50 01 22 20 02 E1 00"
    )
    result = grammar.decode(payload)
    assert result.status == "vector_identified"
    assert result.confidence == "sequence-correlated-captured-vector"
    assert result.payload_length == 19
    assert result.header_byte == 0x80
    assert result.next_bit_position == 8
    assert result.message_name == "PowerDeliveryReq"
    assert result.session_id_hex is None
    assert result.body_choice_value is None
    assert "1027" in result.diagnostic.lower()
    assert "precharge" in result.diagnostic.lower()


def test_power_delivery_res_sequence_correlated_vector(grammar):
    payload = bytes.fromhex(
        "80 98 02 0B 2A 48 8B 85 3E C0 68 11 60 04 00 00 10 20"
    )
    result = grammar.decode(payload)
    assert result.status == "vector_identified"
    assert result.confidence == "sequence-correlated-captured-vector"
    assert result.payload_length == 18
    assert result.header_byte == 0x80
    assert result.next_bit_position == 8
    assert result.message_name == "PowerDeliveryRes"
    assert result.session_id_hex is None
    assert result.body_choice_value is None
    assert "1029" in result.diagnostic.lower()
    assert "1032" in result.diagnostic.lower()


def test_current_demand_req_sequence_correlated_vector(grammar):
    payload = bytes.fromhex(
        "80 98 02 0B 2A 48 8B 85 3E C0 68 10 D1 00 17 01 06 00 00 10 81 E0 3E 01 06 11 04 E4 02 04 00 00 40 80 00 08 40 F0 1F 00"
    )
    result = grammar.decode(payload)
    assert result.status == "vector_identified"
    assert result.confidence == "sequence-correlated-captured-vector"
    assert result.payload_length == 40
    assert result.header_byte == 0x80
    assert result.next_bit_position == 8
    assert result.message_name == "CurrentDemandReq"
    assert result.session_id_hex is None
    assert result.body_choice_value is None
    assert "1032" in result.diagnostic.lower()
    assert "powerdelivery" in result.diagnostic.lower()
    assert "currentdemand" in result.diagnostic.lower()


def test_current_demand_res_sequence_correlated_vector(grammar):
    payload = bytes.fromhex(
        "80 98 02 0B 2A 48 8B 85 3E C0 68 10 E0 00 00 00 20 40 84 0B 61 B0 20 C0 00 00 00 21 03 C0 7C 04 18 44 13 81 85 0C C0 10 03 00 01 28"
    )
    result = grammar.decode(payload)
    assert result.status == "vector_identified"
    assert result.confidence == "sequence-correlated-captured-vector"
    assert result.payload_length == 44
    assert result.header_byte == 0x80
    assert result.next_bit_position == 8
    assert result.message_name == "CurrentDemandRes"
    assert result.session_id_hex is None
    assert result.body_choice_value is None
    assert "1034" in result.diagnostic.lower()
    assert "currentdemand" in result.diagnostic.lower()


def test_identify_all_captured_vectors(grammar):
    vectors = {
        "80 98 00 40 11 D0 19 20 C4 CC 00 10 C0 00": "SessionSetupReq",
        "80 98 02 0B 2A 48 8B 85 3E C0 68 11 E0 20 0C 00 80": "SessionSetupRes",
        "80 98 02 0B 2A 48 8B 85 3E C0 68 11 B8": "ServiceDiscoveryReq",
        "80 98 02 0B 2A 48 8B 85 3E C0 68 11 C0 01 20 04 82 03 20 01 14 51 00": "ServiceDiscoveryRes",
        "80 98 02 0B 2A 48 8B 85 3E C0 68 11 32 00 12 80": "ServicePaymentSelectionReq",
        "80 98 02 0B 2A 48 8B 85 3E C0 68 11 40 00": "ServicePaymentSelectionRes",
        "80 98 02 0B 2A 48 8B 85 3E C0 68 10 08": "ContractAuthenticationReq",
        "80 98 02 0B 2A 48 8B 85 3E C0 68 10 10 01 00": "ContractAuthenticationRes",
        "80 98 02 0B 2A 48 8B 85 3E C0 68 10 94 C8 00 00 00 B8 08 30 88 27 11 08 1E 03 E4 00": "ChargeParameterDiscoveryReq",
        "80 98 02 0B 2A 48 8B 85 3E C0 68 10 A0 01 00 12 00 00 20 28 C1 41 85 0C C0 10 AA 00 00 04 08 10 61 10 4E 0C 28 66 00 81 08 1E 03 E0 41 81 90 10 81 A0 1E 02 0C 05 00 83 01 40 30 C1 F4 02 00": "ChargeParameterDiscoveryRes",
        "80 98 02 0B 2A 48 8B 85 3E C0 68 10 31 00 17 00": "CableCheckReq",
        "80 98 02 0B 2A 48 8B 85 3E C0 68 10 40 00 00 00 20 41 00": "CableCheckRes",
        "80 98 02 0B 2A 48 8B 85 3E C0 68 11 71 00 17 01 08 18 03 60 41 80 A0 00": "PreChargeReq",
        "80 98 02 0B 2A 48 8B 85 3E C0 68 11 80 00 00 00 20 40 84 00 00 00": "PreChargeRes",
        "80 98 02 0B 2A 48 8B 85 3E C0 68 11 50 01 22 20 02 E1 00": "PowerDeliveryReq",
        "80 98 02 0B 2A 48 8B 85 3E C0 68 11 60 04 00 00 10 20": "PowerDeliveryRes",
        "80 98 02 0B 2A 48 8B 85 3E C0 68 10 D1 00 17 01 06 00 00 10 81 E0 3E 01 06 11 04 E4 02 04 00 00 40 80 00 08 40 F0 1F 00": "CurrentDemandReq",
        "80 98 02 0B 2A 48 8B 85 3E C0 68 10 E0 00 00 00 20 40 84 0B 61 B0 20 C0 00 00 00 21 03 C0 7C 04 18 44 13 81 85 0C C0 10 03 00 01 28": "CurrentDemandRes",
    }
    for raw_hex, expected_name in vectors.items():
        assert grammar.identify_captured_vector(bytes.fromhex(raw_hex)) == expected_name




def test_packet153_remains_grammar_pending(grammar):
    payload = bytes.fromhex("80 98 02 0B 2A 48 8B 85 3E C0 68 10 10 00 00")
    result = grammar.decode(payload)
    assert result.status == "grammar_pending"
    assert result.confidence == "context-proven"
    assert result.message_name is None
    assert result.header_byte == 0x80
    assert result.next_bit_position == 8
    assert result.session_id_hex is None
    assert result.body_choice_value is None
    assert grammar.identify_captured_vector(payload) is None


def test_exi_header_and_candidate_events_are_preserved(grammar):
    payload = bytes.fromhex("80 98 02 0B 2A 48 8B 85 3E C0 68 11 32 00 12 80")
    result = grammar.decode(payload)
    assert result.events[0].name == "EXI header"
    assert result.events[0].start_bit == 0
    assert result.events[0].end_bit == 8
    assert result.events[0].bits == "10000000"
    assert result.events[0].value == 0x80
    assert result.events[0].confidence == "decoded"
    candidates = result.events[1:]
    assert len(candidates) == 8
    assert [event.end_bit - event.start_bit for event in candidates] == list(range(1, 9))
    assert candidates[-1].bits == "10011000"
    assert candidates[-1].value == 0x98


def test_empty_payload_is_invalid(grammar):
    result = grammar.decode(b"")
    assert result.status == "invalid"
    assert result.confidence == "none"
    assert result.payload_length == 0
    assert result.header_byte is None
    assert result.next_bit_position is None
    assert result.message_name is None
    assert result.events == ()


def test_unsupported_exi_header(grammar):
    result = grammar.decode(bytes.fromhex("00 98 02 0B"))
    assert result.status == "unsupported_header"
    assert result.confidence == "none"
    assert result.header_byte == 0x00
    assert result.next_bit_position is None
    assert result.message_name is None
    assert len(result.events) == 1
    assert result.events[0].name == "EXI header"
    assert result.events[0].confidence == "observed"
