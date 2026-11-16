from __future__ import annotations

from dataclasses import dataclass


DIN_NAMESPACE = "urn:din:70121:2012:MsgDef"


@dataclass(frozen=True)
class DinGrammarEvent:
    name: str
    start_bit: int
    end_bit: int
    bits: str
    value: int
    confidence: str


@dataclass(frozen=True)
class DinGrammarResult:
    protocol: str
    version: str
    status: str
    confidence: str
    payload_length: int
    header_byte: int | None
    next_bit_position: int | None
    message_name: str | None
    events: tuple[DinGrammarEvent, ...]
    raw_hex: str
    diagnostic: str
    session_id_hex: str | None
    body_choice_value: int | None


class Din70121ExiGrammar:
    PROTOCOL = "DIN 70121"
    VERSION = "2.0"
    EXI_HEADER = 0x80

    SESSION_SETUP_REQ_VECTOR = bytes.fromhex(
        "80 98 00 40 11 D0 19 20 C4 CC 00 10 C0 00"
    )
    SESSION_SETUP_RES_VECTOR = bytes.fromhex(
        "80 98 02 0B 2A 48 8B 85 3E C0 68 11 E0 20 0C 00 80"
    )
    SERVICE_DISCOVERY_REQ_VECTOR = bytes.fromhex(
        "80 98 02 0B 2A 48 8B 85 3E C0 68 11 B8"
    )
    SERVICE_DISCOVERY_RES_VECTOR = bytes.fromhex(
        "80 98 02 0B 2A 48 8B 85 3E C0 68 11 C0 01 20 04 82 03 20 01 14 51 00"
    )
    SERVICE_PAYMENT_SELECTION_REQ_VECTOR = bytes.fromhex(
        "80 98 02 0B 2A 48 8B 85 3E C0 68 11 32 00 12 80"
    )
    SERVICE_PAYMENT_SELECTION_RES_VECTOR = bytes.fromhex(
        "80 98 02 0B 2A 48 8B 85 3E C0 68 11 40 00"
    )

    CONTRACT_AUTHENTICATION_REQ_VECTOR = bytes.fromhex(
        "80 98 02 0B 2A 48 8B 85 3E C0 68 10 08"
    )
    CONTRACT_AUTHENTICATION_RES_VECTOR = bytes.fromhex(
        "80 98 02 0B 2A 48 8B 85 3E C0 68 10 10 01 00"
    )

    CHARGE_PARAMETER_DISCOVERY_REQ_VECTOR = bytes.fromhex(
        "80 98 02 0B 2A 48 8B 85 3E C0 68 10 94 C8 00 00 00 B8 08 30 88 27 11 08 1E 03 E4 00"
    )
    CHARGE_PARAMETER_DISCOVERY_RES_VECTOR = bytes.fromhex(
        "80 98 02 0B 2A 48 8B 85 3E C0 68 10 A0 01 00 12 00 00 20 28 C1 41 85 0C C0 10 AA 00 00 04 08 10 61 10 4E 0C 28 66 00 81 08 1E 03 E0 41 81 90 10 81 A0 1E 02 0C 05 00 83 01 40 30 C1 F4 02 00"
    )

    CABLE_CHECK_REQ_VECTOR = bytes.fromhex(
        "80 98 02 0B 2A 48 8B 85 3E C0 68 10 31 00 17 00"
    )
    CABLE_CHECK_RES_VECTOR = bytes.fromhex(
        "80 98 02 0B 2A 48 8B 85 3E C0 68 10 40 00 00 00 20 41 00"
    )

    PRE_CHARGE_REQ_VECTOR = bytes.fromhex(
        "80 98 02 0B 2A 48 8B 85 3E C0 68 11 71 00 17 01 08 18 03 60 41 80 A0 00"
    )
    PRE_CHARGE_RES_VECTOR = bytes.fromhex(
        "80 98 02 0B 2A 48 8B 85 3E C0 68 11 80 00 00 00 20 40 84 00 00 00"
    )

    POWER_DELIVERY_REQ_VECTOR = bytes.fromhex(
        "80 98 02 0B 2A 48 8B 85 3E C0 68 11 50 01 22 20 02 E1 00"
    )
    POWER_DELIVERY_RES_VECTOR = bytes.fromhex(
        "80 98 02 0B 2A 48 8B 85 3E C0 68 11 60 04 00 00 10 20"
    )

    CURRENT_DEMAND_REQ_VECTOR = bytes.fromhex(
        "80 98 02 0B 2A 48 8B 85 3E C0 68 10 D1 00 17 01 06 00 00 10 81 E0 3E 01 06 11 04 E4 02 04 00 00 40 80 00 08 40 F0 1F 00"
    )
    CURRENT_DEMAND_RES_VECTOR = bytes.fromhex(
        "80 98 02 0B 2A 48 8B 85 3E C0 68 10 E0 00 00 00 20 40 84 0B 61 B0 20 C0 00 00 00 21 03 C0 7C 04 18 44 13 81 85 0C C0 10 03 00 01 28"
    )

    CAPTURED_VECTORS = {
        SESSION_SETUP_REQ_VECTOR: "SessionSetupReq",
        SESSION_SETUP_RES_VECTOR: "SessionSetupRes",
        SERVICE_DISCOVERY_REQ_VECTOR: "ServiceDiscoveryReq",
        SERVICE_DISCOVERY_RES_VECTOR: "ServiceDiscoveryRes",
        SERVICE_PAYMENT_SELECTION_REQ_VECTOR: "ServicePaymentSelectionReq",
        SERVICE_PAYMENT_SELECTION_RES_VECTOR: "ServicePaymentSelectionRes",
        CONTRACT_AUTHENTICATION_REQ_VECTOR: "ContractAuthenticationReq",
        CONTRACT_AUTHENTICATION_RES_VECTOR: "ContractAuthenticationRes",
        CHARGE_PARAMETER_DISCOVERY_REQ_VECTOR: "ChargeParameterDiscoveryReq",
        CHARGE_PARAMETER_DISCOVERY_RES_VECTOR: "ChargeParameterDiscoveryRes",
        CABLE_CHECK_REQ_VECTOR: "CableCheckReq",
        CABLE_CHECK_RES_VECTOR: "CableCheckRes",
        PRE_CHARGE_REQ_VECTOR: "PreChargeReq",
        PRE_CHARGE_RES_VECTOR: "PreChargeRes",
        POWER_DELIVERY_REQ_VECTOR: "PowerDeliveryReq",
        POWER_DELIVERY_RES_VECTOR: "PowerDeliveryRes",
        CURRENT_DEMAND_REQ_VECTOR: "CurrentDemandReq",
        CURRENT_DEMAND_RES_VECTOR: "CurrentDemandRes",
    }

    VECTOR_DIAGNOSTICS = {
        "SessionSetupReq": (
            "Captured-vector identification from packet 98: the first EV-to-EVSE "
            "DIN application request after successful SAP negotiation. General "
            "XSD-derived event decoding remains pending."
        ),
        "SessionSetupRes": (
            "Captured-vector identification from packet 100: the immediate DIN EXI "
            "response following the validated packet-98 SessionSetupReq. Packets "
            "100, 103, 105, 108, and 110 share the first 96 bits, but those bits are "
            "not labeled as SessionID or Body grammar until XSD-derived decoding is implemented."
        ),
        "ServiceDiscoveryReq": (
            "Sequence-correlated captured-vector identification from packet 103. "
            "The validated packet-98/100 SessionSetup pair anchors the real DIN session, "
            "and packet 103 is the next observed request in the DIN sequence. General "
            "XSD-derived Body-choice decoding remains pending."
        ),
        "ServiceDiscoveryRes": (
            "Sequence-correlated captured-vector identification from packet 105. "
            "Packet 105 is the observed response paired with packet-103 ServiceDiscoveryReq. "
            "General XSD-derived Body-choice decoding remains pending."
        ),
        "ServicePaymentSelectionReq": (
            "Sequence-correlated captured-vector identification from packet 108. "
            "The validated SessionSetup and ServiceDiscovery pairs anchor the preceding "
            "DIN sequence, and packet 108 is the next observed request. General "
            "XSD-derived Body-choice decoding remains pending."
        ),
        "ServicePaymentSelectionRes": (
            "Sequence-correlated captured-vector identification from packet 110. "
            "Packet 110 is the observed response paired with packet-108 "
            "ServicePaymentSelectionReq. General XSD-derived Body-choice decoding remains pending."
        ),
        "ContractAuthenticationReq": (
            "Sequence-correlated captured-vector identification from packet 113 with repeated-pair support. "
            "All six preceding captured-vector anchors validate, and the same request payload repeats through "
            "packet 152. General XSD-derived Body-choice decoding remains pending."
        ),
        "ContractAuthenticationRes": (
            "Sequence-correlated captured-vector identification from packet 115 with repeated-pair support. "
            "The same response payload repeats through packet 149; packet 153 differs and is intentionally not "
            "treated as this exact captured vector. General XSD-derived field decoding remains pending."
        ),
        "ChargeParameterDiscoveryReq": (
            "Sequence-correlated captured-vector identification from packet 156 with repeated-pair support. "
            "All eight preceding captured-vector anchors validate, the authentication response changes at packet 153, "
            "and packet 161 exactly repeats this request. General XSD-derived field decoding remains pending."
        ),
        "ChargeParameterDiscoveryRes": (
            "Sequence-correlated captured-vector identification from packet 158 with repeated-pair support. "
            "Packet 163 exactly repeats this response paired with the repeated ChargeParameterDiscoveryReq. "
            "General XSD-derived field decoding remains pending."
        ),
        "CableCheckReq": (
            "Sequence-correlated captured-vector identification from packet 224 with repeated-pair support. "
            "All ten preceding captured-vector anchors validate, and sampled requests through packet 248 "
            "repeat this exact CableCheck request payload. General XSD-derived field decoding remains pending."
        ),
        "CableCheckRes": (
            "Sequence-correlated captured-vector identification from packet 228 with repeated-pair support. "
            "Sampled responses through packet 249 repeat this exact CableCheck response payload. "
            "General XSD-derived field decoding remains pending."
        ),
        "PreChargeReq": (
            "Sequence-correlated captured-vector identification from packet 909 with variable-loop support. "
            "All twelve preceding captured-vector anchors validate; packet 904 remains CableCheckReq while packet 906 "
            "changes CableCheck response state, and packets 909 through 1024 form a distinct variable PreCharge family. "
            "General XSD-derived field decoding remains pending."
        ),
        "PreChargeRes": (
            "Sequence-correlated captured-vector identification from packet 911 with variable-loop support. "
            "Subsequent PreCharge responses through packet 1024 retain the same structural family while encoded values vary. "
            "General XSD-derived field decoding remains pending."
        ),
        "PowerDeliveryReq": (
            "Sequence-correlated captured-vector identification from packet 1027 at the distinct post-PreCharge boundary. "
            "All preceding captured-vector anchors through PreCharge validate against the real capture. "
            "General XSD-derived ChargeProgress and field decoding remains pending."
        ),
        "PowerDeliveryRes": (
            "Sequence-correlated captured-vector identification from packet 1029 paired with packet-1027 PowerDeliveryReq. "
            "Packet 1032 begins a structurally distinct subsequent DIN message family. "
            "General XSD-derived EVSE status field decoding remains pending."
        ),
        "CurrentDemandReq": (
            "Sequence-correlated captured-vector identification from packet 1032 with variable charging-loop support. "
            "All preceding captured-vector anchors through PowerDelivery validate against the real capture, and subsequent "
            "requests retain the same broad CurrentDemand structure while encoded charging values vary. "
            "General XSD-derived field decoding remains pending."
        ),
        "CurrentDemandRes": (
            "Sequence-correlated captured-vector identification from packet 1034 with variable charging-loop support. "
            "Subsequent responses retain the same broad CurrentDemand structure while present current, voltage, and other "
            "encoded charging values vary. General XSD-derived field decoding remains pending."
        ),
    }

    def decode(self, payload: bytes | bytearray | memoryview) -> DinGrammarResult:
        data = bytes(payload)
        raw_hex = data.hex(" ").upper()

        if not data:
            return DinGrammarResult(
                protocol=self.PROTOCOL,
                version=self.VERSION,
                status="invalid",
                confidence="none",
                payload_length=0,
                header_byte=None,
                next_bit_position=None,
                message_name=None,
                events=(),
                raw_hex=raw_hex,
                diagnostic="Empty EXI payload.",
                session_id_hex=None,
                body_choice_value=None,
            )

        header = data[0]
        if header != self.EXI_HEADER:
            return DinGrammarResult(
                protocol=self.PROTOCOL,
                version=self.VERSION,
                status="unsupported_header",
                confidence="none",
                payload_length=len(data),
                header_byte=header,
                next_bit_position=None,
                message_name=None,
                events=(self._event("EXI header", data, 0, 8, "observed"),),
                raw_hex=raw_hex,
                diagnostic=f"Expected EXI header 0x{self.EXI_HEADER:02X}, found 0x{header:02X}.",
                session_id_hex=None,
                body_choice_value=None,
            )

        events = [self._event("EXI header", data, 0, 8, "decoded")]
        events.extend(self._candidate_events(data, 8))

        message_name = self.CAPTURED_VECTORS.get(data)
        if message_name is not None:
            confidence = (
                "captured-vector"
                if message_name.startswith("SessionSetup")
                else "sequence-correlated-captured-vector"
            )
            return DinGrammarResult(
                protocol=self.PROTOCOL,
                version=self.VERSION,
                status="vector_identified",
                confidence=confidence,
                payload_length=len(data),
                header_byte=header,
                next_bit_position=8,
                message_name=message_name,
                events=tuple(events),
                raw_hex=raw_hex,
                diagnostic=self.VECTOR_DIAGNOSTICS[message_name],
                session_id_hex=None,
                body_choice_value=None,
            )

        return DinGrammarResult(
            protocol=self.PROTOCOL,
            version=self.VERSION,
            status="grammar_pending",
            confidence="context-proven",
            payload_length=len(data),
            header_byte=header,
            next_bit_position=8,
            message_name=None,
            events=tuple(events),
            raw_hex=raw_hex,
            diagnostic=(
                "DIN 70121 context and EXI header are established. The Body-choice "
                "event-code width and ordering must come from the DIN XSD-derived "
                "schema grammar before a general message name is decoded."
            ),
            session_id_hex=None,
            body_choice_value=None,
        )

    def identify_captured_vector(
        self, payload: bytes | bytearray | memoryview
    ) -> str | None:
        return self.CAPTURED_VECTORS.get(bytes(payload))

    def _candidate_events(self, data: bytes, start_bit: int) -> list[DinGrammarEvent]:
        available = len(data) * 8 - start_bit
        events: list[DinGrammarEvent] = []
        for width in range(1, min(8, available) + 1):
            events.append(
                self._event(
                    f"post-header candidate width {width}",
                    data,
                    start_bit,
                    width,
                    "observed",
                )
            )
        return events

    def _event(
        self,
        name: str,
        data: bytes,
        start_bit: int,
        width: int,
        confidence: str,
    ) -> DinGrammarEvent:
        bits = self._bit_string(data, start_bit, width)
        return DinGrammarEvent(
            name=name,
            start_bit=start_bit,
            end_bit=start_bit + width,
            bits=bits,
            value=int(bits, 2),
            confidence=confidence,
        )

    @staticmethod
    def _bit_string(data: bytes, start_bit: int, width: int) -> str:
        end_bit = start_bit + width
        if start_bit < 0 or width < 1 or end_bit > len(data) * 8:
            raise ValueError("Requested bit range is outside the payload")

        result = []
        for position in range(start_bit, end_bit):
            byte_index, bit_index = divmod(position, 8)
            result.append(str((data[byte_index] >> (7 - bit_index)) & 1))
        return "".join(result)
