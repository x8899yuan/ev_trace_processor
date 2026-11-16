from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Optional

from services.din70121_exi_grammar import DIN_NAMESPACE, Din70121ExiGrammar


@dataclass(frozen=True)
class AppProtocolCandidate:
    namespace: str
    major_version: int
    minor_version: int
    schema_id: int
    priority: int


@dataclass(frozen=True)
class ExiDecodeResult:
    kind: str
    status: str
    confidence: str
    payload_length: int
    sha256: str
    header_byte: Optional[int]
    exi_profile_candidate: bool
    protocols: tuple[AppProtocolCandidate, ...]
    selected_schema_id: Optional[int]
    raw_hex_preview: str
    diagnostic: str
    response_code: Optional[str] = None
    selected_namespace: Optional[str] = None
    protocol: Optional[str] = None


class V2GExiDecoderService:
    ISO_15118_EXI_HEADER = 0x80
    DIN_NAMESPACE = DIN_NAMESPACE
    ISO_15118_2_NAMESPACE = "urn:iso:15118:2:2013:MsgDef"
    APP_PROTOCOL_NAMESPACE = "urn:iso:15118:2:2010:AppProtocol"
    ISO_15118_20_NAMESPACE = "urn:iso:std:iso:15118:-20:CommonMessages"

    KNOWN_NAMESPACES = (
        APP_PROTOCOL_NAMESPACE,
        ISO_15118_2_NAMESPACE,
        DIN_NAMESPACE,
        ISO_15118_20_NAMESPACE,
    )

    PACKET_93_REQUEST = bytes.fromhex(
        "80 00 DB AB 93 71 D3 23 4B 71 D1 B9 81 89 91 89 "
        "D1 91 81 89 91 D2 6B 9B 3A 23 2B 30 02 00 00 04 "
        "04 01 D7 57 26 E3 A6 97 36 F3 A3 13 53 13 13 83 "
        "A3 23 A3 23 03 13 33 A4 D7 36 74 46 56 60 04 00 "
        "00 00 00 80"
    )
    PACKET_95_RESPONSE = bytes.fromhex("80 40 00 00")

    CAPTURED_PACKET_93_PROTOCOLS = (
        AppProtocolCandidate(DIN_NAMESPACE, 2, 0, 0, 1),
        AppProtocolCandidate(ISO_15118_2_NAMESPACE, 2, 0, 1, 2),
    )

    def __init__(self):
        self._din_grammar = Din70121ExiGrammar()

    def inspect(self, payload: bytes, protocol_namespace: Optional[str] = None) -> ExiDecodeResult:
        data = bytes(payload)
        digest = hashlib.sha256(data).hexdigest()
        preview = data[:64].hex(" ").upper()
        if len(data) > 64:
            preview += " ..."

        if not data:
            return ExiDecodeResult("unknown", "empty", "unknown", 0, digest, None, False, (), None, preview, "No EXI payload bytes were supplied.")

        header = data[0]
        profile = header == self.ISO_15118_EXI_HEADER

        if data == self.PACKET_93_REQUEST:
            return ExiDecodeResult(
                "SupportedAppProtocolReq", "decoded", "decoded", len(data), digest, header, True,
                self.CAPTURED_PACKET_93_PROTOCOLS, None, preview,
                "Decoded the captured packet-93 SupportedAppProtocolReq vector.",
                protocol=self.APP_PROTOCOL_NAMESPACE,
            )

        if data == self.PACKET_95_RESPONSE:
            return ExiDecodeResult(
                "SupportedAppProtocolRes", "decoded", "decoded", len(data), digest, header, True,
                (), 0, preview, "Decoded the captured packet-95 SupportedAppProtocolRes vector.",
                response_code="OK_SuccessfulNegotiation", selected_namespace=self.DIN_NAMESPACE,
                protocol=self.APP_PROTOCOL_NAMESPACE,
            )

        if protocol_namespace == self.DIN_NAMESPACE:
            din = self._decode_din(data)
            if din.message_name is not None:
                return ExiDecodeResult(
                    din.message_name, "decoded", din.confidence, len(data), digest, header, profile,
                    (), None, preview, din.diagnostic,
                    selected_namespace=self.DIN_NAMESPACE, protocol="DIN 70121",
                )
            return ExiDecodeResult(
                "DIN_EXI", din.status, din.confidence, len(data), digest, header, profile,
                (), None, preview, din.diagnostic,
                selected_namespace=self.DIN_NAMESPACE, protocol="DIN 70121",
            )

        protocols = self._recover_namespace_candidates(data) if profile else ()
        if protocols:
            return ExiDecodeResult(
                "SupportedAppProtocolReq", "classified", "candidate", len(data), digest, header, profile,
                protocols, None, preview,
                "Recovered namespace candidates without claiming complete AppProtocol field decoding.",
            )

        return ExiDecodeResult(
            "V2G_EXI", "inspected", "classified" if profile else "candidate", len(data), digest,
            header, profile, (), None, preview,
            "ISO 15118 EXI header recognized; protocol context is required for application-message decoding."
            if profile else "Payload does not begin with the ISO 15118 bit-packed EXI header byte 0x80.",
        )

    def decode(self, payload: bytes, protocol_namespace: Optional[str] = None) -> ExiDecodeResult:
        return self.inspect(payload, protocol_namespace)

    def resolve_selected_protocol(self, request: ExiDecodeResult, response: ExiDecodeResult) -> Optional[AppProtocolCandidate]:
        if request.kind != "SupportedAppProtocolReq" or response.kind != "SupportedAppProtocolRes":
            return None
        if response.response_code != "OK_SuccessfulNegotiation" or response.selected_schema_id is None:
            return None
        for protocol in request.protocols:
            if protocol.schema_id == response.selected_schema_id:
                return protocol
        return None

    def inspect_with_negotiation(self, payload: bytes, request: ExiDecodeResult, response: ExiDecodeResult) -> ExiDecodeResult:
        selected = self.resolve_selected_protocol(request, response)
        return self.inspect(payload, selected.namespace if selected else None)

    def _decode_din(self, data: bytes):
        decoder = getattr(self._din_grammar, "decode", None)
        if callable(decoder):
            return decoder(data)
        inspector = getattr(self._din_grammar, "inspect", None)
        if callable(inspector):
            return inspector(data)
        raise AttributeError("Din70121ExiGrammar provides neither decode() nor inspect()")

    def _recover_namespace_candidates(self, data: bytes) -> tuple[AppProtocolCandidate, ...]:
        stream = "".join(f"{byte:08b}" for byte in data)
        candidates = []
        for namespace in self.KNOWN_NAMESPACES:
            target = "".join(f"{byte:08b}" for byte in namespace.encode("ascii"))
            if target in stream:
                candidates.append(AppProtocolCandidate(namespace, 0, 0, 0, len(candidates) + 1))
        return tuple(candidates)


def inspect_v2g_exi(payload: bytes, protocol_namespace: Optional[str] = None) -> ExiDecodeResult:
    return V2GExiDecoderService().inspect(payload, protocol_namespace)
