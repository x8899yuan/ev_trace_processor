from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class EmbeddedProtocol(str, Enum):
    ETHERNET = "ethernet"
    HOMEPLUG = "homeplug"
    SLAC = "slac"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ClassificationEvidence:
    offset: int
    pattern: str
    value: str


@dataclass
class EmbeddedFrameClassification:
    protocol: EmbeddedProtocol
    confidence: float
    offset: int
    length: int
    subtype: Optional[str] = None
    evidence: list[ClassificationEvidence] = field(default_factory=list)


class IoTechaEmbeddedFrameClassifier:
    ETHERTYPE_HOMEPLUG = 0x88E1
    ETHERTYPE_VLAN = 0x8100
    ETHERTYPE_QINQ = 0x88A8

    SLAC_MMTYPES = {
        0x6064: "CM_SLAC_PARM.REQ",
        0x6065: "CM_SLAC_PARM.CNF",
        0x606A: "CM_START_ATTEN_CHAR.IND",
        0x606E: "CM_ATTEN_CHAR.IND",
        0x606F: "CM_ATTEN_CHAR.RSP",
        0x6076: "CM_MNBC_SOUND.IND",
        0x607C: "CM_SLAC_MATCH.REQ",
        0x607D: "CM_SLAC_MATCH.CNF",
        0x6008: "CM_SET_KEY.REQ",
        0x6009: "CM_SET_KEY.CNF",
    }

    def classify(
        self,
        frame: bytes,
        offset: int = 0,
    ) -> EmbeddedFrameClassification:
        if not isinstance(frame, bytes):
            frame = bytes(frame)

        if len(frame) < 14:
            return self._unknown(
                frame=frame,
                offset=offset,
                subtype="TRUNCATED_ETHERNET",
            )

        ethertype = int.from_bytes(frame[12:14], "big")
        payload_offset = 14

        evidence = [
            ClassificationEvidence(
                offset=offset,
                pattern="destination_mac",
                value=self._format_mac(frame[0:6]),
            ),
            ClassificationEvidence(
                offset=offset + 6,
                pattern="source_mac",
                value=self._format_mac(frame[6:12]),
            ),
            ClassificationEvidence(
                offset=offset + 12,
                pattern="ethertype",
                value=f"0x{ethertype:04X}",
            ),
        ]

        if ethertype in {self.ETHERTYPE_VLAN, self.ETHERTYPE_QINQ}:
            if len(frame) < 18:
                return EmbeddedFrameClassification(
                    protocol=EmbeddedProtocol.ETHERNET,
                    confidence=0.7,
                    offset=offset,
                    length=len(frame),
                    subtype="TRUNCATED_VLAN",
                    evidence=evidence,
                )

            vlan_tci = int.from_bytes(frame[14:16], "big")
            ethertype = int.from_bytes(frame[16:18], "big")
            payload_offset = 18

            evidence.extend(
                [
                    ClassificationEvidence(
                        offset=offset + 14,
                        pattern="vlan_tci",
                        value=f"0x{vlan_tci:04X}",
                    ),
                    ClassificationEvidence(
                        offset=offset + 16,
                        pattern="inner_ethertype",
                        value=f"0x{ethertype:04X}",
                    ),
                ]
            )

        if ethertype == self.ETHERTYPE_HOMEPLUG:
            return self._classify_homeplug(
                frame=frame,
                payload_offset=payload_offset,
                offset=offset,
                evidence=evidence,
            )

        return EmbeddedFrameClassification(
            protocol=EmbeddedProtocol.ETHERNET,
            confidence=1.0,
            offset=offset,
            length=len(frame),
            subtype=f"ETHERTYPE_0x{ethertype:04X}",
            evidence=evidence,
        )

    def _classify_homeplug(
        self,
        frame: bytes,
        payload_offset: int,
        offset: int,
        evidence: list[ClassificationEvidence],
    ) -> EmbeddedFrameClassification:
        payload_length = len(frame) - payload_offset

        if payload_length < 3:
            return EmbeddedFrameClassification(
                protocol=EmbeddedProtocol.HOMEPLUG,
                confidence=0.7,
                offset=offset,
                length=len(frame),
                subtype="TRUNCATED_HOMEPLUG",
                evidence=evidence,
            )

        mmv = frame[payload_offset]
        mmtype = int.from_bytes(
            frame[payload_offset + 1:payload_offset + 3],
            "little",
        )

        evidence = [
            *evidence,
            ClassificationEvidence(
                offset=offset + payload_offset,
                pattern="homeplug_mmv",
                value=f"0x{mmv:02X}",
            ),
            ClassificationEvidence(
                offset=offset + payload_offset + 1,
                pattern="homeplug_mmtype",
                value=f"0x{mmtype:04X}",
            ),
        ]

        slac_subtype = self.SLAC_MMTYPES.get(mmtype)

        if slac_subtype is not None:
            return EmbeddedFrameClassification(
                protocol=EmbeddedProtocol.SLAC,
                confidence=1.0,
                offset=offset,
                length=len(frame),
                subtype=slac_subtype,
                evidence=evidence,
            )

        return EmbeddedFrameClassification(
            protocol=EmbeddedProtocol.HOMEPLUG,
            confidence=0.9,
            offset=offset,
            length=len(frame),
            subtype=f"MMTYPE_0x{mmtype:04X}",
            evidence=evidence,
        )

    def _unknown(
        self,
        frame: bytes,
        offset: int,
        subtype: Optional[str] = None,
    ) -> EmbeddedFrameClassification:
        return EmbeddedFrameClassification(
            protocol=EmbeddedProtocol.UNKNOWN,
            confidence=0.0,
            offset=offset,
            length=len(frame),
            subtype=subtype,
        )

    @staticmethod
    def _format_mac(value: bytes) -> str:
        return ":".join(f"{byte:02x}" for byte in value)
