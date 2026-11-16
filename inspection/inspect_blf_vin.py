from pathlib import Path

from readers.blf_reader import BlfReader
from services.dbc_decoder_service import DbcDecoderService


blf_file = Path(r"data\blf\VW31666_0173_20260508_140000h_Trace.blf")
dbc_file = Path(r"dbc\E3_1_1_UNECE_E3V_EVCANFD_KMatrix_V15_20230303_BAm.dbc")

trace = BlfReader().read(blf_file)
decoder = DbcDecoderService()

characters = {}
conflicts = {}
mux_values = set()
frame_count = 0

for event in trace.events:
    if event.event_name != "CAN_FRAME":
        continue

    if event.payload.get("arbitration_id") != 0x6B4:
        continue

    data = bytes.fromhex(event.payload["data"])
    decoded = decoder.decode_message(
        dbc_file,
        0x6B4,
        data,
    )

    frame_count += 1

    mux = decoded.get("VIN_01_MUX")
    if mux is not None:
        mux_values.add(mux)

    for position in range(1, 18):
        key = f"VIN_{position}"

        if key not in decoded:
            continue

        value = decoded[key]

        if not isinstance(value, (int, float)):
            continue

        value = int(value)

        if not 32 <= value <= 126:
            continue

        character = chr(value)

        if position in characters and characters[position] != character:
            conflicts.setdefault(position, set()).update(
                {characters[position], character}
            )
        else:
            characters[position] = character

vin = "".join(
    characters.get(position, "?")
    for position in range(1, 18)
)

print("VIN_01 frames decoded:", frame_count)
print("MUX values:", sorted(mux_values))
print("VIN characters:", characters)
print("VIN:", vin)
print("Conflicts:", conflicts or "None")