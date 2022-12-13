import os
import json
import typing as T

def readfile(filepath: str) -> bytes:
    with open(filepath, "rb") as fh:
        return fh.read()

def hexdump(data: bytes, offset: int = 0) -> str:
    lines = []
    step = 0x10
    for i in range(0, len(data), step):
        chunk = data[i : i + step]
        hexline = ""
        for byte in range(0, len(chunk)):
            if byte == step / 2:
                hexline += " "

            byte = hex(chunk[byte]).replace("0x", "")
            if len(byte) == 1:
                byte = "0" + byte

            hexline += byte + " "

        hexline += (step * 3 - len(hexline) + 1) * " "
        asciiline = ""
        for byte in chunk:
            if ord(" ") <= byte < ord("~"):
                asciiline += chr(byte)

            else:
                asciiline += "."

        asciiline += (step - len(asciiline)) * " "

        lines.append(f"{i + offset:#08x}: {hexline}|{asciiline}|")

    return "\n".join(lines)

def read_result_infos(result_hash: str) -> T.Dict[str, T.Any]:
    results_dir = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "results"))
    infos_path = os.path.join(results_dir, result_hash, "infos.json")
    if not os.path.exists(infos_path):
        return None

    with open(infos_path, "rt") as fh:
        return json.load(fh)