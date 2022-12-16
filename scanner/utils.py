import os
import subprocess
import typing as T


def run_process(
    args: T.List[str],
    stdout: T.Union[T.BinaryIO, T.TextIO, int] = subprocess.PIPE,
    stderr: T.Union[T.BinaryIO, T.TextIO, int] = subprocess.PIPE,
    write: T.Optional[str] = None,
    **kwargs: T.Any,
) -> T.Tuple[int, str, str]:
    p = subprocess.Popen(
        args,
        universal_newlines=True,
        close_fds=False,
        stdout=stdout,
        stderr=stderr,
        **kwargs,
    )
    o, e = p.communicate(write)
    return p.returncode, o, e


def yield_files(from_dir: str) -> T.Iterator[str]:
    for root, _, files in os.walk(from_dir):
        for file in files:
            yield os.path.join(os.path.basename(root), file)


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
