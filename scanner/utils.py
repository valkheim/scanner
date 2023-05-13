import glob
import os
import pathlib
import subprocess
import time
import typing as T
import zipfile

import colorama


def run_process(
    args: list[str],
    stdout: T.Union[T.BinaryIO, T.TextIO, int] = subprocess.PIPE,
    stderr: T.Union[T.BinaryIO, T.TextIO, int] = subprocess.PIPE,
    write: str | None = None,
    **kwargs: T.Any,
) -> tuple[int, str, str]:
    start = time.perf_counter()
    p = subprocess.Popen(
        args,
        universal_newlines=True,
        close_fds=False,
        stdout=stdout,
        stderr=stderr,
        **kwargs,
    )
    o, e = p.communicate(write)
    end = time.perf_counter()
    status = f"{colorama.Fore.RED}KO{colorama.Style.RESET_ALL}"
    if p.returncode == 0:
        status = f"{colorama.Fore.GREEN}OK{colorama.Style.RESET_ALL}"

    print(
        f"[{status}] Process {args[0].split(os.sep)[-1]} ran in {round(end-start, 2)} second(s)"
    )
    return p.returncode, o, e


def yield_files(from_dir: str) -> T.Iterator[str]:
    for root, _, files in os.walk(from_dir):
        parts = root.split(os.sep)
        if any([x.startswith("_") for x in parts]):
            continue

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

            bytestr = hex(chunk[byte]).replace("0x", "")
            if len(bytestr) == 1:
                bytestr = "0" + bytestr

            hexline += bytestr + " "

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


def get_results_dir(hash: str | None = None) -> str:
    results_dir = os.path.normpath(
        os.path.join(os.path.dirname(__file__), "results")
    )

    if hash is not None:
        results_dir = os.path.join(results_dir, hash)

    os.makedirs(results_dir, exist_ok=True)
    return results_dir


def get_extractors_dir() -> str:
    return os.path.join(os.path.dirname(__file__), "extractors")


def archive(hash: str, infos: T.Dict[str, T.Any]) -> str:
    results_dir = get_results_dir()
    timestamp = infos["last_update"].replace(" ", "_").replace(":", "-")
    archive_filename = f"scanner-{hash}-{timestamp}.zip"
    archive_path = os.path.join(results_dir, archive_filename)
    if os.path.exists(archive_path):
        return archive_path

    directory = pathlib.Path(get_results_dir(hash))
    with zipfile.ZipFile(
        archive_path, "w", compression=zipfile.ZIP_BZIP2, compresslevel=9
    ) as archive:
        for filepath in directory.rglob("*"):
            archive.write(filepath, filepath.relative_to(directory))

    return archive_path


def resolve_extractor_path(result_relpath: str) -> str:
    result_abspath = os.path.join(get_results_dir(), result_relpath)
    prefix = os.sep.join(
        [
            "extractors" if x == "results" else x
            for x in os.path.dirname(result_abspath).split(os.sep)
        ]
    )
    return glob.glob(prefix + "*", recursive=False)[0]
