import glob
import os
import subprocess
import typing as T


def run_process(
    args: T.List[str],
    stdout: T.Union[T.BinaryIO, T.TextIO, int] = subprocess.PIPE,
    stderr: T.Union[T.BinaryIO, T.TextIO, int] = subprocess.PIPE,
    write: T.Optional[str] = None,
    **kwargs: T.Any
) -> T.Tuple[int, str, str]:
    p = subprocess.Popen(
        args,
        universal_newlines=True,
        close_fds=False,
        stdout=stdout,
        stderr=stderr,
        **kwargs
    )
    o, e = p.communicate(write)
    return p.returncode, o, e


def yield_files(from_dir: str) -> T.Iterator[str]:
    for root, _, files in os.walk(from_dir):
        for file in files:
            yield os.path.join(os.path.basename(root), file)


def run_extractors(filepath: str) -> None:
    extractors_dir = os.path.join(os.path.dirname(__file__), "extractors")
    for extractor_relpath in yield_files(extractors_dir):
        extractor_abspath = os.path.join(extractors_dir, extractor_relpath)
        parts = extractor_relpath.split(os.sep)
        if any([x.startswith("_") for x in parts]):
            continue

        results_absdir = os.path.join(
            os.path.dirname(filepath),
            *parts[:-1],
            ".".join(parts[-1].split(".")[:-1])
        )
        os.makedirs(results_absdir, exist_ok=True)
        with open(os.path.join(results_absdir, "stdout.log"), "wt") as stdout:
            with open(
                os.path.join(results_absdir, "stderr.log"), "wt"
            ) as stderr:
                run_process(
                    [extractor_abspath, filepath], stdout=stdout, stderr=stderr
                )


def get_extractors_data(filedir: str) -> T.Dict[str, T.Any]:
    files = [
        y
        for x in os.walk(filedir)
        for y in glob.glob(os.path.join(x[0], "*.log"))
    ]
    ldirs = len(os.path.normpath(filedir).split(os.sep))
    results = {}
    for file in files:
        subpath = os.sep.join(file.split(os.sep)[ldirs:])
        with open(file, "rt", errors="ignore") as fh:
            data = fh.read()
            if len(data) > 0:
                results[subpath] = data

    return results
