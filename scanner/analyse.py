import datetime
import glob
import hashlib
import json
import os
import typing as T

from scanner.utils import run_process, yield_files


def read_result_infos(result_hash: str) -> T.Dict[str, T.Any]:
    results_dir = os.path.normpath(
        os.path.join(os.path.dirname(__file__), "..", "results")
    )
    infos_path = os.path.join(results_dir, result_hash, "infos.json")
    if not os.path.exists(infos_path):
        return None

    with open(infos_path, "rt") as fh:
        return json.load(fh)


def get_results_dir(hash: str = None) -> T.Optional[str]:
    # for all hashes
    if hash is None:
        results_dir = os.path.normpath(
            os.path.join(os.path.dirname(__file__), "..", "results")
        )
        os.makedirs(results_dir, exist_ok=True)
        return results_dir

    # for a specific hash
    if read_result_infos(hash) is None:
        return None

    return os.path.normpath(
        os.path.join(os.path.dirname(__file__), "..", "results", hash)
    )


def yield_valid_extractor_paths(dst_file):
    extractors_dir = os.path.join(os.path.dirname(__file__), "extractors")
    for extractor_relpath in yield_files(extractors_dir):
        extractor_abspath = os.path.join(extractors_dir, extractor_relpath)
        parts = extractor_relpath.split(os.sep)
        if any([x.startswith("_") for x in parts]):
            continue

        results_absdir = os.path.join(
            os.path.dirname(dst_file),
            *parts[:-1],
            ".".join(parts[-1].split(".")[:-1]),
        )
        os.makedirs(results_absdir, exist_ok=True)
        yield extractor_abspath, results_absdir


def run_extractors(hash: str) -> None:
    dst_dir = get_results_dir(hash)
    infos = read_result_infos(hash)
    dst_file = os.path.join(dst_dir, infos["filename"])
    for extractor_path, results_dir in yield_valid_extractor_paths(dst_file):
        with open(os.path.join(results_dir, "stdout.log"), "wt") as stdout:
            with open(os.path.join(results_dir, "stderr.log"), "wt") as stderr:
                run_process(
                    [extractor_path, dst_file], stdout=stdout, stderr=stderr
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


def handle_submitted_file(f, filename: str) -> str:
    hash = hashlib.sha1(f.read()).hexdigest()
    f.seek(0)
    dst_dir = os.path.normpath(
        os.path.join(os.path.dirname(__file__), "..", "results", hash)
    )
    dst_file = os.path.join(dst_dir, filename)
    if not os.path.isdir(dst_dir):
        os.makedirs(dst_dir)
        with open(dst_file, "wb") as fh:
            fh.write(f.read())

    with open(os.path.join(dst_dir, "infos.json"), "wt") as fh:
        fh.write(
            json.dumps(
                {
                    "filename": filename,
                    "sha1": hash,
                    "last_update": datetime.datetime.now().strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),
                }
            )
        )

    return hash


def get_results(hash: str) -> T.Dict[str, T.Any]:
    results_dir = get_results_dir()
    dst_dir = os.path.join(results_dir, hash)
    return {
        "infos": read_result_infos(hash),
        "extractors": get_extractors_data(dst_dir),
    }


def get_last_results() -> T.List[T.Any]:
    last_results = []
    results_dir = get_results_dir()
    for result in os.listdir(results_dir):
        if (infos := read_result_infos(result)) is not None:
            last_results += [infos]

    return sorted(last_results, key=lambda d: d["last_update"], reverse=True)
