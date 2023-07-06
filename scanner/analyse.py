import datetime
import glob
import hashlib
import json
import multiprocessing
import multiprocessing.dummy
import os
import shutil
import time
import typing as T

from scanner.types import Infos, Result
from scanner.utils import (
    get_extractors_dir,
    get_results_dir,
    run_process,
    yield_files,
)


def read_result_infos(result_hash: str) -> T.Optional[Infos]:
    results_dir = get_results_dir()
    infos_path = os.path.join(results_dir, result_hash, "infos.json")
    if not os.path.exists(infos_path):
        return None

    with open(infos_path, "rt") as fh:
        return json.load(fh)


def write_result_infos(result_hash: str, data: Infos) -> None:
    dst_dir = get_results_dir(result_hash)
    with open(os.path.join(dst_dir, "infos.json"), "wt") as fh:
        fh.write(json.dumps(data))


def yield_extractor_paths(
    dst_file: str,
    mkdir: bool = True,
    extractor_abspaths_whitelist: T.Optional[T.List[str]] = None,
) -> T.Generator[T.Tuple[str, str], None, None]:
    extractors_dir = get_extractors_dir()
    for extractor_relpath in yield_files(extractors_dir):
        extractor_abspath = os.path.join(extractors_dir, extractor_relpath)
        if (
            extractor_abspaths_whitelist is not None
            and extractor_abspath not in extractor_abspaths_whitelist
        ):
            continue

        parts = extractor_relpath.split(os.sep)
        if any([x.startswith("_") for x in parts]):
            continue

        results_absdir = os.path.join(
            os.path.dirname(dst_file),
            *parts[:-1],
            ".".join(parts[-1].split(".")[:-1]),
        )
        if mkdir:
            os.makedirs(results_absdir, exist_ok=True)

        yield extractor_abspath, results_absdir


def run_extractors(
    hash: str, extractor_abspaths_whitelist: T.Optional[T.List[str]] = None
) -> None:
    start = time.perf_counter()
    files = []
    args = []
    dst_dir = get_results_dir(hash)
    if (infos := read_result_infos(hash)) is None:
        return

    dst_file = os.path.join(dst_dir, infos["filename"])
    for extractor_path, results_dir in yield_extractor_paths(
        dst_file,
        mkdir=True,
        extractor_abspaths_whitelist=extractor_abspaths_whitelist,
    ):
        files.append(open(os.path.join(results_dir, "stdout.log"), "wt"))
        files.append(open(os.path.join(results_dir, "stderr.log"), "wt"))
        args.append([[extractor_path, dst_file], files[-2], files[-1]])

    with multiprocessing.dummy.Pool(
        multiprocessing.cpu_count() - 1 or 1
    ) as pool:
        pool.starmap(run_process, args)

    for f in files:
        f.close()

    elapsed = round(time.perf_counter() - start, 2)
    infos["elapsed"] = elapsed
    write_result_infos(hash, infos)
    print(f"Extractors ran in {elapsed} second(s) for {hash}")


def get_extractors_data(result_dir: str) -> T.Dict[str, T.Any]:
    files = [
        y
        for x in os.walk(result_dir)
        for y in glob.glob(os.path.join(x[0], "*.log"))
    ]
    ldirs = len(os.path.normpath(result_dir).split(os.sep))
    results = {}
    for file in files:
        subpath = os.sep.join(file.split(os.sep)[ldirs:])
        with open(file, "rt", errors="ignore") as fh:
            data = fh.read()
            if len(data) > 0:
                results[subpath] = data

    return results


def handle_submitted_file(f: T.BinaryIO, filename: str) -> str:
    # Compute SHA1 hash
    hash = hashlib.sha1(f.read()).hexdigest()
    f.seek(0)

    # Copy file to results dir
    dst_dir = get_results_dir(hash)
    dst_file = os.path.join(dst_dir, filename)
    with open(dst_file, "wb") as fh:
        fh.write(f.read())

    # Complete file infos
    write_result_infos(
        hash,
        {
            "filename": filename,
            "sha1": hash,
            "last_update": datetime.datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
        },
    )

    return hash


def get_result(hash: str) -> Result:
    results_dir = get_results_dir()
    dst_dir = os.path.join(results_dir, hash)
    extractors_data = get_extractors_data(dst_dir)
    sorted_extractors_data = dict(sorted(extractors_data.items()))
    return {
        "infos": read_result_infos(hash),
        "extractors": sorted_extractors_data,
    }


def del_result(hash: str) -> None:
    results_dir = get_results_dir()
    dst_dir = os.path.join(results_dir, hash)
    shutil.rmtree(dst_dir, ignore_errors=True)
    print(f"{dst_dir} deleted")


def get_last_results() -> T.List[Result]:
    last_results = []
    results_dir = get_results_dir()
    for result in os.listdir(results_dir):
        if (infos := read_result_infos(result)) is not None:
            last_results += [infos]

    return sorted(last_results, key=lambda d: d["last_update"], reverse=True)
