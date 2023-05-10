#!/usr/bin/env python3

import hashlib
import json
import os
import sys
import typing as T

import vt  # vt-py

Report = T.Dict[str, T.Any]


def cache_report(cache_file_path: str, report: Report) -> None:
    # Cache report
    with open(cache_file_path, "wt") as fh:
        fh.write(json.dumps(report))


def get_report_from_vt(hash: str, cache_file_path: str) -> Report:
    apikey = (
        r"7ffcbe6864c6f8c0e82e3cb4a55cb0ec900bd942efacf203cdc67f1b2c3bf492"
    )
    client = vt.Client(apikey)
    file = client.get_object(f"/files/{hash}")
    report = file.to_dict()
    cache_report(cache_file_path, report)
    return report


def get_report_from_cache(cache_file_path: str) -> Report:
    with open(cache_file_path, "rt") as fh:
        return json.loads(fh.read())


def sha1sum(filename: str) -> str:
    h = hashlib.sha1()
    b = bytearray(128 * 1024)
    mv = memoryview(b)
    with open(filename, "rb", buffering=0) as f:
        while n := f.readinto(mv):
            h.update(mv[:n])
    return h.hexdigest()


def get_report(filepath: str) -> Report:
    hash = sha1sum(filepath)
    cache_dir = os.path.join(os.path.dirname(__file__), "_cache")
    os.makedirs(cache_dir, exist_ok=True)
    cache_file_path = os.path.join(cache_dir, hash)
    if os.path.exists(cache_file_path):
        return get_report_from_cache(cache_file_path)

    return get_report_from_vt(hash, cache_file_path)


if __name__ == "__main__":
    if (report := get_report(sys.argv[1])) is None:
        sys.exit(1)

    print(json.dumps(report, indent=4))
    sys.exit(0)
