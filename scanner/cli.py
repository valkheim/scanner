import argparse
import json
import os

from scanner.analyse import (
    get_last_results,
    get_results,
    handle_submitted_file,
    run_extractors,
)


def handle_file(filepath: str) -> int:
    print(f"Handle {filepath}")
    with open(filepath, "rb") as fh:
        filename = filepath.split(os.sep)[-1]
        hash = handle_submitted_file(fh, filename)
        print(f"{filename} -- {hash}")
        run_extractors(hash)
        get_results(hash)

    return 0


def handle_dir(dirpath: str) -> str:
    for filename in os.listdir(dirpath):
        filepath = os.path.join(dirpath, filename)
        handle_file(filepath)


def print_results(hash: str):
    results = get_results(hash)
    print(json.dumps(results))


def print_last_results():
    for res in get_last_results():
        print(res["last_update"], res["sha1"], res["filename"], sep=" | ")

    return 0


def run(args: argparse.Namespace) -> int:
    if args.dir:
        return handle_dir(args.dir)

    elif args.file:
        return handle_file(args.file)

    elif args.hash:
        return print_results(args.hash)

    elif args.last:
        return print_last_results()

    else:
        return 1
