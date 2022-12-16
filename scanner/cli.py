import argparse
import json
import os

from scanner.analyse import (get_last_results, get_results,
                             handle_submitted_file, run_extractors)


def run(args: argparse.Namespace) -> int:
    if args.file:
        with open(args.file, "rb") as fh:
            filename = args.file.split(os.sep)[-1]
            hash = handle_submitted_file(fh, filename)
            print(f"{filename} -- {hash}")
            run_extractors(hash)
            results = get_results(hash)
            print(json.dumps(results))

        return 0

    elif args.last:
        for res in get_last_results():
            print(
                res["sha1"],
                res["filename"],
            )

        return 0

    else:
        return 1
