#!/usr/bin/env python3
import os
import subprocess
import sys

if __name__ == "__main__":
    rules_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "_rules", "pe_injection")
    )
    # https://github.com/mandiant/capa/tree/master/sigs
    sigs_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "_sigs")
    )
    arguments = [
        "capa",
        "-q",
        "-vv",
        "--rules",
        rules_path,
        "--signatures",
        sigs_path,
        sys.argv[1],
    ]
    p = subprocess.Popen(arguments, stdout=subprocess.PIPE)
    if p.stdout is not None:
        print(p.stdout.read().decode())

    sys.exit(p.returncode)
