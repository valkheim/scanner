#!/usr/bin/env python3

import sys

from _pe import get_sections

import itertools

def read_c_string(f):
    return "".join((map(chr, itertools.takewhile(lambda x: x, f))))

if __name__ == "__main__":
    if (sections := get_sections(sys.argv[1])) is None:
        sys.exit(1)

    print("name,virtual_address,virtual_size,raw_size")
    for name, va, vs, rs in sections:
        print(
            read_c_string(name),
            f"{va:#x}",
            f"{vs:#x}",
            f"{rs:#x}",
            sep=","
        )

    sys.exit(0)