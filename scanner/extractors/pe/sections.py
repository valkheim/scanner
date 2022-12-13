#!/usr/bin/env python3

import itertools
import sys

from _pe import get_sections


def read_c_string(f):
    return "".join((map(chr, itertools.takewhile(lambda x: x, f))))


if __name__ == "__main__":
    if (sections := get_sections(sys.argv[1])) is None:
        sys.exit(1)

    print("name,raw_size,virtual_address,virtual_size,entropy")
    for name, rs, va, vs, ent in sections:
        line = [
            read_c_string(name),
            f"{rs:#0x}",
            f"{va:#0x}",
            f"{vs:#0x}",
            f"{ent}",
        ]
        print(",".join(line))

    sys.exit(0)
