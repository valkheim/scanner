#!/usr/bin/env python3

import sys

from _pe import get_header_infos

if __name__ == "__main__":
    if (infos := get_header_infos(sys.argv[1])) is None:
        sys.exit(1)

    for k, v in infos.items():
        if k in (
            "AddressOfEntryPoint",
            "BaseOfCode",
            "BaseOfData",
            "CheckSum",
        ):
            v = hex(v)

        print(f"{k}: {v}")

    sys.exit(0)
