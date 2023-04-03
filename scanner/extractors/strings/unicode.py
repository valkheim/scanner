#!/usr/bin/env python3

import sys

from _strings import get_strings

if __name__ == "__main__":
    """/usr/bin/strings -el $1"""
    if (
        strings_infos := get_strings(
            sys.argv[1], ascii=False, unicode=True, offsets=True
        )
    ) == []:
        sys.exit(1)

    print("offset,string")
    for offset, string in strings_infos:
        print(f"{offset:#08x}", string.decode("utf-16"), sep=",")

    sys.exit(0)
