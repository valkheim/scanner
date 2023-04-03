#!/usr/bin/env python3

import sys

from _strings import get_strings

if __name__ == "__main__":
    """/usr/bin/strings -es $1"""
    if (
        strings_infos := get_strings(
            sys.argv[1], ascii=True, unicode=False, offsets=True
        )
    ) == []:
        sys.exit(1)

    print("offset,string")
    for offset, string in strings_infos:
        print(f"{offset:#08x}", string.decode("ascii"), sep=",")

    sys.exit(0)
