#!/usr/bin/env python3

import sys

from _pe import WHITELIST_SECTION_NAMES, load_lief_pe

if __name__ == "__main__":
    if (pe := load_lief_pe(sys.argv[1])) is None:
        sys.exit(1)

    sections_infos = [
        (section.offset, section.name)
        for section in pe.sections
        if section.name not in WHITELIST_SECTION_NAMES
    ]
    if sections_infos == []:
        sys.exit(1)

    print("offset,name")
    for offset, name in sections_infos:
        print(f"{offset:#08x}", name, sep=",")

    sys.exit(0)
