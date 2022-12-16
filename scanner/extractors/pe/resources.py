#!/usr/bin/env python3

import sys

from _pe import get_resources

if __name__ == "__main__":
    if (resources := get_resources(sys.argv[1])) is None:
        sys.exit(1)

    print("path,name,size,data_offset,lang,sublang")
    for path, name, size, data_offset, lang, sublang in resources:
        print(path, name, size, data_offset, lang, sublang, sep=",")

    sys.exit(0)
