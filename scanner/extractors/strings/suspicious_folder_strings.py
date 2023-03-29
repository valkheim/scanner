#!/usr/bin/env python3

import sys

from _strings import SUSPICIOUS_FOLDERS, get_blacklisted_strings

if __name__ == "__main__":
    if (
        strings := get_blacklisted_strings(sys.argv[1], SUSPICIOUS_FOLDERS)
    ) is None:
        sys.exit(1)

    for string in strings:
        print(string)

    sys.exit(0)
