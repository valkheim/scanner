#!/usr/bin/env python3

import sys

from _strings import SUSPICIOUS_AVS, get_blacklisted_strings

if __name__ == "__main__":
    if (
        strings := get_blacklisted_strings(sys.argv[1], SUSPICIOUS_AVS)
    ) is None:
        sys.exit(1)

    if strings:
        print("suspicious antivirus strings")
        for string in strings:
            print(string)

    sys.exit(0)
