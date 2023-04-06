#!/usr/bin/env python3

import sys

from _pe import SUSPICIOUS_MODULES, get_imports

if __name__ == "__main__":
    if (imports := get_imports(sys.argv[1])) is None:
        sys.exit(1)

    suspicious_modules = []
    for dll, _offset, _name in imports:
        if dll in SUSPICIOUS_MODULES:
            suspicious_modules.append(dll)

    if suspicious_modules == []:
        sys.exit(1)

    print("dll")
    for dll in suspicious_modules:
        print(dll, sep=",")

    sys.exit(0)
