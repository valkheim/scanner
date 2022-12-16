#!/usr/bin/env python3

import sys

from _pe import get_imports_hash

if __name__ == "__main__":
    if (imports_hash := get_imports_hash(sys.argv[1])) is None:
        sys.exit(1)

    print(imports_hash)
    sys.exit(0)
