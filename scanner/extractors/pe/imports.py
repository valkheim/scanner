#!/usr/bin/env python3

import sys

from _pe import get_imports

if __name__ == "__main__":
    if (imports := get_imports(sys.argv[1])) is None:
        sys.exit(1)

    print("dll,address,name")
    for dll, address, name in imports:
        print(
            dll,
            f"{address:#x}",
            name,
            sep=","
        )

    sys.exit(0)