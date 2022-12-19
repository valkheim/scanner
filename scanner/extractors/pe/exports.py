#!/usr/bin/env python3

import sys

from _pe import get_exports

if __name__ == "__main__":
    if (imports := get_exports(sys.argv[1])) is None:
        sys.exit(1)

    print("address,name,ordinal")
    for address, ordinal, name in imports:
        print(
            f"{address:#x}",
            ordinal,
            name.decode("utf-8") if name else "",
            sep=",",
        )

    sys.exit(0)
