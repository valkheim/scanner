#!/usr/bin/env python3

import sys

from _pe import SUSPICIOUS_IMPORTS, in_imports_list

if __name__ == "__main__":
    if (imports := in_imports_list(sys.argv[1], SUSPICIOUS_IMPORTS)) is None:
        sys.exit(1)

    if imports == []:
        sys.exit(1)

    print("dll,name")
    for dll, name in imports:
        print(
            dll.decode("utf-8"),
            name.decode("utf-8") if name else "",
            sep=",",
        )

    sys.exit(0)
