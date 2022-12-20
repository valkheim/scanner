#!/usr/bin/env python3

import sys

from _pe import get_packers

if __name__ == "__main__":
    if (packers := get_packers(sys.argv[1])) is None:
        sys.exit(1)

    print("packers")
    for packer in packers:
        print(packer)

    sys.exit(0)
