#!/usr/bin/env python3

import sys

from _pe import get_rich_header

if __name__ == "__main__":
    if (sections := get_rich_header(sys.argv[1])) is None:
        sys.exit(1)

    sys.exit(0)
