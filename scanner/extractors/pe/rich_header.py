#!/usr/bin/env python3

import sys

from _pe import get_rich_header

if __name__ == "__main__":
    if (rich_header := get_rich_header(sys.argv[1])) is None:
        sys.exit(1)

    print("id,type,version,count,vs")
    for product_id, product, version, count, vs in rich_header:
        print(product_id, product, version, count, vs, sep=",")

    sys.exit(0)
