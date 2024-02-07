#!/usr/bin/env python3

"""
One can prevent Microsoft to tools from emitting this Rich header using the
following undocumented linker option: /emittoolversioninfo:no
"""

import sys

from _pe import get_rich_header

if __name__ == "__main__":
    if (rich_header := get_rich_header(sys.argv[1])) is None:
        sys.exit(1)

    print("id,type,version,count,vs")
    for product_id, product, version, count, vs in rich_header:
        print(
            product_id,
            product or "Unknown",
            version,
            count,
            vs or "Unknown",
            sep=",",
        )

    sys.exit(0)
