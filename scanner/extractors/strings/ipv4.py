#!/usr/bin/env python3

import sys

from _strings import get_ipv4

if __name__ == "__main__":
    if (ips := get_ipv4(sys.argv[1])) is None:
        sys.exit(1)

    if ips:
        print("ips")
        for ip in ips:
            print(ip.decode())

    sys.exit(0)
