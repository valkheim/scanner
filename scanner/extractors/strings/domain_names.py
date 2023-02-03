#!/usr/bin/env python3

import sys

from _strings import get_domain_names

if __name__ == "__main__":
    if (domain_names := get_domain_names(sys.argv[1])) is None:
        sys.exit(1)

    if domain_names:
        print("domain_names")
        for domain_name in domain_names:
            print(domain_name.decode())

    sys.exit(0)
