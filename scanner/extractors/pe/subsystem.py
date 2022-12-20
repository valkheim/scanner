#!/usr/bin/env python3

import sys

from _pe import get_subsystem

if __name__ == "__main__":
    subsystem_id, subsystem_label = get_subsystem(sys.argv[1])
    if subsystem_id is None:
        sys.exit(1)

    print(f"{subsystem_id}: {subsystem_label or 'Unknown'}")
    sys.exit(0)
