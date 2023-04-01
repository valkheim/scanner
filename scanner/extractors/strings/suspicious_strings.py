#!/usr/bin/env python3

import sys

from _strings import (
    SUSPICIOUS_AVS,
    SUSPICIOUS_DOMAIN_NAMES,
    SUSPICIOUS_DOS_STUB_STRINGS,
    SUSPICIOUS_EXTENSIONS,
    SUSPICIOUS_FILENAMES,
    SUSPICIOUS_FMT_STRINGS,
    SUSPICIOUS_GUID,
    SUSPICIOUS_OIDS,
    SUSPICIOUS_PROCESSES,
    SUSPICIOUS_PROTOCOLS,
    SUSPICIOUS_REGISTRY,
    SUSPICIOUS_SANDBOX_PIDS,
    SUSPICIOUS_SDDL,
    SUSPICIOUS_SIDS,
    SUSPICIOUS_STRINGS,
    SUSPICIOUS_USER_AGENTS,
    get_blacklisted_strings,
)

if __name__ == "__main__":
    types = [
        (SUSPICIOUS_AVS, "antivirus"),
        (SUSPICIOUS_USER_AGENTS, "user agent"),
        (SUSPICIOUS_DOMAIN_NAMES, "domain name"),
        (SUSPICIOUS_DOS_STUB_STRINGS, "DOS stub string"),
        (SUSPICIOUS_EXTENSIONS, "extension"),
        (SUSPICIOUS_FILENAMES, "filename"),
        (SUSPICIOUS_FMT_STRINGS, "format string"),
        (SUSPICIOUS_GUID, "guid"),
        (SUSPICIOUS_SIDS, "sid"),
        (SUSPICIOUS_OIDS, "oid"),
        (SUSPICIOUS_PROTOCOLS, "protocol"),
        (SUSPICIOUS_PROCESSES, "process"),
        (SUSPICIOUS_STRINGS, "generic"),
        (SUSPICIOUS_REGISTRY, "registry"),
        (SUSPICIOUS_SANDBOX_PIDS, "sandbox pid"),
        (SUSPICIOUS_SDDL, "sddl"),
        # TLDS
    ]
    suspicious_strings_infos = []
    for type, label in types:
        if (strings := get_blacklisted_strings(sys.argv[1], type)) is None:
            continue

        for string in strings:
            suspicious_strings_infos.append([string, label])

    if suspicious_strings_infos == []:
        sys.exit(1)

    for string, label in suspicious_strings_infos:
        print(label, string, sep=",")

    sys.exit(0)
