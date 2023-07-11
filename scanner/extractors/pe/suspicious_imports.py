#!/usr/bin/env python3

import sys

from _pe import (  # noqa
    ANTIDEBUG_IMPORTS,
    KEYBOARD_IMPORTS,
    SUSPICIOUS_IMPORTS,
    UNPACKING_IMPORTS,
    in_imports_list,
)

if __name__ == "__main__":
    types = [
        (SUSPICIOUS_IMPORTS, "generic"),
        (ANTIDEBUG_IMPORTS, "antidebug"),
        (KEYBOARD_IMPORTS, "keyboard"),
        (UNPACKING_IMPORTS, "unpacking"),
    ]
    suspicious_imports_infos = []
    for type, label in types:
        if (imports := in_imports_list(sys.argv[1], type)) is None:
            continue

        if imports == []:
            continue

        for dll, name in imports:
            suspicious_imports_infos.append([label, dll, name])

    if suspicious_imports_infos == []:
        sys.exit(1)

    print("label,dll,name")
    for label, dll, name in suspicious_imports_infos:
        print(
            label,
            dll.decode("utf-8"),
            name.decode("utf-8") if name else "",
            sep=",",
        )

    sys.exit(0)
