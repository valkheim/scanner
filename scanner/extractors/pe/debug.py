#!/usr/bin/env python3

import sys
import typing as T

from pdbparse.peinfo import (
    get_dbg_fname,
    get_nb10,
    get_pe_debug_data,
    get_pe_guid,
    get_rsds,
)


def handle_xp_pe(debug_data: bytes) -> tuple[str | None, str | None]:
    # XP+
    if debug_data[:4] == b"RSDS":
        return get_rsds(debug_data)

    elif debug_data[:4] == b"NB10":
        return get_nb10(debug_data)

    return None, None


def handle_win2k_pe(debug_data: bytes, pe_file: str) -> tuple[str, str]:
    # Win2k
    # Get the .dbg file
    guid = get_pe_guid(pe_file)
    guid = guid.upper()
    try:
        filepath = get_dbg_fname(debug_data)

    except AttributeError:
        # pdbparse may fail to parse the symbol filename because of encoding
        # With the code below, we try to avoid such decoding errors
        import ntpath

        from pdbparse.dbgold import IMAGE_DEBUG_MISC

        dbgstruct = IMAGE_DEBUG_MISC.parse(debug_data)
        raw_filename = dbgstruct.Strings[0]
        filepath = ntpath.basename(raw_filename)

    return guid, filepath


def get_debug_infos(filepath: str) -> tuple[str | None, str | None]:
    try:
        debug_data, debug_type = get_pe_debug_data(filepath)

    except (
        Exception
    ):  # pefile.PEFormatError: # DOS Header magic not found, pdbparse lib error
        return None, None

    if debug_type == "IMAGE_DEBUG_TYPE_CODEVIEW":
        return handle_xp_pe(debug_data)

    elif debug_type == "IMAGE_DEBUG_TYPE_MISC":
        return handle_win2k_pe(debug_data, filepath)

    return None, None


if __name__ == "__main__":
    guid, filepath = get_debug_infos(sys.argv[1])
    if guid is None and filepath is None:
        sys.exit(1)

    print("guid,filepath")
    print(T.cast(str, guid) + "," + T.cast(str, filepath))
    sys.exit(0)
