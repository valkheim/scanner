import typing as T

import pefile


def load_pe_file(filepath: str) -> T.Optional[T.Any]:
    try:
        return pefile.PE(filepath, fast_load=True)
    except pefile.PEFormatError:
        return None


def get_sections(filepath: str) -> T.Optional[T.List[T.Any]]:
    if (pe := load_pe_file(filepath)) is None:
        return None

    return [
        (
            section.Name,
            section.SizeOfRawData,
            section.VirtualAddress,
            section.Misc_VirtualSize,
            section.get_entropy(),
        )
        for section in pe.sections
    ]


def get_imports(filepath: str) -> T.Optional[T.List[T.Any]]:
    if (pe := load_pe_file(filepath)) is None:
        return None

    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
    )
    if not hasattr(pe, "IMAGE_DIRECTORY_ENTRY_IMPORT"):
        return None

    acc = []
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for imp in entry.imports:
            acc += [entry.dll, imp.address, imp.name]

    return acc


def get_exports(filepath: str) -> T.Optional[T.List[T.Any]]:
    if (pe := load_pe_file(filepath)) is None:
        return None

    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
    )
    if not hasattr(pe, "IMAGE_DIRECTORY_ENTRY_EXPORT"):
        return None

    return [
        [pe.OPTIONAL_HEADER.ImageBase + exp.address, exp.ordinal, exp.name]
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols
    ]


def get_stamps(filepath: str) -> T.Optional[T.Dict[str, str]]:
    if (pe := load_pe_file(filepath)) is None:
        return None

    pe.parse_data_directories()
    acc = {
        "FILE_HEADER": int(
            pe.FILE_HEADER.dump_dict()["TimeDateStamp"]["Value"].split()[0], 16
        ),
    }

    for directory in (
        "DIRECTORY_ENTRY_IMPORT",
        "DELAY_IMPORT_DESCRIPTOR",
        "DIRECTORY_ENTRY_BOUND_IMPORT",  # + IMAGE_BOUND_FORWARDER_REF
        "DIRECTORY_ENTRY_EXPORT",
        "DIRECTORY_ENTRY_RESOURCE",
        "DIRECTORY_ENTRY_LOAD_CONFIG",
    ):
        if hasattr(pe, directory):
            acc[directory] = int(getattr(pe, directory).struct.TimeDateStamp)

    if hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
        for idx, debug_data in enumerate(pe.DIRECTORY_ENTRY_DEBUG):
            acc[f"DIRECTORY_ENTRY_DEBUG DebugData #{idx}"] = int(
                debug_data.struct.TimeDateStamp
            )

    return acc
