import itertools
import typing as T

import lief
import pefile
from _pe.packers import PACKER_SECTIONS
from _pe.rich_header import KNOWN_PRODUCT_IDS, vs_version, vs_version_fallback


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
            section.VirtualAddress,
            section.SizeOfRawData,
            section.Misc_VirtualSize,
            section.Characteristics,
            section.get_entropy(),
        )
        for section in pe.sections
    ]


def get_packers(filepath) -> T.Optional[T.List[str]]:
    if (sections := get_sections(filepath)) is None:
        return []

    candidates = []
    for name, _va, _rs, _vs, _char, _ent in sections:
        section_name = "".join(
            (map(chr, itertools.takewhile(lambda x: x, name)))
        )
        if section_name in PACKER_SECTIONS.keys():
            candidates.append(PACKER_SECTIONS[section_name])

    return list(set(candidates))


def get_imports(filepath: str) -> T.Optional[T.List[T.Any]]:
    if (pe := load_pe_file(filepath)) is None:
        return None

    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
    )
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return None

    acc = []
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for imp in entry.imports:
            acc += [(entry.dll, imp.address, imp.name)]

    return acc


def get_imports_hash(filepath: str) -> T.Optional[str]:
    if (pe := load_pe_file(filepath)) is None:
        return None

    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
    )
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return None

    return pe.get_imphash()


def get_exports(filepath: str) -> T.Optional[T.List[T.Any]]:
    if (pe := load_pe_file(filepath)) is None:
        return None

    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
    )
    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
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

    for directory_name in (
        "DIRECTORY_ENTRY_IMPORT",
        "DELAY_IMPORT_DESCRIPTOR",
        "DIRECTORY_ENTRY_BOUND_IMPORT",  # + IMAGE_BOUND_FORWARDER_REF
        "DIRECTORY_ENTRY_EXPORT",
        "DIRECTORY_ENTRY_RESOURCE",
        "DIRECTORY_ENTRY_LOAD_CONFIG",
        "DIRECTORY_ENTRY_DEBUG",
    ):
        if hasattr(pe, directory_name):
            directory = getattr(pe, directory_name)
            if type(directory) is list:
                for idx, dir_entry in enumerate(directory):
                    acc[
                        f"{directory_name} > {dir_entry.__class__.__name__} #{idx}"
                    ] = int(dir_entry.struct.TimeDateStamp)
            else:
                acc[directory_name] = int(
                    getattr(pe, directory_name).struct.TimeDateStamp
                )

    return acc


def get_rich_header(filepath: str) -> T.Optional[T.List[T.Any]]:
    if (pe := load_pe_file(filepath)) is None:
        return None

    if (rich_header := pe.parse_rich_header()) is None:
        return None

    acc = []
    for comp_id, count in zip(
        rich_header["values"][::2], rich_header["values"][1::2]
    ):
        version = comp_id & 0xFFFF
        product_id = (comp_id & 0xFFFF0000) >> 0x10
        product = "Unknown"
        if product_id in KNOWN_PRODUCT_IDS:
            product = KNOWN_PRODUCT_IDS[product_id]

        if (vs := vs_version(comp_id)) is None:
            vs = vs_version_fallback(product_id)

        acc += [(product_id, product, version, count, vs)]

    return acc


def resource(pe, r, parents=[], acc=[]):
    if hasattr(r, "data"):
        return acc + [
            "-".join(parents + [str(r.id)]),
            r.name or "Unknown",
            r.data.struct.Size,
            r.data.struct.OffsetToData,
            pefile.LANG.get(r.data.lang, "Unknown"),
            pefile.get_sublang_name_for_lang(r.data.lang, r.data.sublang),
        ]

    else:
        if r.name:
            parents += [str(r.name)]
        else:
            parents += [str(r.id)]
        for entry in r.directory.entries:
            return resource(pe, entry, parents, acc)


def get_resources(filepath: str) -> T.Optional[T.List[T.Any]]:
    if (pe := load_pe_file(filepath)) is None:
        return None

    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]]
    )
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        return None

    return [
        resource(pe, entry) for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries
    ]


def get_resources_section(filepath):
    if (pe := load_pe_file(filepath)) is None:
        return None

    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]]
    )
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        return None

    res = pe.DIRECTORY_ENTRY_RESOURCE
    return res


def get_optional_header(filepath: str):
    if (pe := load_pe_file(filepath)) is None:
        return None

    return pe.OPTIONAL_HEADER


def get_size_of_optional_header(filepath: str) -> int:
    """
    Size of the OptionalHeader AND the data directories which follows this header.
    This value is equivalent to: sizeof(pe_optional_header) + NB_DATA_DIR * sizeof(data_directory)
    This size should be either:
    * 0xE0 (224) for a PE32 (32 bits)
    * 0xF0 (240) for a PE32+ (64 bits)
    """
    pe = lief.PE.parse(filepath)
    if not hasattr(pe, "header"):
        return 0

    return pe.header.sizeof_optional_header


def get_header_infos(filepath: str):
    if (pe := load_pe_file(filepath)) is None:
        return None

    acc = {}
    for value in [
        "MajorLinkerVersion",
        "MinorLinkerVersion",
        "AddressOfEntryPoint",
        "SizeOfImage",
        "SizeOfCode",
        "BaseOfCode",
        "BaseOfData",
        "SizeOfHeaders",
        "SizeOfStackReserve",
        "SizeOfStackCommit",
        "SizeOfHeapReserve",
        "SizeOfHeapCommit",
        "CheckSum",
    ]:
        if hasattr(pe.OPTIONAL_HEADER, value):
            acc[value] = getattr(pe.OPTIONAL_HEADER, value)

    return acc


def get_subsystem(filepath: str):
    if (pe := load_pe_file(filepath)) is None:
        return None, None

    if not hasattr(pe.OPTIONAL_HEADER, "Subsystem"):
        return None, None

    if pe.OPTIONAL_HEADER.Subsystem in pefile.SUBSYSTEM_TYPE:
        return (
            pe.OPTIONAL_HEADER.Subsystem,
            pefile.SUBSYSTEM_TYPE[pe.OPTIONAL_HEADER.Subsystem],
        )

    return pe.OPTIONAL_HEADER.Subsystem, None
