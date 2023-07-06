#!/usr/bin/env python3

import datetime
import sys
import typing as T

import joblib
import lief
from _pe import (  # noqa
    CYGWIN_SECTION_NAMES,
    LINUX_ELF_SECTION_NAMES,
    SUSPICIOUS_IMPHASHES,
    USUSAL_SECTION_CHARACTERISTICS,
    get_exports,
    get_header_infos,
    get_imports,
    get_optional_header,
    get_packers,
    get_resources,
    get_rich_header,
    get_sections,
    get_size_of_optional_header,
    get_stamps,
    get_subsystem,
    has_valid_checksum,
    load_lief_pe,
)

from scanner.extractors.entropy.entropy import get_entropy
from scanner.extractors.pe.debug import get_debug_infos


def feature_amount_of_exports(filepath: str) -> int:
    return len(get_exports(filepath) or [])


def feature_amount_of_imports(filepath: str) -> int:
    return len(get_imports(filepath) or [])


def feature_amount_of_distinct_import_modules(filepath: str) -> int:
    if (imports := get_imports(filepath)) is None:
        return 0

    return len(set([module for module, _, _ in imports]))


def feature_amount_of_sections(filepath: str) -> int:
    return len(get_sections(filepath) or [])


def feature_amount_of_resources(filepath: str) -> int:
    return len(get_resources(filepath) or [])


def feature_amount_of_zero_stamps(filepath: str) -> int:
    if (stamps := get_stamps(filepath)) is None:
        return 0

    amount = 0
    for stamp in stamps.values():
        if stamp == 0:
            amount += 1

    return amount


def feature_has_valid_checksum(filepath: str) -> bool:
    return has_valid_checksum(filepath)


def feature_has_zero_checksum(filepath: str) -> bool:
    hdr = get_header_infos(filepath)
    if "CheckSum" in hdr:
        return bool(hdr["CheckSum"] == 0)

    return False


def feature_has_packer(filepath: str) -> bool:
    return bool(get_packers(filepath) != [])


def feature_has_debug_infos(filepath: str) -> bool:
    guid, filepath = get_debug_infos(filepath)
    return guid is not None or filepath is not None


def feature_has_rich_header(filepath: str) -> bool:
    return get_rich_header(filepath) is not None


def feature_has_suspicious_entropy_shannon(filepath: str) -> bool:
    with open(filepath, "rb") as fh:
        data = fh.read()

    return bool(get_entropy(data, "shannon") >= 7.2)


def feature_has_native_subsystem(filepath: str) -> bool:
    ss_id, _ = get_subsystem(filepath)
    return bool(ss_id == 1)


def feature_has_gui_subsystem(filepath: str) -> bool:
    ss_id, _ = get_subsystem(filepath)
    return bool(ss_id == 2)


def feature_has_cui_subsystem(filepath: str) -> bool:
    ss_id, _ = get_subsystem(filepath)
    return bool(ss_id == 3)


def feature_has_suspicious_number_of_imports(filepath: str) -> bool:
    n = len(get_imports(filepath) or [])
    return n < 10 or 500 < n


def feature_has_suspicious_imphash(filepath: str) -> bool:
    if (pe := load_lief_pe(filepath)) is None:
        return False

    imphash = lief.PE.get_imphash(pe).lower()
    return imphash in SUSPICIOUS_IMPHASHES


def feature_has_suspicious_entrypoint_non_executable(filepath: str) -> bool:
    """Entrypoint in a non executable section"""
    sections = get_sections(filepath)
    header = get_header_infos(filepath)
    if header is None or not hasattr(header, "AddressOfEntryPoint"):
        return False

    entrypoint = header["AddressOfEntryPoint"]
    optional_header = get_optional_header(filepath)
    for _name, va, _rs, vs, char, _ent in sections:
        start = optional_header.ImageBase + va
        if start < entrypoint < start + vs:
            if not (char & 0x20000000):
                return True

    return False


def feature_has_suspicious_entrypoint_in_last_section(filepath: str) -> bool:
    if (sections := get_sections(filepath)) is None:
        return False

    if sections == []:
        return False

    header = get_header_infos(filepath)
    if header is None or not hasattr(header, "AddressOfEntryPoint"):
        return False

    entrypoint = header["AddressOfEntryPoint"]
    optional_header = get_optional_header(filepath)
    _name, va, _rs, vs, _char, _ent = sections[-1]
    start = optional_header.ImageBase + va
    return bool(start < entrypoint < start + vs)


def feature_suspicious_entrypoint_outside_of_file(filepath: str) -> bool:
    header = get_header_infos(filepath)
    if header is None or not hasattr(header, "AddressOfEntryPoint"):
        return False

    entrypoint = header["AddressOfEntryPoint"]
    optional_header = get_optional_header(filepath)
    return any(
        [
            entrypoint < optional_header.ImageBase,
            entrypoint
            > optional_header.ImageBase
            + optional_header.SizeOfImage,  # get_header_infos()["SizeOfImage"]
        ]
    )


def feature_has_suspicious_entrypoint_zero(filepath: str) -> bool:
    if (header := get_header_infos(filepath)) is None:
        return False

    if header is None or not hasattr(header, "AddressOfEntryPoint"):
        return False

    entrypoint = header["AddressOfEntryPoint"]
    return bool(entrypoint == 0)


def feature_has_suspicious_SizeOfImage(filepath: str) -> bool:
    header = get_header_infos(filepath)
    if header is None or not hasattr(header, "SizeOfImage"):
        return False

    size = header["SizeOfImage"]
    return bool(size < 0x1000) or bool(0xA00000 < size)


def feature_has_suspicious_size_of_optional_hdr(filepath: str) -> bool:
    optional_header_size = get_size_of_optional_header(filepath)
    # pe studio allows the 0xe0 - 0x104 range
    return not any(
        [
            optional_header_size == 0xE0,  # PE32
            optional_header_size == 0xF0,  # PE32+
        ]
    )


def feature_has_suspicious_resources_size(filepath: str) -> bool:
    if (pe := load_lief_pe(filepath)) is None:
        return False

    rsrc_directory = pe.data_directory(lief.PE.DATA_DIRECTORY.RESOURCE_TABLE)
    if not rsrc_directory.has_section:
        return False

    return bool(
        0.0
        <= rsrc_directory.section.size / pe.optional_header.sizeof_image
        <= 0.75
    )


def feature_has_suspicious_size_of_initialized_data(
    filepath: str,
) -> bool:
    if (pe := load_lief_pe(filepath)) is None:
        return False

    return bool(0 < pe.optional_header.sizeof_initialized_data < 0x1927C0)


def feature_has_suspicious_debug_timestamp(filepath: str) -> bool:
    if (pe := load_lief_pe(filepath)) is None:
        return False

    if not pe.has_debug:
        return False

    for entry in pe.debug:
        dbg_time = datetime.datetime.fromtimestamp(entry.timestamp)
        if dbg_time >= datetime.datetime.now():
            return True

    return False


def feature_has_suspicious_section_many_shared_sections(filepath: str) -> bool:
    if (pe := load_lief_pe(filepath)) is None:
        return False

    # pe-studio allows a 0-1 range²
    return bool(
        sum(
            1
            for section in pe.sections
            if section.has_characteristic(
                lief.PE.SECTION_CHARACTERISTICS.MEM_SHARED
            )
        )
        > 1
    )


def feature_has_suspicious_section_first_is_writable(filepath: str) -> bool:
    if (pe := load_lief_pe(filepath)) is None:
        return False

    return bool(
        list(pe.sections)[0].has_characteristic(
            lief.PE.SECTION_CHARACTERISTICS.MEM_WRITE
        )
        != []
    )


def feature_has_suspicious_section_last_is_executable(filepath: str) -> bool:
    if (pe := load_lief_pe(filepath)) is None:
        return False

    return bool(
        list(pe.sections)[0].has_characteristic(
            lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE
        )
        != []
    )


def feature_has_suspicious_section_many_executable(filepath: str) -> bool:
    if (pe := load_lief_pe(filepath)) is None:
        return False

    i = 0
    for section in pe.sections:
        if section.has_characteristic(
            lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE
        ):
            i += 1

        if i > 1:
            return True

    return False


def feature_has_suspicious_section_has_wx_section(filepath: str) -> bool:
    if (pe := load_lief_pe(filepath)) is None:
        return False

    for section in pe.sections:
        if section.has_characteristic(
            lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE
        ) and section.has_characteristic(
            lief.PE.SECTION_CHARACTERISTICS.MEM_WRITE
        ):
            return True

    return False


def feature_has_size_of_code_greater_than_size_of_code_sections(
    filepath: str,
) -> bool:
    if (pe := load_lief_pe(filepath)) is None:
        return False

    code_section_size = sum(
        section.size
        for section in pe.sections
        if section.has_characteristic(lief.PE.SECTION_CHARACTERISTICS.CNT_CODE)
    )
    return bool(pe.optional_header.sizeof_code > code_section_size)


def feature_amount_of_suspicious_section_characteristics(
    filepath: str,
) -> int:
    if (pe := load_lief_pe(filepath)) is None:
        return 0

    return sum(
        1
        for sec in pe.sections
        if sec.name in USUSAL_SECTION_CHARACTERISTICS
        and USUSAL_SECTION_CHARACTERISTICS[sec.name] != sec.characteristics
    )


def _has_section_names(filepath: str, section_names: T.List[str]) -> bool:
    if (pe := load_lief_pe(filepath)) is None:
        return False

    for section in pe.sections:
        if section.name in section_names:
            return True

    return False


def feature_has_cygwin_section_names(filepath: str) -> bool:
    return _has_section_names(filepath, CYGWIN_SECTION_NAMES)


def feature_has_linux_elf_section_names(filepath: str) -> bool:
    return _has_section_names(filepath, LINUX_ELF_SECTION_NAMES)


def feature_has_duplicate_section_names(filepath: str) -> bool:
    if (pe := load_lief_pe(filepath)) is None:
        return False

    lst = [section.name for section in pe.sections]
    return len(set(lst)) != len(lst)


def feature_has_unititialized_section_containing_data(
    filepath: str,
) -> bool:
    if (pe := load_lief_pe(filepath)) is None:
        return False

    for section in pe.sections:
        if not section.has_characteristic(
            lief.PE.SECTION_CHARACTERISTICS.CNT_UNINITIALIZED_DATA
        ):
            continue

        if any(
            [
                section.offset,
                section.size,
                section.sizeof_raw_data,
                section.pointerto_raw_data,
            ]
        ):
            return True

    return False


if __name__ == "__main__":
    feature_extractors = {
        # Some amounts
        "amount_of_exports": feature_amount_of_exports,
        "amount_of_imports": feature_amount_of_imports,
        "amount_of_distinct_import_modules": feature_amount_of_distinct_import_modules,
        "amount_of_sections": feature_amount_of_sections,
        "amount_of_resources": feature_amount_of_resources,
        "amount_of_zero_stamps": feature_amount_of_zero_stamps,
        # Some features
        "has_zero_checksum": feature_has_zero_checksum,
        "has_valid_checksum": feature_has_valid_checksum,
        "has_packer": feature_has_packer,
        "has_debug_infos": feature_has_debug_infos,
        "has_rich_header": feature_has_rich_header,
        "has_native_subsystem": feature_has_native_subsystem,
        "has_gui_subsystem": feature_has_gui_subsystem,
        "has_cui_subsystem": feature_has_cui_subsystem,
        "has_suspicious_entropy_shannon": feature_has_suspicious_entropy_shannon,
        "has_suspicious_number_of_imports": feature_has_suspicious_number_of_imports,
        "has_suspicious_imphash": feature_has_suspicious_imphash,
        "has_suspicious_debug_timestamp": feature_has_suspicious_debug_timestamp,
        # Header entrypoint
        "has_suspicious_entrypoint_non_executable": feature_has_suspicious_entrypoint_non_executable,
        "has_suspicious_entrypoint_in_last_section": feature_has_suspicious_entrypoint_in_last_section,
        "has_suspicious_entrypoint_outside_the_file": feature_suspicious_entrypoint_outside_of_file,
        "has_suspicious_entrypoint_zero": feature_has_suspicious_entrypoint_zero,
        # Header sizes
        "has_suspicious_SizeOfImage": feature_has_suspicious_SizeOfImage,
        "has_suspicious_size_of_optional_hdr": feature_has_suspicious_size_of_optional_hdr,
        "has_suspicious_resources_size": feature_has_suspicious_resources_size,
        "has_suspicious_size_of_initialied_data": feature_has_suspicious_size_of_initialized_data,
        # Sections
        "amount_of_suspicious_section_characteristics": feature_amount_of_suspicious_section_characteristics,
        "has_size_of_code_greater_than_size_of_code_sections": feature_has_size_of_code_greater_than_size_of_code_sections,
        "has_cygwin_section_names": feature_has_cygwin_section_names,
        "has_linux_elf_section_names": feature_has_linux_elf_section_names,
        "has_duplicate_section_names": feature_has_duplicate_section_names,
        "has_unititialized_section_containing_data": feature_has_unititialized_section_containing_data,
        "has_suspicious_section_many_shared_sections": feature_has_suspicious_section_many_shared_sections,
        "has_suspicious_section_first_is_writable": feature_has_suspicious_section_first_is_writable,
        "has_suspicious_section_last_is_executable": feature_has_suspicious_section_last_is_executable,
        "has_suspicious_section_many_executable": feature_has_suspicious_section_many_executable,
        "has_suspicious_section_has_wx_section": feature_has_suspicious_section_has_wx_section,
    }

    feature_values = joblib.Parallel(n_jobs=-1)(
        joblib.delayed(extractor)(sys.argv[1])
        for extractor in feature_extractors.values()
    )

    features = dict(zip(feature_extractors.keys(), feature_values))
    print("name,value")
    for name, value in features.items():
        print(name.replace("_", " "), value, sep=",")

    sys.exit(0)
