import argparse
import asyncio
import datetime
import functools
import glob
import os
import re
import sys
import time
import typing as T

import joblib
import lief
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
import uvloop
from joblib import Parallel, delayed
from sklearn.ensemble import ExtraTreesClassifier
from sklearn.feature_selection import SelectPercentile  # noqa
from sklearn.feature_selection import VarianceThreshold  # noqa
from sklearn.feature_selection import f_classif  # noqa
from sklearn.model_selection import RepeatedStratifiedKFold, cross_val_score
from sklearn.pipeline import Pipeline
from sklearn.tree import DecisionTreeClassifier, export_graphviz

from scanner.extractors.entropy.entropy import get_entropy
from scanner.extractors.pe.authenticode import get_lief_binary  # noqa
from scanner.extractors.pe.authenticode import has_authenticode  # noqa
from scanner.extractors.pe.debug import get_debug_infos
from scanner.features_data import ANTIDEBUG_IMPORTS  # noqa
from scanner.features_data import CYGWIN_SECTION_NAMES  # noqa
from scanner.features_data import KEYBOARD_IMPORTS  # noqa
from scanner.features_data import LINUX_ELF_SECTION_NAMES  # noqa
from scanner.features_data import SUSPICIOUS_IMPHASHES  # noqa
from scanner.features_data import SUSPICIOUS_IMPORTS  # noqa
from scanner.features_data import SUSPICIOUS_STRINGS  # noqa
from scanner.features_data import TLDS  # noqa
from scanner.features_data import USUSAL_SECTION_CHARACTERISTICS  # noqa
from scanner.features_data import WHITELIST_SECTION_NAMES  # noqa

sys.path.append(  # noqa
    os.path.join(os.path.dirname(__file__), "extractors", "pe")  # noqa
)  # noqa

from scanner.extractors.pe._pe import get_exports  # noqa
from scanner.extractors.pe._pe import get_header_infos  # noqa
from scanner.extractors.pe._pe import get_imports  # noqa
from scanner.extractors.pe._pe import get_optional_header  # noqa
from scanner.extractors.pe._pe import get_packers  # noqa
from scanner.extractors.pe._pe import get_resources  # noqa
from scanner.extractors.pe._pe import get_rich_header  # noqa
from scanner.extractors.pe._pe import get_sections  # noqa
from scanner.extractors.pe._pe import get_size_of_optional_header  # noqa
from scanner.extractors.pe._pe import get_stamps  # noqa
from scanner.extractors.pe._pe import get_subsystem  # noqa
from scanner.extractors.pe._pe import has_valid_checksum  # noqa
from scanner.extractors.pe._pe import load_lief_pe  # noqa

ASCII_BYTE = rb" !\"#\$%&\'\(\)\*\+,-\./0123456789:;<=>\?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}\\\~\t"
CACHE = os.path.normpath(
    os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "cache")
)


@functools.lru_cache(maxsize=32)
def _get_file_data(filepath: str) -> bytes:
    with open(filepath, "rb") as fh:
        return fh.read()


@functools.lru_cache(maxsize=32)
def _get_strings(
    filepath: str, ascii: bool = True, unicode: bool = True
) -> T.List[str]:
    # Must include stack and tight strings at some point
    strings = []
    if not ascii and not unicode:
        return strings

    min_length = 5
    data = _get_file_data(filepath)
    if ascii:
        ascii_re = re.compile(rb"([%s]{%d,})" % (ASCII_BYTE, min_length))
        strings += re.findall(ascii_re, data)
    if unicode:
        unicode_re = re.compile(
            b"((?:[%s]\x00){%d,})" % (ASCII_BYTE, min_length)
        )
        strings += re.findall(unicode_re, data)

    return strings


async def feature_amount_of_ascii_strings(filepath: str) -> int:
    return len(_get_strings(filepath, ascii=True, unicode=False))


async def feature_amount_of_unicode_strings(filepath: str) -> int:
    return len(_get_strings(filepath, ascii=False, unicode=True))


async def feature_mean_of_ascii_string_lengths(filepath: str) -> int:
    if (strings := _get_strings(filepath, ascii=True, unicode=False)) == []:
        return 0

    return np.mean([len(string) for string in strings])


async def feature_mean_of_unicode_string_lengths(filepath: str) -> int:
    if (strings := _get_strings(filepath, ascii=False, unicode=True)) == []:
        return 0

    return np.mean([len(string) for string in strings])


async def feature_amount_of_urls(filepath: str) -> int:
    strings = _get_strings(filepath, ascii=True, unicode=True)
    return sum(b"https" in s or b"http" in s for s in strings)


async def feature_amount_of_ipv4(filepath: str) -> int:
    # May capture version strings (e.g. 1.0.0.0)
    strings = _get_strings(filepath, ascii=True, unicode=True)
    # Will match ipv4 with optional :<port> suffix
    prog = re.compile(
        rb"^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}(:((6553[0-5])|(655[0-2][0-9])|(65[0-4][0-9]{2})|(6[0-4][0-9]{3})|([1-5][0-9]{4})|([0-5]{0,5})|([0-9]{1,4})))?$"
    )
    return len(set([s for s in strings if prog.match(s)]))


async def feature_amount_of_unique_paths(filepath: str) -> int:
    strings = _get_strings(filepath, ascii=True, unicode=True)
    # Drive letter and UNC paths
    prog = re.compile(
        rb'^(?:[a-z]:|\\\\[a-z0-9_.$]+\\[a-z0-9_.$]+)\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*$'
    )
    return len(set([s for s in strings if prog.search(s)]))


async def feature_amount_of_port_numbers(filepath: str) -> int:
    strings = _get_strings(filepath, ascii=True, unicode=True)
    prog = re.compile(
        rb"^((6553[0-5])|(655[0-2][0-9])|(65[0-4][0-9]{2})|(6[0-4][0-9]{3})|([1-5][0-9]{4})|([0-5]{0,5})|([0-9]{1,4}))$"
    )
    return len(set([s for s in strings if prog.search(s)]))


async def feature_amount_of_suspicious_strings(filepath: str) -> int:
    strings = _get_strings(filepath, ascii=True, unicode=True)
    return sum(
        1 for s in strings if s in [ss.lower() for ss in SUSPICIOUS_STRINGS]
    )


@functools.lru_cache(maxsize=32)
def _get_domain_names(filepath: str) -> int:
    strings = _get_strings(filepath, ascii=True, unicode=True)
    # From https://gist.github.com/neu5ron/66078f804f16f9bda828
    # OR adapt https://regex101.com/r/FLA9Bv/9
    prog = re.compile(
        rb"^(([\da-zA-Z])([_\w-]{,62})\.){,127}(([\da-zA-Z])[_\w-]{,61})?([\da-zA-Z]\.((xn\-\-[a-zA-Z\d]+)|([a-zA-Z\d]{2,})))$"
    )
    return set(
        [
            s
            for s in strings
            if all(
                [
                    len(max(s.split(b"."), key=len)) > 6,
                    prog.match(s),
                    s.lower().endswith(tuple(TLDS)),
                ]
            )
        ]
    )


async def feature_amount_of_domain_names(filepath: str) -> int:
    return len(_get_domain_names(filepath))


async def feature_mean_of_domain_names_entropy(filepath: str) -> int:
    if (domain_names := _get_domain_names(filepath)) == set():
        return 0

    return np.mean([get_entropy(dn, "shannon") for dn in domain_names])


async def feature_has_tld_list(filepath: str) -> int:
    # DGA indicator
    strings = _get_strings(filepath, ascii=True, unicode=True)
    blacklist = b".data"
    return len(
        set(
            [
                s
                for s in strings
                if s.lower() in TLDS and s.lower() not in blacklist
            ]
        )
    )


async def feature_amount_of_registry_keys(filepath: str) -> int:
    strings = _get_strings(filepath, ascii=True, unicode=True)
    return sum(b"HKEY_" in s for s in strings)


async def feature_amount_of_variables(filepath: str) -> int:
    # Matches arguments, env variables, ini variables, etc
    strings = _get_strings(filepath, ascii=True, unicode=True)
    prog = re.compile(rb'^([a-zA-Z]{6,})=([a-zA-Z0-9"%\. /]+){4,}?')
    return len(set([s for s in strings if prog.match(s)]))


async def feature_amount_of_exports(filepath: str):
    return len(get_exports(filepath) or [])


async def feature_amount_of_imports(filepath: str) -> int:
    return len(get_imports(filepath) or [])


async def feature_amount_of_distinct_import_modules(filepath: str) -> int:
    if (imports := get_imports(filepath)) is None:
        return 0

    return len(set([module for module, _, _ in imports]))


async def feature_amount_of_sections(filepath: str) -> int:
    return len(get_sections(filepath) or [])


async def feature_has_zero_checksum(filepath: str) -> int:
    hdr = get_header_infos(filepath)
    if "CheckSum" in hdr:
        return int(hdr["CheckSum"] == 0)

    return 0


async def feature_has_valid_checksum(filepath: str) -> int:
    return int(has_valid_checksum(filepath))


async def feature_amount_of_resources(filepath: str) -> int:
    return len(get_resources(filepath) or [])


async def feature_amount_of_zero_stamps(filepath: str) -> int:
    if (stamps := get_stamps(filepath)) is None:
        return 0

    amount = 0
    for stamp in stamps.values():
        if stamp == 0:
            amount += 1

    return amount


@functools.lru_cache(maxsize=32)
def _get_entropy(filepath: str) -> int:
    return get_entropy(_get_file_data(filepath), "shannon")


async def feature_shannon_overall_entropy(filepath: str) -> int:
    return _get_entropy(filepath)


async def feature_has_suspicious_shannon_overall_entropy(filepath: str) -> int:
    return int(_get_entropy(filepath) > 7.2)


async def feature_has_packer(filepath: str) -> int:
    return int(not not get_packers(filepath))


async def feature_has_authenticode(filepath: str) -> int:
    if (binary := get_lief_binary(filepath)) is None:
        return int(False)

    return int(has_authenticode(binary))


async def feature_has_debug_infos(filepath: str) -> int:
    guid, filepath = get_debug_infos(filepath)
    return int(guid is not None or filepath is not None)


async def feature_has_rich_header(filepath: str) -> int:
    return int(get_rich_header(filepath) is not None)


async def feature_rich_header_products_count(filepath: str) -> int:
    if (rich_header := get_rich_header(filepath)) is None:
        return 0

    ret = 0
    for _product_id, _product, _version, count, _vs in rich_header:
        ret += int(count)

    return count


async def feature_rich_header_vs_distinct_count(filepath: str) -> int:
    if (rich_header := get_rich_header(filepath)) is None:
        return 0

    vss = []
    for _product_id, _product, _version, _count, vs in rich_header:
        vss += [vs]

    return len(set(vss))


async def feature_has_native_subsystem(filepath: str) -> int:
    ss_id, _ = get_subsystem(filepath)
    return int(ss_id == 1)


async def feature_has_gui_subsystem(filepath: str) -> int:
    ss_id, _ = get_subsystem(filepath)
    return int(ss_id == 2)


async def feature_has_cui_subsystem(filepath: str) -> int:
    ss_id, _ = get_subsystem(filepath)
    return int(ss_id == 3)


async def feature_has_non_executable_entrypoint(filepath: str) -> int:
    """Entrypoint in a non executable section"""
    sections = get_sections(filepath)
    header = get_header_infos(filepath)
    if header is None or not hasattr(header, "AddressOfEntryPoint"):
        return int(False)

    entrypoint = header["AddressOfEntryPoint"]
    optional_header = get_optional_header(filepath)
    for _name, va, _rs, vs, char, _ent in sections:
        start = optional_header.ImageBase + va
        if start < entrypoint < start + vs:
            if not (char & 0x20000000):
                return int(True)

    return int(False)


async def feature_has_entrypoint_in_last_section(filepath: str) -> int:
    if (sections := get_sections(filepath)) is None:
        return int(False)

    if sections == []:
        return int(False)

    header = get_header_infos(filepath)
    if header is None or not hasattr(header, "AddressOfEntryPoint"):
        return int(False)

    entrypoint = header["AddressOfEntryPoint"]
    optional_header = get_optional_header(filepath)
    _name, va, _rs, vs, char, _ent = sections[-1]
    start = optional_header.ImageBase + va
    return int(start < entrypoint < start + vs)


async def feature_has_entrypoint_outside_the_file(filepath: str) -> int:
    header = get_header_infos(filepath)
    if header is None or not hasattr(header, "AddressOfEntryPoint"):
        return int(False)

    entrypoint = header["AddressOfEntryPoint"]
    optional_header = get_optional_header(filepath)
    return int(
        any(
            [
                entrypoint < optional_header.ImageBase,
                entrypoint
                > optional_header.ImageBase
                + optional_header.SizeOfImage,  # get_header_infos()["SizeOfImage"]
            ]
        )
    )


async def feature_has_zero_entrypoint(filepath: str) -> int:
    if (header := get_header_infos(filepath)) is None:
        return int(False)

    if header is None or not hasattr(header, "AddressOfEntryPoint"):
        return int(False)

    entrypoint = header["AddressOfEntryPoint"]
    return int(entrypoint == 0)


async def feature_has_suspicious_resources_size(filepath: str) -> int:
    if (pe := load_lief_pe(filepath)) is None:
        return int(False)

    rsrc_directory = pe.data_directory(lief.PE.DATA_DIRECTORY.RESOURCE_TABLE)
    if not rsrc_directory.has_section:
        return int(False)

    return int(
        0.0
        <= rsrc_directory.section.size / pe.optional_header.sizeof_image
        <= 0.75
    )


async def feature_has_resources(filepath: str) -> int:
    resources = get_resources(filepath)
    return int(resources is not None and resources != [])


async def feature_has_suspicious_SizeOfImage(filepath: str) -> int:
    header = get_header_infos(filepath)
    if header is None or not hasattr(header, "SizeOfImage"):
        return int(False)

    size = header["SizeOfImage"]
    return int(size < 0x1000 or 0xA00000 < size)


async def feature_has_suspicious_size_of_optional_hdr(filepath: str) -> int:
    optional_header_size = get_size_of_optional_header(filepath)
    # pe studio allows the 0xe0 - 0x104 range
    return int(
        not any(
            [
                optional_header_size == 0xE0,  # PE32
                optional_header_size == 0xF0,  # PE32+
            ]
        )
    )


async def feature_has_suspicious_number_of_imports(filepath: str) -> int:
    n = len(get_imports(filepath) or [])
    return int(n < 10 or 500 < n)


async def feature_has_cfg(filepath: str) -> int:
    if (pe := load_lief_pe(filepath)) is None:
        return int(False)

    return int(pe.optional_header.has(lief.PE.DLL_CHARACTERISTICS.GUARD_CF))


async def feature_has_dep(filepath: str) -> int:
    if (pe := load_lief_pe(filepath)) is None:
        return int(False)

    return int(pe.optional_header.has(lief.PE.DLL_CHARACTERISTICS.NX_COMPAT))


async def feature_has_aslr(filepath: str) -> int:
    if (pe := load_lief_pe(filepath)) is None:
        return int(False)

    return int(
        pe.optional_header.has(lief.PE.DLL_CHARACTERISTICS.DYNAMIC_BASE)
    )


async def feature_ignores_seh(filepath: str) -> int:
    if (pe := load_lief_pe(filepath)) is None:
        return int(True)

    return int(pe.optional_header.has(lief.PE.DLL_CHARACTERISTICS.NO_SEH))


async def feature_ignores_gs(filepath: str) -> int:
    """Ignores stack cookies"""
    if (pe := load_lief_pe(filepath)) is None:
        return int(True)

    if not pe.has_configuration:
        return int(True)

    return int(pe.load_configuration.security_cookie == 0)


async def feature_ignores_ci(filepath: str) -> int:
    """Ignores code integrity"""
    if (pe := load_lief_pe(filepath)) is None:
        return int(True)

    if not pe.has_configuration:
        return int(True)

    return int(isinstance(pe.load_configuration, lief.PE.LoadConfigurationV2))


async def feature_has_suspicious_debug_timestamp(filepath: str) -> int:
    if (pe := load_lief_pe(filepath)) is None:
        return int(False)

    if not pe.has_debug:
        return int(False)

    for entry in pe.debug:
        dbg_time = datetime.datetime.fromtimestamp(entry.timestamp)
        if dbg_time >= datetime.datetime.now():
            return int(True)

    return int(False)


async def feature_is_wdm(filepath: str) -> int:
    if (pe := load_lief_pe(filepath)) is None:
        return int(False)

    return int(pe.optional_header.has(lief.PE.DLL_CHARACTERISTICS.WDM_DRIVER))


async def feature_amount_of_high_entropy_sections(filepath: str) -> int:
    if (sections := get_sections(filepath)) is None:
        return 0

    return sum(1 for _, _, _, _, _, entropy in sections if entropy > 7)


async def feature_amount_of_shared_sections(filepath: str) -> int:
    if (pe := load_lief_pe(filepath)) is None:
        return 0

    # pe-studio allows a 0-1 range
    return sum(
        1
        for section in pe.sections
        if section.has_characteristic(
            lief.PE.SECTION_CHARACTERISTICS.MEM_SHARED
        )
    )


async def feature_has_first_section_writable(filepath: str) -> int:
    if (pe := load_lief_pe(filepath)) is None:
        return int(False)

    return int(
        list(pe.sections)[0].has_characteristic(
            lief.PE.SECTION_CHARACTERISTICS.MEM_WRITE
        )
    )


async def feature_has_last_section_executable(filepath: str) -> int:
    if (pe := load_lief_pe(filepath)) is None:
        return int(False)

    return int(
        list(pe.sections)[0].has_characteristic(
            lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE
        )
    )


async def feature_has_many_executable_sections(filepath: str) -> int:
    if (pe := load_lief_pe(filepath)) is None:
        return int(False)

    i = 0
    for section in pe.sections:
        if section.has_characteristic(
            lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE
        ):
            i += 1

        if i > 1:
            return int(True)

    return int(False)


async def feature_has_wx_section(filepath: str) -> int:
    if (pe := load_lief_pe(filepath)) is None:
        return int(False)

    for section in pe.sections:
        if section.has_characteristic(
            lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE
        ) and section.has_characteristic(
            lief.PE.SECTION_CHARACTERISTICS.MEM_WRITE
        ):
            return int(True)

    return int(False)


async def feature_has_suspicious_size_of_initialied_data(filepath: str) -> int:
    if (pe := load_lief_pe(filepath)) is None:
        return int(False)

    return int(0 < pe.optional_header.sizeof_initialized_data < 0x1927C0)


async def feature_has_suspicious_imphash(filepath: str) -> int:
    if (pe := load_lief_pe(filepath)) is None:
        return int(False)

    imphash = lief.PE.get_imphash(pe).lower()
    return int(imphash in SUSPICIOUS_IMPHASHES)


async def feature_has_size_of_code_greater_than_size_of_code_sections(
    filepath: str,
) -> int:
    if (pe := load_lief_pe(filepath)) is None:
        return int(False)

    code_section_size = sum(
        section.size
        for section in pe.sections
        if section.has_characteristic(lief.PE.SECTION_CHARACTERISTICS.CNT_CODE)
    )
    return int(pe.optional_header.sizeof_code > code_section_size)


async def feature_amount_of_suspicious_section_names(filepath: str) -> int:
    if (pe := load_lief_pe(filepath)) is None:
        return 0

    return sum(
        1
        for section in pe.sections
        if section.name not in WHITELIST_SECTION_NAMES
    )


def _has_section_names(filepath: str, section_names: T.List[str]) -> int:
    if (pe := load_lief_pe(filepath)) is None:
        return 0

    for section in pe.sections:
        if section.name in section_names:
            return int(True)

    return int(False)


async def feature_has_cygwin_section_names(filepath: str) -> int:
    return _has_section_names(filepath, CYGWIN_SECTION_NAMES)


async def feature_has_linux_elf_section_names(filepath: str) -> int:
    return _has_section_names(filepath, LINUX_ELF_SECTION_NAMES)


async def feature_amount_of_suspicious_section_characteristics(
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


async def feature_has_dos_stub(filepath: str) -> int:
    if (pe := load_lief_pe(filepath)) is None:
        return int(False)

    return int(len(pe.dos_stub) != 0)


def _in_imports_list(filepath: str, watchlist) -> int:
    if (imports := get_imports(filepath)) is None:
        return 0

    ret = 0
    for dll, _, function in imports:
        if dll.lower() not in watchlist:
            continue

        if function in watchlist[dll.lower()]:
            ret += 1

    return ret


async def feature_amount_of_antidebug_functions(filepath: str) -> int:
    return _in_imports_list(filepath, ANTIDEBUG_IMPORTS)


async def feature_amount_of_keyboard_functions(filepath: str) -> int:
    return _in_imports_list(filepath, KEYBOARD_IMPORTS)


async def feature_amount_of_suspicious_functions(filepath: str) -> int:
    return _in_imports_list(filepath, SUSPICIOUS_IMPORTS)


async def feature_amount_of_suspicious_modules(filepath: str) -> int:
    if (imports := get_imports(filepath)) is None:
        return 0

    ret = 0
    for dll, _n, _f in imports:
        if dll in SUSPICIOUS_IMPORTS:  # lower?
            ret += 1

    return ret


async def feature_optional_header_major_operating_system_version(
    filepath: str,
) -> int:
    if (header := get_header_infos(filepath)) is None:
        return 0  # Must discard categorical feature

    return header["MajorOperatingSystemVersion"]


async def feature_optional_header_minor_operating_system_version(
    filepath: str,
) -> int:
    if (header := get_header_infos(filepath)) is None:
        return 0  # Must discard categorical feature

    return header["MinorOperatingSystemVersion"]


async def feature_optional_header_major_image_version(
    filepath: str,
) -> int:
    if (header := get_header_infos(filepath)) is None:
        return 0  # Must discard categorical feature

    return header["MajorImageVersion"]


async def feature_optional_header_minor_image_version(
    filepath: str,
) -> int:
    if (header := get_header_infos(filepath)) is None:
        return 0  # Must discard categorical feature

    return header["MinorImageVersion"]


async def feature_optional_header_major_linker_version(
    filepath: str,
) -> int:
    if (header := get_header_infos(filepath)) is None:
        return 0  # Must discard categorical feature

    return header["MajorLinkerVersion"]


async def feature_optional_header_minor_linker_version(
    filepath: str,
) -> int:
    if (header := get_header_infos(filepath)) is None:
        return 0  # Must discard categorical feature

    return header["MinorLinkerVersion"]


async def feature_optional_header_sizeof_code(filepath: str) -> int:
    if (header := get_header_infos(filepath)) is None:
        return 0  # Must discard categorical feature

    return header["SizeOfCode"]


async def feature_optional_header_sizeof_headers(filepath: str) -> int:
    if (header := get_header_infos(filepath)) is None:
        return 0  # Must discard categorical feature

    return header["SizeOfHeaders"]


async def feature_optional_header_sizeof_heap_commit(filepath: str) -> int:
    if (header := get_header_infos(filepath)) is None:
        return 0  # Must discard categorical feature

    return header["SizeOfHeapCommit"]


async def feature_has_duplicate_section_names(filepath: str) -> int:
    if (pe := load_lief_pe(filepath)) is None:
        return int(False)

    lst = [section.name for section in pe.sections]
    return int(len(set(lst)) != len(lst))


async def feature_has_unititialized_section_containing_data(
    filepath: str,
) -> int:
    if (pe := load_lief_pe(filepath)) is None:
        return int(False)

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
            return int(True)

    return int(False)


#####################
#####################
#####################


async def collect_features(feature_extractors, filepath):
    tasks = []
    for k, v in feature_extractors.items():
        tasks.append(asyncio.create_task(v(filepath)))

    feature_values = await asyncio.gather(*tasks)
    return dict(zip(feature_extractors.keys(), feature_values))


def as_sync(fn, *args, **kwargs):
    res = fn(*args, **kwargs)
    if asyncio.iscoroutine(res):
        return asyncio.get_event_loop().run_until_complete(res)

    return res


def handle_file(
    filepath: str, method: str = "multiprocessing"
) -> T.Dict[str, int]:
    feature_extractors = {
        "amount_of_exports": feature_amount_of_exports,
        "amount_of_imports": feature_amount_of_imports,
        "amount_of_distinct_import_modules": feature_amount_of_distinct_import_modules,
        "amount_of_sections": feature_amount_of_sections,
        "amount_of_resources": feature_amount_of_resources,
        "amount_of_zero_stamps": feature_amount_of_zero_stamps,
        "amount_of_ascii_strings": feature_amount_of_ascii_strings,
        "amount_of_unicode_strings": feature_amount_of_unicode_strings,
        "mean_of_ascii_string_lengths": feature_mean_of_ascii_string_lengths,
        "mean_of_unicode_string_lengths": feature_mean_of_unicode_string_lengths,
        "has_zero_checksum": feature_has_zero_checksum,
        "has_valid_checksum": feature_has_valid_checksum,
        "has_packer": feature_has_packer,
        "has_authenticode": feature_has_authenticode,
        "has_debug_infos": feature_has_debug_infos,
        "has_rich_header": feature_has_rich_header,
        "shannon_overall_entropy": feature_shannon_overall_entropy,
        "suspicious_shannon_overall_entropy": feature_has_suspicious_shannon_overall_entropy,
        "has_native_subsystem": feature_has_native_subsystem,
        "has_gui_subsystem": feature_has_gui_subsystem,
        "has_cui_subsystem": feature_has_cui_subsystem,
        "has_suspicious_number_of_imports": feature_has_suspicious_number_of_imports,
        "has_suspicious_SizeOfImage": feature_has_suspicious_SizeOfImage,
        "has_non_executable_entrypoint": feature_has_non_executable_entrypoint,
        "has_entrypoint_in_last_section": feature_has_entrypoint_in_last_section,
        "has_entrypoint_outside_the_file": feature_has_entrypoint_outside_the_file,
        "has_zero_entrypoint": feature_has_zero_entrypoint,
        "has_suspicious_size_of_optional_hdr": feature_has_suspicious_size_of_optional_hdr,
        "has_suspicious_resources_size": feature_has_suspicious_resources_size,
        "has_resources": feature_has_resources,
        "has_cfg": feature_has_cfg,
        "has_dep": feature_has_dep,
        "has_aslr": feature_has_aslr,
        "ignores_seh": feature_ignores_seh,
        "ignores_gs": feature_ignores_gs,
        "ignores_ci": feature_ignores_ci,
        "is_wdm": feature_is_wdm,
        "has_suspicious_debug_timestamp": feature_has_suspicious_debug_timestamp,
        "amount_of_high_entropy_sections": feature_amount_of_high_entropy_sections,
        "amount_of_shared_sections": feature_amount_of_shared_sections,
        "has_first_section_writable": feature_has_first_section_writable,
        "has_last_section_executable": feature_has_last_section_executable,
        "has_many_executable_sections": feature_has_many_executable_sections,
        "has_wx_section": feature_has_wx_section,
        "has_suspicious_size_of_initialied_data": feature_has_suspicious_size_of_initialied_data,
        "has_suspicious_imphash": feature_has_suspicious_imphash,
        "has_size_of_code_greater_than_size_of_code_sections": feature_has_size_of_code_greater_than_size_of_code_sections,
        "amount_of_suspicious_section_names": feature_amount_of_suspicious_section_names,
        "has_dos_stub": feature_has_dos_stub,
        "amount_of_antidebug_functions": feature_amount_of_antidebug_functions,
        "amount_of_keyboard_functions": feature_amount_of_keyboard_functions,
        "amount_of_suspicious_functions": feature_amount_of_suspicious_functions,
        "amount_of_suspicious_modules": feature_amount_of_suspicious_modules,
        "rich_header_products_count": feature_rich_header_products_count,
        "rich_header_vs_distinct_count": feature_rich_header_vs_distinct_count,
        "amount_of_suspicious_section_characteristics": feature_amount_of_suspicious_section_characteristics,
        "has_cygwin_section_names": feature_has_cygwin_section_names,
        "has_linux_elf_section_names": feature_has_linux_elf_section_names,
        "optional_header_major_operating_system_version": feature_optional_header_major_operating_system_version,
        "optional_header_minor_operating_system_version": feature_optional_header_minor_operating_system_version,
        "optional_header_major_image_version": feature_optional_header_major_image_version,
        "optional_header_minor_image_version": feature_optional_header_minor_image_version,
        "optional_header_major_linker_version": feature_optional_header_major_linker_version,
        "optional_header_minor_linker_version": feature_optional_header_minor_linker_version,
        "optional_header_sizeof_headers": feature_optional_header_sizeof_headers,
        "optional_header_sizeof_code": feature_optional_header_sizeof_code,
        "optional_header_sizeof_heap_commit": feature_optional_header_sizeof_heap_commit,
        "has_duplicate_section_names": feature_has_duplicate_section_names,
        "has_unititialized_section_containing_data": feature_has_unititialized_section_containing_data,
        "amount_of_urls": feature_amount_of_urls,
        "amount_of_ipv4": feature_amount_of_ipv4,
        "amount_of_unique_paths": feature_amount_of_unique_paths,
        "amount_of_registry_keys": feature_amount_of_registry_keys,
        "amount_of_variables": feature_amount_of_variables,
        "amount_of_port_numbers": feature_amount_of_port_numbers,
        "amount_of_domain_names": feature_amount_of_domain_names,
        "mean_of_domain_names_entropy": feature_mean_of_domain_names_entropy,
        "has_tld_list": feature_has_tld_list,
        "amount_of_suspicious_strings": feature_amount_of_suspicious_strings,
    }
    if method == "asyncio":
        if sys.version_info >= (3, 11):
            with asyncio.Runner(loop_factory=uvloop.new_event_loop) as runner:
                return runner.run(
                    collect_features(feature_extractors, filepath)
                )
        else:
            uvloop.install()
            return asyncio.run(collect_features(feature_extractors, filepath))

    elif method == "multiprocessing":
        # https://stackoverflow.com/a/67891917
        feature_values = Parallel(n_jobs=-1)(
            delayed(as_sync)(v, filepath) for v in feature_extractors.values()
        )
        return dict(zip(feature_extractors.keys(), feature_values))


def handle_dir(dirpath: str) -> str:
    dir_start_time = time.time()
    feature_values = []
    feature_names = []
    filepaths = set(
        [
            f
            for f in glob.iglob(dirpath + "**/**", recursive=True)
            if lief.PE.is_pe(f)
        ]
    )
    filenames_length = len(filepaths)
    for idx, filepath in enumerate(filepaths):
        print(
            f"[{idx + 1}/{filenames_length}] Handle {os.path.abspath(filepath)}",
            end=" ",
        )
        file_start_time = time.time()
        features = handle_file(filepath)
        print(f"({round((time.time() - file_start_time), 3)} seconds)")
        feature_values.append(list(features.values()))
        feature_names = list(features.keys())

    print(
        f"{dirpath} handled in {round((time.time() - dir_start_time), 3)} seconds"
    )
    return feature_names, feature_values


def create_scatter_matrix(
    outdir: str,
):
    print("Create scatter matrix")
    benign_feature_values = joblib.load(
        f"{outdir}/benign_feature_values.joblib"
    )
    malware_feature_values = joblib.load(
        f"{outdir}/malware_feature_values.joblib"
    )
    feature_names = joblib.load(f"{outdir}/feature_names.joblib")
    df = pd.DataFrame(
        benign_feature_values + malware_feature_values, columns=feature_names
    )
    for col in df:
        df[col] = df[col].astype(float)

    df["__type"] = ["Benign"] * len(benign_feature_values) + ["Malware"] * len(
        malware_feature_values
    )
    sns.pairplot(
        df,
        kind="scatter",
        hue="__type",
        diag_kind="hist",
        corner=True,
        markers=["o", "D"],
    )
    plt.savefig(f"{outdir}/scatter_matrix.png")
    plt.clf()
    plt.cla()


def create_correlation_matrix(outdir: str) -> None:
    print("Create correlation matrix")
    benign_feature_values = joblib.load(
        f"{outdir}/benign_feature_values.joblib"
    )
    malware_feature_values = joblib.load(
        f"{outdir}/malware_feature_values.joblib"
    )
    if os.path.exists(f"{outdir}/reduced_feature_names.joblib"):
        feature_names = joblib.load(f"{outdir}/reduced_feature_names.joblib")
    else:
        feature_names = joblib.load(f"{outdir}/feature_names.joblib")

    df = pd.DataFrame(
        benign_feature_values + malware_feature_values, columns=feature_names
    )
    correlation_matrix = df.corr()
    # Generate a mask for the upper triangle
    mask = np.triu(np.ones_like(correlation_matrix, dtype=bool))
    plt.subplots(figsize=(len(feature_names) / 1.8, len(feature_names) / 1.8))
    sns.heatmap(correlation_matrix, annot=True, mask=mask, square=True)
    plt.savefig(f"{outdir}/correlation_matrix.png", bbox_inches="tight")


def save_feature_importance(
    outdir: str,
    feature_names: T.List[str],
    importances: T.List[int],
    label: str,
) -> None:
    feature_importance = {
        name: score for name, score in zip(feature_names, importances)
    }
    feature_importance = {
        k: v
        for k, v in sorted(
            feature_importance.items(), key=lambda item: item[1], reverse=True
        )
    }
    for k, v in feature_importance.items():
        print(f"{v:.3f}: {k}")

    print(f"Save '{label}' feature importance")
    plt.figure(figsize=(10, 18))
    bars = plt.barh(
        [k for k in feature_importance.keys()],
        [v for v in feature_importance.values()],
        height=0.75,
    )
    for bar in bars:
        width = bar.get_width()
        label_y = bar.get_y() + bar.get_height() / 2
        plt.text(width, label_y, s=f"{width}")

    plt.xlabel("Importances")
    plt.ylabel("Features")
    plt.savefig(
        f"{outdir}/{label}_feature_importance.png", bbox_inches="tight"
    )
    plt.clf()
    plt.cla()


def create_decision_tree(
    outdir: str,
    feature_values,
    feature_names,
    data_class_distribution,
    class_names,
    label,
) -> None:
    print("Create decision tree")
    X = pd.DataFrame(feature_values, columns=feature_names)
    y = pd.DataFrame(data_class_distribution, columns=["Binary type"])
    classifier = DecisionTreeClassifier(
        criterion="gini",
        splitter="random",
        # min_samples_split = 5,  # The minimum number of samples required to split an internal node
        # min_samples_leaf = 10,  # The minimum number of samples required to be at a leaf node. A split point at any depth will only be considered if it leaves at least min_samples_leaf training samples in each of the left and right branches. This may have the effect of smoothing the model, especially in regression.
        max_depth=4,  # The maximum depth of the tree. If None, then nodes are expanded until all leaves are pure or until all leaves contain less than min_samples_split samples.
        max_features="log2",
    )
    classifier.fit(X.values, y)
    # The importance of a feature is computed as the (normalized) total reduction of the criterion brought by that feature.
    # It is also known as the Gini importance.
    importances = classifier.feature_importances_
    save_feature_importance(outdir, feature_names, importances, label)
    export_graphviz(
        classifier,
        out_file=f"{outdir}/{label}.dot",
        class_names=class_names,
        feature_names=feature_names,
        filled=True,
        rounded=True,
    )
    os.system(f"dot {outdir}/{label}.dot -Tpng -o {outdir}/{label}.png")
    return classifier


def create_random_forest(
    outdir: str,
    feature_values,
    feature_names,
    data_class_distribution,
    reduce_features: bool,
    label: str,
) -> None:
    print("Create random forest")
    if not os.path.exists(f"{outdir}/{label}.joblib"):
        X = pd.DataFrame(feature_values, columns=feature_names)
        y = pd.DataFrame(data_class_distribution, columns=["Binary type"])
        percentile = 20
        if not reduce_features:
            percentile = 100

        model = Pipeline(
            steps=[
                (
                    "variance_threshold_selector",
                    VarianceThreshold(threshold=0),
                ),
                (
                    "selector",
                    SelectPercentile(
                        score_func=f_classif, percentile=percentile
                    ),
                ),
                ("classifier", ExtraTreesClassifier(n_jobs=-1)),
            ]
        )

        cv = RepeatedStratifiedKFold(n_repeats=3, random_state=1)
        scores = cross_val_score(
            model, X, y.values.ravel(), scoring="accuracy", cv=cv, n_jobs=-1
        )
        print(f"Accuracy: {np.mean(scores):.3f} ({np.std(scores):.3f})")
        model.fit(X, y.values.ravel())
        joblib.dump(model, f"{outdir}/{label}.joblib")

    else:
        model = joblib.load(f"{outdir}/{label}.joblib")

    importances = model.named_steps["classifier"].feature_importances_
    if reduce_features:
        feature_names = model.named_steps["selector"].get_feature_names_out()
        if not os.path.exists(f"{outdir}/reduced_feature_names.joblib"):
            joblib.dump(
                feature_names, f"{outdir}/reduced_feature_names.joblib"
            )

    save_feature_importance(outdir, feature_names, importances, label)
    return model


def prepare_features(outdir: str, malware_dir: str, benign_dir: str):
    # Fetch malware features
    if not os.path.exists(f"{outdir}/malware_feature_values.joblib"):
        feature_names, malware_feature_values = handle_dir(malware_dir)
        joblib.dump(
            malware_feature_values, f"{outdir}/malware_feature_values.joblib"
        )
        if not os.path.exists(f"{outdir}/feature_names.joblib"):
            joblib.dump(feature_names, f"{outdir}/feature_names.joblib")

    else:
        malware_feature_values = joblib.load(
            f"{outdir}/malware_feature_values.joblib"
        )

    # Fetch benign features
    if not os.path.exists(f"{outdir}/benign_feature_values.joblib"):
        _, benign_feature_values = handle_dir(benign_dir)
        joblib.dump(
            benign_feature_values, f"{outdir}/benign_feature_values.joblib"
        )

    else:
        benign_feature_values = joblib.load(
            f"{outdir}/benign_feature_values.joblib"
        )

    feature_names = joblib.load(f"{outdir}/feature_names.joblib")
    return feature_names, benign_feature_values, malware_feature_values


def prepare_classifier(
    output_dir,
    feature_names,
    reduce_features: bool,
    benign_feature_values,
    malware_feature_values,
    label: str = "random_forest",
):
    feature_values = benign_feature_values + malware_feature_values
    data_class_distribution = [0] * len(benign_feature_values) + [1] * len(
        malware_feature_values
    )

    # Classify
    if label == "decision_tree":
        return create_decision_tree(
            output_dir,
            feature_values,
            feature_names,
            data_class_distribution,
            (
                "benign",
                "malware",
            ),
            label,
        )

    if label == "random_forest":
        return create_random_forest(
            output_dir,
            feature_values,
            feature_names,
            data_class_distribution,
            reduce_features,
            label,
        )


def predict(classifier, test, verbose: bool = False):
    features = handle_file(test)
    if verbose:
        print(
            pd.DataFrame(
                features.items(), columns=["Feature", "Value"]
            ).to_string()
        )

    feature_values = [list(features.values())]
    feature_names = list(features.keys())
    X = pd.DataFrame(feature_values, columns=feature_names)
    y = classifier.predict(X)
    classes = (
        "benign",
        "malware",
    )
    print(f"{test} is {classes[y[0]]}")


def run(args: argparse.Namespace) -> int:
    # Config
    reduce_features = False

    if args.dry:
        features = handle_file(args.dry, "asyncio")
        print(
            pd.DataFrame.from_dict(
                features, orient="index", columns=["Value"]
            ).to_string()
        )

    if args.output_dir and args.malwares_dir and args.benigns_dir:
        os.makedirs(args.output_dir, exist_ok=True)
        (
            feature_names,
            benign_feature_values,
            malware_feature_values,
        ) = prepare_features(
            args.output_dir, args.malwares_dir, args.benigns_dir
        )
        prepare_classifier(
            args.output_dir,
            feature_names,
            reduce_features,
            benign_feature_values,
            malware_feature_values,
        )

    if args.output_dir and args.scatter_matrix:
        create_scatter_matrix(args.output_dir)

    if args.output_dir and args.correlation_matrix:
        create_correlation_matrix(args.output_dir)

    if args.classifier_path:
        classifier = joblib.load(args.classifier_path)
        if args.test_file:
            predict(classifier, args.test_file, verbose=True)

        if args.test_dir:
            for filename in os.listdir(args.test_dir):
                filepath = os.path.join(args.test_dir, filename)
                if not os.path.isfile(filepath):
                    continue

                predict(classifier, filepath, verbose=False)

    return 0
