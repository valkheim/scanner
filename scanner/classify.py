import argparse
import asyncio
import datetime
import os
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
from sklearn import metrics
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier, export_graphviz

from scanner.extractors.entropy.entropy import get_entropy
from scanner.extractors.pe.authenticode import get_lief_binary  # noqa
from scanner.extractors.pe.authenticode import has_authenticode  # noqa
from scanner.extractors.pe.debug import get_debug_infos

sys.path.append(
    os.path.join(os.path.dirname(__file__), "extractors", "pe")
)  # noqa
import re

from scanner.extractors.pe._pe import get_header_infos  # noqa
from scanner.extractors.pe._pe import get_imports  # noqa
from scanner.extractors.pe._pe import get_packers  # noqa
from scanner.extractors.pe._pe import get_resources  # noqa
from scanner.extractors.pe._pe import get_rich_header  # noqa
from scanner.extractors.pe._pe import get_sections  # noqa
from scanner.extractors.pe._pe import get_size_of_optional_header  # noqa
from scanner.extractors.pe._pe import get_stamps  # noqa
from scanner.extractors.pe._pe import get_subsystem  # noqa
from scanner.extractors.pe._pe import get_exports, get_optional_header  # noqa

ASCII_BYTE = rb" !\"#\$%&\'\(\)\*\+,-\./0123456789:;<=>\?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}\\\~\t"
CACHE = os.path.normpath(
    os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "cache")
)


async def feature_amount_of_ascii_strings(filepath: str) -> int:
    with open(filepath, "rb") as fh:
        ascii_re = re.compile(rb"([%s]{%d,})" % (ASCII_BYTE, 5))
        return sum(1 for _ in re.finditer(ascii_re, fh.read()))


async def feature_amount_of_unicode_strings(filepath: str) -> int:
    with open(filepath, "rb") as fh:
        unicode_re = re.compile(b"((?:[%s]\x00){%d,})" % (ASCII_BYTE, 5))
        return sum(1 for _ in re.finditer(unicode_re, fh.read()))


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
    has_checksum = hasattr(hdr, "CheckSum")
    if has_checksum:
        return int(hdr["CheckSum"] == 0)

    return 0


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


async def feature_get_shannon_entropy(filepath: str) -> int:
    with open(filepath, "rb") as fh:
        data = fh.read()
        return get_entropy(data, "shannon")


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
    if (pe := lief.PE.parse(filepath)) is None:
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
    return not any(
        [
            optional_header_size == 0xE0,  # PE32
            optional_header_size == 0xF0,  # PE32+
        ]
    )


async def feature_has_suspicious_number_of_imports(filepath: str) -> int:
    n = len(get_imports(filepath) or [])
    return int(n < 10 or 500 < n)


async def feature_has_cfg(filepath: str) -> int:
    if (pe := lief.PE.parse(filepath)) is None:
        return int(False)

    return int(pe.optional_header.has(lief.PE.DLL_CHARACTERISTICS.GUARD_CF))


async def feature_has_dep(filepath: str) -> int:
    if (pe := lief.PE.parse(filepath)) is None:
        return int(False)

    return int(pe.optional_header.has(lief.PE.DLL_CHARACTERISTICS.NX_COMPAT))


async def feature_has_aslr(filepath: str) -> int:
    if (pe := lief.PE.parse(filepath)) is None:
        return int(False)

    return int(
        pe.optional_header.has(lief.PE.DLL_CHARACTERISTICS.DYNAMIC_BASE)
    )


async def feature_ignores_seh(filepath: str) -> int:
    if (pe := lief.PE.parse(filepath)) is None:
        return int(True)

    return int(pe.optional_header.has(lief.PE.DLL_CHARACTERISTICS.NO_SEH))


async def feature_ignores_gs(filepath: str) -> int:
    """Ignores stack cookies"""
    if (pe := lief.PE.parse(filepath)) is None:
        return int(True)

    if not pe.has_configuration:
        return int(True)

    return int(pe.load_configuration.security_cookie == 0)


async def feature_ignores_ci(filepath: str) -> int:
    """Ignores code integrity"""
    if (pe := lief.PE.parse(filepath)) is None:
        return int(True)

    if not pe.has_configuration:
        return int(True)

    return int(isinstance(pe.load_configuration, lief.PE.LoadConfigurationV2))


async def feature_has_suspicious_debug_timestamp(filepath: str) -> int:
    if (pe := lief.PE.parse(filepath)) is None:
        return int(False)

    if not pe.has_debug:
        return int(False)

    for entry in pe.debug:
        dbg_time = datetime.datetime.fromtimestamp(entry.timestamp)
        if dbg_time >= datetime.datetime.now():
            return int(True)

    return int(False)


async def feature_is_wdm(filepath: str) -> int:
    if (pe := lief.PE.parse(filepath)) is None:
        return int(False)

    return int(pe.optional_header.has(lief.PE.DLL_CHARACTERISTICS.WDM_DRIVER))


async def feature_amount_of_high_entropy_sections(filepath: str) -> int:
    if (sections := get_sections(filepath)) is None:
        return 0

    acc: int = 0
    for _name, _va, _rs, _vs, _char, ent in sections:
        if 0 < ent < 7:
            acc += 1

    return acc


async def feature_amount_of_shared_sections(filepath: str) -> int:
    if (pe := lief.PE.parse(filepath)) is None:
        return 0

    found = 0
    for section in pe.sections:
        if section.has_characteristic(
            lief.PE.SECTION_CHARACTERISTICS.MEM_SHARED
        ):
            found += 1

    return int(not 0 <= found <= 1)


async def feature_has_first_section_writable(filepath: str) -> int:
    if (pe := lief.PE.parse(filepath)) is None:
        return int(False)

    return int(
        list(pe.sections)[0].has_characteristic(
            lief.PE.SECTION_CHARACTERISTICS.MEM_WRITE
        )
    )


async def feature_has_last_section_executable(filepath: str) -> int:
    if (pe := lief.PE.parse(filepath)) is None:
        return int(False)

    return int(
        list(pe.sections)[0].has_characteristic(
            lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE
        )
    )


async def feature_has_many_executable_sections(filepath: str) -> int:
    if (pe := lief.PE.parse(filepath)) is None:
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
    if (pe := lief.PE.parse(filepath)) is None:
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
    if (pe := lief.PE.parse(filepath)) is None:
        return int(False)

    return int(0 < pe.optional_header.sizeof_initialized_data < 0x1927C0)


async def feature_has_suspicious_imphash(filepath: str) -> int:
    if (pe := lief.PE.parse(filepath)) is None:
        return int(False)

    imphash = lief.PE.get_imphash(pe).lower()
    blacklist = (
        # https://www.mandiant.com/resources/blog/tracking-malware-import-hashing
        "2c26ec4a570a502ed3e8484295581989",  # GREENCAT
        "b722c33458882a1ab65a13e99efe357e",  # GREENCAT
        "2d24325daea16e770eb82fa6774d70f1",  # GREENCAT
        "0d72b49ed68430225595cc1efb43ced9",  # GREENCAT
        "959711e93a68941639fd8b7fba3ca28f",  # STARSYPOUND
        "4cec0085b43f40b4743dc218c585f2ec",  # COOKIEBAG
        "3b10d6b16f135c366fc8e88cba49bc6c",  # NEWSREELS
        "4f0aca83dfe82b02bbecce448ce8be00",  # NEWSREELS
        "ee22b62aa3a63b7c17316d219d555891",  # TABMSGSQL
        "a1a42f57ff30983efda08b68fedd3cfc",  # WEBC2
        "7276a74b59de5761801b35c672c9ccb4",  # WEBC2
    )
    return int(imphash in blacklist)


async def feature_has_size_of_code_greater_than_size_of_code_sections(
    filepath: str,
) -> int:
    if (pe := lief.PE.parse(filepath)) is None:
        return int(False)

    code_section_size = 0
    for section in pe.sections:
        if section.has_characteristic(
            lief.PE.SECTION_CHARACTERISTICS.CNT_CODE
        ):
            code_section_size += section.size

    return int(pe.optional_header.sizeof_code > code_section_size)


async def feature_amount_of_suspicious_section_names(filepath: str) -> int:
    if (pe := lief.PE.parse(filepath)) is None:
        return 0

    whitelist = [
        ".text",
        ".bss",
        ".rdata",
        ".data",
        ".idata",
        ".reloc",
        ".rsrc",
    ]
    amount = 0
    for section in pe.sections:
        if section.name not in whitelist:
            amount += 1

    return amount


async def feature_has_dos_stub(filepath: str) -> int:
    if (pe := lief.PE.parse(filepath)) is None:
        return int(False)

    return int(len(pe.dos_stub) != 0)


async def feature_amount_of_antidebug_functions(filepath: str) -> int:
    watchlist = {
        "kernel32.dll": {
            "IsDebuggerPresent",
            "RegisterApplicationRestart",
            "RegisterApplicationRecoveryCallback",
            "ApplicationRecoveryInProgress",
            "ApplicationRecoveryFinished",
            "GetThreadSelectorEntry",
            "RtlCaptureStackBackTrace",
            "RegisterEventSource",
            "RegisterHotKey",
            "FatalAppExit",
            "ContinueDebugEvent",
            "DebugActiveProcessStop",
            "SetDebugErrorLevel",
            "DebugActiveProcess",
            "DebugBreak",
            "FlushInstructionCache",
            "CheckRemoteDebuggerPresent",
            "RtlLookupFunctionEntry",
            "OutputDebugString",
            "RtlPcToFileHeader",
        },
        "shlwapi.dll": {
            "OutputDebugStringWrap",
        },
        "loadperf.dll": {
            "LoadPerfCounterTextStrings",
            "UnloadPerfCounterTextStrings",
        },
        "ntdll.dll": {
            "DbgUiConnectToDbg",
            "DbgUiDebugActiveProcess",
            "DbgPrint",
            "DbgPrintEx",
            "QueryTrace",
            "EtwLogTraceEvent",
            "EtwEventWrite",
            "EtwEventEnabled",
            "EtwEventRegister",
            "EtwEventUnregister",
            "EtwUnregisterTraceGuids",
            "EtwRegisterTraceGuids",
            "EtwGetTraceLoggerHandle",
            "EtwGetTraceEnableLevel",
            "EtwGetTraceEnableFlags",
            "EtwTraceMessage",
            "NtGetContextThread",
            "WerReportSQMEvent",
            "WerRegisterMemoryBlock",
            "WerUnregisterMemoryBlock",
        },
        "advapi32.dll": {
            "EventRegister",
            "EventSetInformation",
            "EventUnregister",
            "EventWriteTransfer",
            "ElfOpenEventLog",
            "ElfReadEventLog",
            "ElfReportEvent",
            "ElfReportEventAndSource",
            "BackupEventLog",
            "ClearEventLog",
            "CloseEventLog",
            "DeregisterEventSource",
            "GetEventLogInformation",
            "GetNumberOfEventLogRecords",
            "GetOldestEventLogRecord",
            "NotifyChangeEventLog",
            "OpenBackupEventLog",
            "OpenEventLog",
            "ReadEventLog",
            "RegisterEventSource",
            "ReportEvent",
            "SaferRecordEventLogEntry",
            "StartTrace",
            "CloseTrace",
            "ProcessTrace",
            "FlushTrace",
            "OpenTrace",
            "QueryAllTraces",
            "LockServiceDatabase",
            "GetNumberOfEventLogRecords",
            "GetOldestEventLogRecord",
            "BackupEventLog",
            "NotifyChangeEventLog",
            "DeregisterEventSource",
            "ReportEvent",
            "GetTraceEnableLevel",
        },
        "psapi.dll": {
            "EmptyWorkingSet",
            "EnumDeviceDrivers",
            "EnumPageFiles",
            "GetMappedFileName",
            "GetDeviceDriverBaseName",
            "GetDeviceDriverBaseName",
            "GetDeviceDriverFileName",
            "GetMappedFileName",
            "GetModuleInformation",
            "GetPerformanceInfo",
            "RtlImageNtHeader",
            "RtlImageDirectoryEntryToData",
        },
        "mspdb80.dll": {
            "PDBOpenValidate5",
        },
        "imagehlp.dll": {
            "UpdateDebugInfoFileEx",
            "CheckSumMappedFile",
            "EnumerateLoadedModulesW64",
            "ImageNtHeader",
            "ImageRvaToVa",
            "StackWalk64",
            "SymCleanup",
            "SymFromAddr",
            "SymFunctionTableAccess64",
            "SymGetModuleInfo64",
            "SymGetModuleBase64",
            "SymGetModuleInfoW64",
            "SymGetOptions",
            "SymGetSymFromName",
            "SymInitialize",
            "SymLoadModule64",
            "SymRegisterCallback64",
            "SymSetOptions",
            "SymUnloadModule64",
            "SymAddSourceStream",
            "SymEnumSourceFileTokens",
            "SymEnumSourceFiles",
            "SymGetSourceFileFromToken",
            "SymGetSourceFileToken",
            "SymGetSourceVarFromToken",
            "SymMatchString",
            "SymRegisterCallbackW64",
            "SymSetHomeDirectory",
            "SymSrvGetFileIndexes",
            "RemoveRelocations",
            "BindImage",
            "BindImageEx",
            "CheckSumMappedFile",
            "EnumerateLoadedModules64",
            "EnumerateLoadedModules",
            "EnumerateLoadedModulesEx",
            "FindDebugInfoFile",
            "FindDebugInfoFileEx",
            "FindExecutableImage",
            "FindExecutableImageEx",
            "FindFileInPath",
            "FindFileInSearchPath",
            "GetImageConfigInformation",
            "GetImageUnusedHeaderBytes",
            "GetTimestampForLoadedLibrary",
            "ImageAddCertificate",
            "ImageDirectoryEntryToData",
            "ImageDirectoryEntryToDataEx",
            "ImageEnumerateCertificates",
            "ImageGetCertificateData",
            "ImageGetCertificateHeader",
            "ImageGetDigestStream",
            "ImageLoad",
            "ImageRemoveCertificate",
            "ImageRvaToSection",
            "ImageUnload",
            "ImagehlpApiVersion",
            "ImagehlpApiVersionEx",
            "MakeSureDirectoryPathExists",
            "MapAndLoad",
            "MapDebugInformation",
            "MapFileAndCheckSum",
            "ReBaseImage64",
            "ReBaseImage",
            "RemovePrivateCvSymbolic",
            "RemovePrivateCvSymbolicEx",
            "SearchTreeForFile",
            "SetImageConfigInformation",
            "SplitSymbols",
            "StackWalk",
            "SymEnumSym",
            "TouchFileTimes",
            "UnDecorateSymbolName",
            "UnMapAndLoad",
            "UnmapDebugInformation",
            "UpdateDebugInfoFile",
        },
        "dbghelp.dll": {
            "EnumDirTree",
            "SymFromAddr",
            "SymGetModuleBase64",
            "SymFunctionTableAccess64",
            "SymCleanup",
            "StackWalk64",
            "SymInitialize",
            "SymFunctionTableAccess64",
            "SymGetModuleBase64",
            "StackWalk64",
            "ImageNtHeader",
            "SymUnloadModule64",
            "SymLoadModule64",
            "SymLoadModuleEx",
            "SymGetOptions",
            "SymSetOptions",
            "MiniDumpWriteDump",
            "SymGetSymFromName",
            "SymFromAddr",
            "SymCleanup",
            "SymGetModuleInfoW64",
            "SymRegisterCallback64",
            "EnumerateLoadedModules",
            "EnumerateLoadedModulesW64",
            "SymInitialize",
            "ImageDirectoryEntryToData",
            "SymEnumSym",
            "SymEnumerateSymbolsW",
            "MapDebugInformation",
            "SymEnumerateSymbols64",
            "SymGetSymFromAddr64",
            "SymGetSymFromName64",
            "SymGetSymNext64",
            "SymGetSymPrev64",
            "UnMapDebugInformation",
        },
    }
    if (imports := get_imports(filepath)) is None:
        return 0

    ret = 0
    for dll, _, function in imports:
        if dll.lower() not in watchlist:
            continue

        if function in watchlist[dll.lower()]:
            ret += 1

    return ret


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
        "has_zero_checksum": feature_has_zero_checksum,
        "has_packer": feature_has_packer,
        "has_authenticode": feature_has_authenticode,
        "has_debug_infos": feature_has_debug_infos,
        "has_rich_header": feature_has_rich_header,
        "shannon_entropy": feature_get_shannon_entropy,
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
        feature_values = Parallel(n_jobs=-1)(
            delayed(as_sync)(v, filepath) for v in feature_extractors.values()
        )
        return dict(zip(feature_extractors.keys(), feature_values))


def yield_filepath(dirpath):
    filenames = os.listdir(dirpath)
    for idx, filename in enumerate(filenames):
        filepath = os.path.join(dirpath, filename)
        yield filepath


def handle_dir(dirpath: str) -> str:
    dir_start_time = time.time()

    feature_values = []
    feature_names = []
    filenames = os.listdir(dirpath)
    filenames_length = len(filenames)
    for idx, filename in enumerate(filenames):
        filepath = os.path.join(dirpath, filename)
        if os.path.isdir(filepath):
            continue

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
    feature_names = joblib.load(f"{outdir}/feature_names.joblib")
    df = pd.DataFrame(
        benign_feature_values + malware_feature_values, columns=feature_names
    )
    correlation_matrix = df.corr()
    # Generate a mask for the upper triangle
    mask = np.triu(np.ones_like(correlation_matrix, dtype=bool))
    plt.subplots(figsize=(11, 9))
    sns.heatmap(correlation_matrix, annot=True, mask=mask, square=True)
    plt.savefig(f"{outdir}/correlation_matrix.png", bbox_inches="tight")


def save_feature_importance(
    outdir: str,
    feature_names: T.List[str],
    importances: T.List[int],
    label: str,
) -> None:
    print(f"Save '{label}' feature importance")
    plt.tight_layout()
    bars = plt.barh(feature_names, importances)
    for bar in bars:
        width = bar.get_width()
        label_y = bar.get_y() + bar.get_height() / 2
        plt.text(width, label_y, s=f"{width}")

    plt.xlabel("Feature importance")
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
    label: str,
) -> None:
    print("Create random forest")
    X = pd.DataFrame(feature_values, columns=feature_names)
    y = pd.DataFrame(data_class_distribution, columns=["Binary type"])
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3)
    ((ntest, _), (ntrain, _)) = (X_test.shape, X_train.shape)
    print(f"Train samples: {ntrain}")
    print(f"Test  samples: {ntest}")
    if not os.path.exists(f"{outdir}/{label}.joblib"):
        classifier = RandomForestClassifier(n_jobs=-1)
        classifier.fit(X_train, y_train.values.ravel())
        joblib.dump(classifier, f"{outdir}/{label}.joblib")

    else:
        classifier = joblib.load(f"{outdir}/{label}.joblib")

    y_pred = classifier.predict(X_test)
    print("RF accuracy:", metrics.accuracy_score(y_test, y_pred))
    importances = classifier.feature_importances_
    save_feature_importance(outdir, feature_names, importances, label)
    return classifier


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
    if args.dry:
        features = handle_file(args.dry, "asyncio")
        print(features)

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

                predict(classifier, filepath)

    return 0
