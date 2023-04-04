#!/usr/bin/env python3

import sys

import joblib
from _pe import (  # noqa
    get_exports,
    get_header_infos,
    get_imports,
    get_packers,
    get_resources,
    get_rich_header,
    get_sections,
    get_stamps,
    get_subsystem,
    has_valid_checksum,
)

from scanner.extractors.entropy.entropy import get_entropy
from scanner.extractors.pe.debug import get_debug_infos


def feature_amount_of_exports(filepath: str):
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


def feature_has_valid_checksum(filepath: str) -> int:
    return has_valid_checksum(filepath)


def feature_has_zero_checksum(filepath: str) -> int:
    hdr = get_header_infos(filepath)
    if "CheckSum" in hdr:
        return hdr["CheckSum"] == 0

    return 0


def feature_has_packer(filepath: str) -> int:
    return get_packers(filepath) == []


def feature_has_debug_infos(filepath: str) -> int:
    guid, filepath = get_debug_infos(filepath)
    return guid is not None or filepath is not None


def feature_has_rich_header(filepath: str) -> int:
    return get_rich_header(filepath) is not None


def feature_has_suspicious_shannon_overall_entropy(filepath: str) -> int:
    with open(filepath, "rb") as fh:
        data = fh.read()

    return get_entropy(data, "shannon") >= 7.2


def feature_has_native_subsystem(filepath: str) -> int:
    ss_id, _ = get_subsystem(filepath)
    return ss_id == 1


def feature_has_gui_subsystem(filepath: str) -> int:
    ss_id, _ = get_subsystem(filepath)
    return ss_id == 2


def feature_has_cui_subsystem(filepath: str) -> int:
    ss_id, _ = get_subsystem(filepath)
    return ss_id == 3


def feature_has_suspicious_number_of_imports(filepath: str) -> int:
    n = len(get_imports(filepath) or [])
    return n < 10 or 500 < n


def feature_has_suspicious_SizeOfImage(filepath: str) -> int:
    header = get_header_infos(filepath)
    if header is None or not hasattr(header, "SizeOfImage"):
        return False

    size = header["SizeOfImage"]
    return size < 0x1000 or 0xA00000 < size


if __name__ == "__main__":
    feature_extractors = {
        "amount_of_exports": feature_amount_of_exports,
        "amount_of_imports": feature_amount_of_imports,
        "amount_of_distinct_import_modules": feature_amount_of_distinct_import_modules,
        "amount_of_sections": feature_amount_of_sections,
        "amount_of_resources": feature_amount_of_resources,
        "amount_of_zero_stamps": feature_amount_of_zero_stamps,
        "has_zero_checksum": feature_has_zero_checksum,
        "has_valid_checksum": feature_has_valid_checksum,
        "has_packer": feature_has_packer,
        "has_debug_infos": feature_has_debug_infos,
        "has_rich_header": feature_has_rich_header,
        "has_native_subsystem": feature_has_native_subsystem,
        "has_gui_subsystem": feature_has_gui_subsystem,
        "has_cui_subsystem": feature_has_cui_subsystem,
        "has_suspicious_shannon_overall_entropy": feature_has_suspicious_shannon_overall_entropy,
        "has_suspicious_number_of_imports": feature_has_suspicious_number_of_imports,
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
