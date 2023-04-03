#!/usr/bin/env python3

import sys

import joblib
from _pe import (  # noqa
    get_exports,
    get_imports,
    get_resources,
    get_sections,
    get_stamps,
)


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


if __name__ == "__main__":
    feature_extractors = {
        "amount_of_exports": feature_amount_of_exports,
        "amount_of_imports": feature_amount_of_imports,
        "amount_of_distinct_import_modules": feature_amount_of_distinct_import_modules,
        "amount_of_sections": feature_amount_of_sections,
        "amount_of_resources": feature_amount_of_resources,
        "amount_of_zero_stamps": feature_amount_of_zero_stamps,
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
