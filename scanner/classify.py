import argparse
import os
import sys
import typing as T

import joblib
import pandas
import seaborn
from sklearn.tree import DecisionTreeClassifier, export_graphviz

from scanner.extractors.entropy.entropy import get_entropy
from scanner.extractors.pe.authenticode import get_lief_binary, has_authenticode
from scanner.extractors.pe.debug import get_debug_infos

sys.path.append(
    os.path.join(os.path.dirname(__file__), "extractors", "pe")
)  # noqa
import collections
import re

from scanner.extractors.pe._pe import (  # noqa
    get_exports,
    get_header_infos,
    get_imports,
    get_packers,
    get_resources,
    get_rich_header,
    get_sections,
    get_stamps,
    get_subsystem,
)

ASCII_BYTE = rb" !\"#\$%&\'\(\)\*\+,-\./0123456789:;<=>\?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}\\\~\t"


def feature_amount_of_ascii_strings(filepath: str) -> int:
    with open(filepath, "rb") as fh:
        ascii_re = re.compile(rb"([%s]{%d,})" % (ASCII_BYTE, 5))
        return sum(1 for _ in re.finditer(ascii_re, fh.read()))


def feature_amount_of_unicode_strings(filepath: str) -> int:
    with open(filepath, "rb") as fh:
        unicode_re = re.compile(b"((?:[%s]\x00){%d,})" % (ASCII_BYTE, 5))
        return sum(1 for _ in re.finditer(unicode_re, fh.read()))


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


def feature_has_non_zero_checksum(filepath: str) -> int:
    hdr = get_header_infos(filepath)
    has_non_zero_checksum = hasattr(hdr, "CheckSum")
    if has_non_zero_checksum:
        has_non_zero_checksum = has_non_zero_checksum != 0

    return int(has_non_zero_checksum)


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


def feature_get_shannon_entropy(filepath: str) -> int:
    with open(filepath, "rb") as fh:
        data = fh.read()
        return get_entropy(data, "shannon")


def feature_has_packer(filepath: str) -> int:
    return int(not not get_packers(filepath))


def feature_has_authenticode(filepath: str) -> int:
    if (binary := get_lief_binary(filepath)) is None:
        return int(False)

    return int(has_authenticode(binary))


def feature_has_debug_infos(filepath: str) -> int:
    guid, filepath = get_debug_infos(filepath)
    return int(guid is not None or filepath is not None)


def feature_has_rich_header(filepath: str) -> int:
    return int(get_rich_header(filepath) is not None)


def feature_get_subsystem(filepath: str):
    ss_id, _ = get_subsystem(filepath)
    # return int(ss_id or 0)
    return {
        "subsystem_is_unknown": int(ss_id == 0),
        "subsystem_is_native": int(ss_id == 1),
        "subsystem_is_gui": int(ss_id == 2),
        "subsystem_is_cui": int(ss_id == 3),
    }


#####################


def handle_file(filepath: str) -> T.Dict[str, int]:
    return {
        "amount_of_exports": feature_amount_of_exports(filepath),
        "amount_of_imports": feature_amount_of_imports(filepath),
        "amount_of_distinct_import_modules": feature_amount_of_distinct_import_modules(
            filepath
        ),
        "amount_of_sections": feature_amount_of_sections(filepath),
        "amount_of_resources": feature_amount_of_resources(filepath),
        "amount_of_zero_stamps": feature_amount_of_zero_stamps(filepath),
        "amount_of_ascii_strings": feature_amount_of_ascii_strings(filepath),
        "amount_of_unicode_strings": feature_amount_of_unicode_strings(
            filepath
        ),
        "has_non_zero_checksum": feature_has_non_zero_checksum(filepath),
        "has_packer": feature_has_packer(filepath),
        "has_authenticode": feature_has_authenticode(filepath),
        "has_debug_infos": feature_has_debug_infos(filepath),
        "has_rich_header": feature_has_rich_header(filepath),
        "shannon_entropy": feature_get_shannon_entropy(filepath),
        **feature_get_subsystem(filepath),
        # "amount_of_stamps": len(stamps.values()) if stamps else 0,
    }


def handle_dir(dirpath: str) -> str:
    feature_values = []
    feature_names = []
    filenames = os.listdir(dirpath)
    filenames_length = len(filenames)
    for idx, filename in enumerate(filenames):
        filepath = os.path.join(dirpath, filename)
        print(
            f"[{idx + 1}/{filenames_length}] Handle {os.path.abspath(filepath)}"
        )
        features = handle_file(filepath)
        feature_values.append(list(features.values()))
        feature_names = list(features.keys())

    return feature_names, feature_values


def create_scatter_matrix(
    feature_values,
    feature_names,
    benign_feature_values,
    malware_feature_values,
):
    print("Create scatter matrix")
    df = pandas.DataFrame(feature_values, columns=feature_names)
    for col in df:
        df[col] = df[col].astype(float)

    df["__type"] = ["Benign"] * len(benign_feature_values) + ["Malware"] * len(
        malware_feature_values
    )
    scatter = seaborn.pairplot(
        df,
        kind="scatter",
        hue="__type",
        diag_kind="hist",
        corner=True,
        markers=["o", "D"],
    )
    scatter.fig.savefig("cache/scatter.png")


def create_decision_tree(
    feature_values, feature_names, data_class_distribution, class_names
):
    print("Create decision tree")
    X = pandas.DataFrame(feature_values, columns=feature_names)
    y = pandas.DataFrame(data_class_distribution, columns=["Binary type"])
    classifier = DecisionTreeClassifier(
        criterion="gini",
        splitter="random",
        # min_samples_split = 5,  # The minimum number of samples required to split an internal node
        # min_samples_leaf = 10,  # The minimum number of samples required to be at a leaf node. A split point at any depth will only be considered if it leaves at least min_samples_leaf training samples in each of the left and right branches. This may have the effect of smoothing the model, especially in regression.
        max_depth=4,  # The maximum depth of the tree. If None, then nodes are expanded until all leaves are pure or until all leaves contain less than min_samples_split samples.
        max_features="log2",
    )
    classifier.fit(X.values, y)
    export_graphviz(
        classifier,
        out_file="cache/classifier.dot",
        class_names=class_names,
        feature_names=feature_names,
        filled=True,
        rounded=True,
    )
    os.system("dot cache/classifier.dot -Tpng -o cache/classifier.png")


def run(args: argparse.Namespace) -> int:
    # Fetch malware features
    if not os.path.exists("cache/malware_feature_values.joblib"):
        feature_names, malware_feature_values = handle_dir(args.malwares_dir)
        joblib.dump(
            malware_feature_values, "cache/malware_feature_values.joblib"
        )
        if not os.path.exists("cache/feature_names.joblib"):
            joblib.dump(feature_names, "cache/feature_names.joblib")

    else:
        malware_feature_values = joblib.load(
            "cache/malware_feature_values.joblib"
        )

    # Fetch benign features
    if not os.path.exists("cache/benign_feature_values.joblib"):
        _, benign_feature_values = handle_dir(args.benigns_dir)
        joblib.dump(
            benign_feature_values, "cache/benign_feature_values.joblib"
        )

    else:
        benign_feature_values = joblib.load(
            "cache/benign_feature_values.joblib"
        )

    # Prepare datasets
    class_names = (
        "benign",
        "malware",
    )
    feature_names = joblib.load("cache/feature_names.joblib")
    feature_values = benign_feature_values + malware_feature_values
    data_class_distribution = [0] * len(benign_feature_values) + [1] * len(
        malware_feature_values
    )

    # Visualize feature
    # create_scatter_matrix(feature_values, feature_names, benign_feature_values, malware_feature_values)
    from sklearn.linear_model import LinearRegression

    X = pandas.DataFrame(feature_values, columns=feature_names)
    y = pandas.DataFrame(data_class_distribution, columns=["Binary type"])
    model = LinearRegression()
    model.fit(X, y)
    importance = model.coef_
    print(importance)
    # summarize feature importance
    for i, v in enumerate(importance):
        print("Feature: %0d, Score: %.5f" % (i, v))

    # Classify
    # create_decision_tree(
    #    feature_values, feature_names, data_class_distribution, class_names
    # )

    return 0
