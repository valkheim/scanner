import argparse
import os
import sys
import typing as T

import joblib
import pandas
from sklearn.tree import DecisionTreeClassifier, export_graphviz

from scanner.extractors.entropy.entropy import get_entropy
from scanner.extractors.pe.authenticode import get_lief_binary, has_authenticode

sys.path.append(
    os.path.join(os.path.dirname(__file__), "extractors", "pe")
)  # noqa
from scanner.extractors.pe._pe import (  # noqa
    get_exports,
    get_header_infos,
    get_imports,
    get_packers,
    get_resources,
    get_sections,
    get_stamps,
)


def feature_amount_of_exports(filepath: str):
    return len(get_exports(filepath) or [])


def feature_amount_of_imports(filepath: str) -> int:
    return len(get_imports(filepath) or [])


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


#####################


def handle_file(filepath: str) -> T.Dict[str, int]:
    return {
        "amount_of_exports": feature_amount_of_exports(filepath),
        "amount_of_imports": feature_amount_of_imports(filepath),
        "amount_of_sections": feature_amount_of_sections(filepath),
        "amount_of_resources": feature_amount_of_resources(filepath),
        "amount_of_zero_stamps": feature_amount_of_zero_stamps(filepath),
        "has_non_zero_checksum": feature_has_non_zero_checksum(filepath),
        "shannon_entropy": feature_get_shannon_entropy(filepath),
        "has_packer": feature_has_packer(filepath),
        "has_authenticode": feature_has_authenticode(filepath),
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


def create_decision_tree(
    feature_values, feature_names, data_class_distribution, class_names
):
    X = pandas.DataFrame(feature_values, columns=feature_names)
    y = pandas.DataFrame(data_class_distribution, columns=["Data class"])
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
        out_file="classifier.dot",
        class_names=class_names,
        feature_names=feature_names,
        filled=True,
        rounded=True,
    )
    os.system("dot classifier.dot -Tpng -o classifier.png")


def run(args: argparse.Namespace) -> int:
    # Fetch malware features
    if not os.path.exists("cache/malware_feature_values.joblib"):
        feature_names, malware_feature_values = handle_dir(args.malwares_dir)
        breakpoint()
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

    # Classify
    create_decision_tree(
        feature_values, feature_names, data_class_distribution, class_names
    )

    return 0
