import argparse
import os
import sys
import typing as T

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
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

from scanner.extractors.pe._pe import get_exports  # noqa
from scanner.extractors.pe._pe import get_header_infos  # noqa
from scanner.extractors.pe._pe import get_imports  # noqa
from scanner.extractors.pe._pe import get_packers  # noqa
from scanner.extractors.pe._pe import get_resources  # noqa
from scanner.extractors.pe._pe import get_rich_header  # noqa
from scanner.extractors.pe._pe import get_sections  # noqa
from scanner.extractors.pe._pe import get_stamps  # noqa
from scanner.extractors.pe._pe import get_subsystem  # noqa

ASCII_BYTE = rb" !\"#\$%&\'\(\)\*\+,-\./0123456789:;<=>\?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}\\\~\t"
CACHE = os.path.normpath(
    os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "cache")
)


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
        # "subsystem_is_unknown": int(ss_id == 0),
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
        # "has_non_zero_checksum": feature_has_non_zero_checksum(filepath),
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
