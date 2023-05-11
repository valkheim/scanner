import os
import random
import typing as T


def get_golden_results_dir():
    return os.path.join(os.path.dirname(__file__), "golden")


def get_some_golden_hash():
    golden_dir = get_golden_results_dir()
    return random.choice(os.listdir(golden_dir))


def get_some_golden_result(hash: T.Optional[str] = None) -> str:
    golden_dir = get_golden_results_dir()
    if hash is None:
        hash = random.choice(os.listdir(golden_dir))

    return os.path.join(golden_dir, hash)
