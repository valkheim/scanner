import os
import random


def get_golden_results_dir() -> str:
    return os.path.join(os.path.dirname(__file__), "golden")


def get_some_golden_hash() -> str:
    golden_dir = get_golden_results_dir()
    return random.choice(os.listdir(golden_dir))


def get_some_golden_result(hash: str | None = None) -> str:
    golden_dir = get_golden_results_dir()
    if hash is None:
        hash = random.choice(os.listdir(golden_dir))

    return os.path.join(golden_dir, hash)
