import math
import typing as T
from collections import Counter


def get_entropy(data: bytes, unit: str) -> float:
    base = {"shannon": 2.0, "natural": math.exp(1), "hartley": 10.0}
    if len(data) <= 1:
        return 0

    counts: T.Counter[int] = Counter()
    for d in data:
        counts[d] += 1

    ent = 0.0
    probs = [float(c) / len(data) for c in counts.values()]
    for p in probs:
        if p > 0.0:
            ent -= p * math.log(p, base[unit])

    return ent
