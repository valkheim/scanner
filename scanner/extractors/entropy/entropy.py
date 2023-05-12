#!/usr/bin/env python3

import math
import sys
from collections import Counter


def get_entropy(data: bytes, unit: str) -> float:
    base = {"shannon": 2.0, "natural": math.exp(1), "hartley": 10.0}
    if len(data) <= 1:
        return 0

    counts: Counter[int] = Counter()
    for d in data:
        counts[d] += 1

    ent = 0.0
    probs = [float(c) / len(data) for c in counts.values()]
    for p in probs:
        if p > 0.0:
            ent -= p * math.log(p, base[unit])

    return ent


if __name__ == "__main__":
    with open(sys.argv[1], "rb") as fh:
        data = fh.read()
        print("algorithm,value")
        print(f"shannon,{get_entropy(data, 'shannon')}")
        print(f"natural,{get_entropy(data, 'natural')}")
        print(f"hartley,{get_entropy(data, 'hartley')}")
