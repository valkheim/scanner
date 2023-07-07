#!/usr/bin/env python3

import math
import os
import sys

from _entropy import get_entropy
from PIL import Image


def yield_chunk_entropy(data: bytes, size: int, unit: str):
    for x in range(len(data) // size):
        start = x * size
        end = start + size
        yield get_entropy(data[start:end], unit)


def normalize(a):
    amin, amax = min(a), max(a)
    for i, val in enumerate(a):
        a[i] = round((val - amin) / (amax - amin) * 255)
    return a


if __name__ == "__main__":
    chunk_size = 16
    with open(sys.argv[1], "rb") as fh:
        data = fh.read()

    # Compute entropy for each chunk
    chunks_entropy = [
        _ for _ in yield_chunk_entropy(data, chunk_size, "shannon")
    ]

    # Normalize vector in range 0,255 for pixelization
    vmin, vmax = min(chunks_entropy), max(chunks_entropy)
    for idx, val in enumerate(chunks_entropy):
        chunks_entropy[idx] = round((val - vmin) / (vmax - vmin) * 0xFF)

    # Prepare image from bytes
    sq = int(math.sqrt(len(chunks_entropy)))
    im = Image.frombytes("L", (sq, sq), bytes(chunks_entropy))
    # im.show()
    path = os.path.join(sys.argv[2], "entropy.png")
    im.save(path)
    print(f"entropy visualization saved to {path}")
