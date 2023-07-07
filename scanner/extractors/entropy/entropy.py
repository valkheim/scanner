#!/usr/bin/env python3

import sys

from _entropy import get_entropy

if __name__ == "__main__":
    with open(sys.argv[1], "rb") as fh:
        data = fh.read()
        print("algorithm,value")
        print(f"shannon,{get_entropy(data, 'shannon')}")
        print(f"natural,{get_entropy(data, 'natural')}")
        print(f"hartley,{get_entropy(data, 'hartley')}")
