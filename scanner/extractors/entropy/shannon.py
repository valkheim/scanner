#!/usr/bin/env python3

import sys
import math
from collections import Counter

with open(sys.argv[1], "rb") as fh:
    data = fh.read()
    p = Counter(data)
    lns = float(len(data))
    entropy = -sum(count / lns * math.log(count / lns, 2) for count in p.values())
    print(entropy)
