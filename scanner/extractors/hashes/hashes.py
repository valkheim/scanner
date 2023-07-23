#!/usr/bin/env python3

import hashlib
import os
import subprocess
import sys

import tlsh

# Depends on another extractor
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "pe"))

from _pe import get_imports_hash


def get_ssdeep_hash(path: str) -> str:
    """
    https://ssdeep-project.github.io/ssdeep/
    https://blueteamresources.in/ssdeep-hash/
    """
    ssdeep_path = os.path.join(os.path.dirname(__file__), "_ssdeep", "ssdeep")
    cmd = f"{ssdeep_path} -c {path}"
    result = subprocess.check_output(cmd, shell=True)
    return result.decode().splitlines()[-1].split(",")[0]


def get_tlsh_hash(path: str) -> str:
    """
    https://tlsh.org/
    https://pypi.org/project/py-tlsh/
    https://github.com/trendmicro/tlsh/blob/master/TLSH_Introduction.pdf
    https://github.com/trendmicro/tlsh/blob/master/TLSH_CTC_final.pdf
    """
    return tlsh.hash(open(path, "rb").read())


if __name__ == "__main__":
    path = sys.argv[1]
    if (imports_hash := get_imports_hash(path)) is None:
        sys.exit(1)

    print("algorithm,value")
    print(f"md5,{hashlib.md5(open(path,'rb').read()).hexdigest()}")
    print(f"sha1,{hashlib.sha1(open(path,'rb').read()).hexdigest()}")
    print(f"sha256,{hashlib.sha256(open(path,'rb').read()).hexdigest()}")
    print(f"sha512,{hashlib.sha512(open(path,'rb').read()).hexdigest()}")
    print(f"imphash,{imports_hash}")
    print(f"ssdeep,{get_ssdeep_hash(path)}")
    print(f"tlsh,{get_tlsh_hash(path)}")
    sys.exit(0)
