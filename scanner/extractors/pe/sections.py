#!/usr/bin/env python3

import itertools
import sys

from _pe import get_sections


def read_c_string(f: bytes) -> str:
    return "".join((map(chr, itertools.takewhile(lambda x: x, f))))


def decode_characteristics(characteristics: int) -> str:
    return "|".join(
        set(
            [
                v
                for k, v in {
                    0x00000000: "Reserved.",
                    0x00000001: "Reserved.",
                    0x00000002: "Reserved.",
                    0x00000004: "Reserved.",
                    0x00000008: "IMAGE_SCN_TYPE_NO_PAD",  # The section should not be padded to the next boundary. This flag is obsolete and is replaced by IMAGE_SCN_ALIGN_1BYTES.
                    0x00000010: "Reserved.",
                    0x00000020: "IMAGE_SCN_CNT_CODE",  # The section contains executable code.
                    0x00000040: "IMAGE_SCN_CNT_INITIALIZED_DATA",  # The section contains initialized data.
                    0x00000080: "IMAGE_SCN_CNT_UNINITIALIZED_DATA",  # The section contains uninitialized data.
                    0x00000100: "IMAGE_SCN_LNK_OTHER",  # Reserved.
                    0x00000200: "IMAGE_SCN_LNK_INFO",  # The section contains comments or other information. This is valid only for object files.
                    0x00000400: "Reserved.",
                    0x00000800: "IMAGE_SCN_LNK_REMOVE",  # The section will not become part of the image. This is valid only for object files.
                    0x00001000: "IMAGE_SCN_LNK_COMDAT",  # The section contains COMDAT data. This is valid only for object files.
                    0x00002000: "Reserved.",
                    0x00004000: "IMAGE_SCN_NO_DEFER_SPEC_EXC",  # Reset speculative exceptions handling bits in the TLB entries for this section.
                    0x00008000: "IMAGE_SCN_GPREL",  # The section contains data referenced through the global pointer.
                    0x00010000: "Reserved.",  # Reserved.
                    0x00020000: "IMAGE_SCN_MEM_PURGEABLE",  # Reserved.
                    0x00040000: "IMAGE_SCN_MEM_LOCKED",  # Reserved.
                    0x00080000: "IMAGE_SCN_MEM_PRELOAD",  # Reserved.
                    0x00100000: "IMAGE_SCN_ALIGN_1BYTES",  # Align data on a 1-byte boundary. This is valid only for object files.
                    0x00200000: "IMAGE_SCN_ALIGN_2BYTES",  # Align data on a 2-byte boundary. This is valid only for object files.
                    0x00300000: "IMAGE_SCN_ALIGN_4BYTES",  # Align data on a 4-byte boundary. This is valid only for object files.
                    0x00400000: "IMAGE_SCN_ALIGN_8BYTES",  # Align data on a 8-byte boundary. This is valid only for object files.
                    0x00500000: "IMAGE_SCN_ALIGN_16BYTES",  # Align data on a 16-byte boundary. This is valid only for object files.
                    0x00600000: "IMAGE_SCN_ALIGN_32BYTES",  # Align data on a 32-byte boundary. This is valid only for object files.
                    0x00700000: "IMAGE_SCN_ALIGN_64BYTES",  # Align data on a 64-byte boundary. This is valid only for object files.
                    0x00800000: "IMAGE_SCN_ALIGN_128BYTES",  # Align data on a 128-byte boundary. This is valid only for object files.
                    0x00900000: "IMAGE_SCN_ALIGN_256BYTES",  # Align data on a 256-byte boundary. This is valid only for object files.
                    0x00A00000: "IMAGE_SCN_ALIGN_512BYTES",  # Align data on a 512-byte boundary. This is valid only for object files.
                    0x00B00000: "IMAGE_SCN_ALIGN_1024BYTES",  # Align data on a 1024-byte boundary. This is valid only for object files.
                    0x00C00000: "IMAGE_SCN_ALIGN_2048BYTES",  # Align data on a 2048-byte boundary. This is valid only for object files.
                    0x00D00000: "IMAGE_SCN_ALIGN_4096BYTES",  # Align data on a 4096-byte boundary. This is valid only for object files.
                    0x00E00000: "IMAGE_SCN_ALIGN_8192BYTES",  # Align data on a 8192-byte boundary. This is valid only for object files.
                    0x01000000: "IMAGE_SCN_LNK_NRELOC_OVFL",  # The section contains extended relocations. The count of relocations for the section exceeds the 16 bits that is reserved for it in the section header. If the NumberOfRelocations field in the section header is 0xffff, the actual relocation count is stored in the VirtualAddress field of the first relocation. It is an error if IMAGE_SCN_LNK_NRELOC_OVFL is set and there are fewer than 0xffff relocations in the section.
                    0x02000000: "IMAGE_SCN_MEM_DISCARDABLE",  # The section can be discarded as needed.
                    0x04000000: "IMAGE_SCN_MEM_NOT_CACHED",  # The section cannot be cached.
                    0x08000000: "IMAGE_SCN_MEM_NOT_PAGED",  # The section cannot be paged.
                    0x10000000: "IMAGE_SCN_MEM_SHARED",  # The section can be shared in memory.
                    0x20000000: "IMAGE_SCN_MEM_EXECUTE",  # The section can be executed as code.
                    0x40000000: "IMAGE_SCN_MEM_READ",  # The section can be read.
                    0x80000000: "IMAGE_SCN_MEM_WRITE",  # The section can be written to.
                }.items()
                if characteristics & k
            ]
        )
    )


if __name__ == "__main__":
    if (sections := get_sections(sys.argv[1])) is None:
        sys.exit(1)

    print(
        "name,virtual_address,raw_size,virtual_size,characteristics,characteristics_ex,entropy,md5"
    )
    for name, va, rs, vs, char, ent, md5 in sections:
        line = [
            read_c_string(name),
            f"{va:#0x}",
            f"{rs:#0x}",
            f"{vs:#0x}",
            f"{char:#0x}",
            decode_characteristics(char),
            f"{ent}",
            f"{md5}",
        ]
        print(",".join(line))

    sys.exit(0)
