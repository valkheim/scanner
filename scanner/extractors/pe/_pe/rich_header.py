# From      https://github.com/RichHeaderResearch/RichPE/blob/master/spoof_check.py
# Updated   https://github.com/Te-k/pecli/blob/master/pecli/lib/richpe.py
# Also      https://github.com/hasherezade/bearparser/blob/master/parser/pe/RichHdrWrapper.cpp
#           https://github.com/kirschju/richheader/blob/master/prodids.py
# up to date list https://github.com/dishather/richprint/blob/master/comp_id.txt
# also check the xml\rich-header.xml database of pe studio

import os
import typing as T

KNOWN_PRODUCT_IDS = {
    0: "Unknown",
    1: "Import0",
    2: "Linker510",
    3: "Cvtomf510",
    4: "Linker600",
    5: "Cvtomf600",
    6: "Cvtres500",
    7: "Utc11_Basic",
    8: "Utc11_C",
    9: "Utc12_Basic",
    10: "Utc12_C",
    11: "Utc12_CPP",
    12: "AliasObj60",
    13: "VisualBasic60",
    14: "Masm613",
    15: "Masm710",
    16: "Linker511",
    17: "Cvtomf511",
    18: "Masm614",
    19: "Linker512",
    20: "Cvtomf512",
    21: "Utc12_C_Std",
    22: "Utc12_CPP_Std",
    23: "Utc12_C_Book",
    24: "Utc12_CPP_Book",
    25: "Implib700",
    26: "Cvtomf700",
    27: "Utc13_Basic",
    28: "Utc13_C",
    29: "Utc13_CPP",
    30: "Linker610",
    31: "Cvtomf610",
    32: "Linker601",
    33: "Cvtomf601",
    34: "Utc12_1_Basic",
    35: "Utc12_1_C",
    36: "Utc12_1_CPP",
    37: "Linker620",
    38: "Cvtomf620",
    39: "AliasObj70",
    40: "Linker621",
    41: "Cvtomf621",
    42: "Masm615",
    43: "Utc13_LTCG_C",
    44: "Utc13_LTCG_CPP",
    45: "Masm620",
    46: "ILAsm100",
    47: "Utc12_2_Basic",
    48: "Utc12_2_C",
    49: "Utc12_2_CPP",
    50: "Utc12_2_C_Std",
    51: "Utc12_2_CPP_Std",
    52: "Utc12_2_C_Book",
    53: "Utc12_2_CPP_Book",
    54: "Implib622",
    55: "Cvtomf622",
    56: "Cvtres501",
    57: "Utc13_C_Std",
    58: "Utc13_CPP_Std",
    59: "Cvtpgd1300",
    60: "Linker622",
    61: "Linker700",
    62: "Export622",
    63: "Export700",
    64: "Masm700",
    65: "Utc13_POGO_I_C",
    66: "Utc13_POGO_I_CPP",
    67: "Utc13_POGO_O_C",
    68: "Utc13_POGO_O_CPP",
    69: "Cvtres700",
    70: "Cvtres710p",
    71: "Linker710p",
    72: "Cvtomf710p",
    73: "Export710p",
    74: "Implib710p",
    75: "Masm710p",
    76: "Utc1310p_C",
    77: "Utc1310p_CPP",
    78: "Utc1310p_C_Std",
    79: "Utc1310p_CPP_Std",
    80: "Utc1310p_LTCG_C",
    81: "Utc1310p_LTCG_CPP",
    82: "Utc1310p_POGO_I_C",
    83: "Utc1310p_POGO_I_CPP",
    84: "Utc1310p_POGO_O_C",
    85: "Utc1310p_POGO_O_CPP",
    86: "Linker624",
    87: "Cvtomf624",
    88: "Export624",
    89: "Implib624",
    90: "Linker710",
    91: "Cvtomf710",
    92: "Export710",
    93: "Implib710",
    94: "Cvtres710",
    95: "Utc1310_C",
    96: "Utc1310_CPP",
    97: "Utc1310_C_Std",
    98: "Utc1310_CPP_Std",
    99: "Utc1310_LTCG_C",
    100: "Utc1310_LTCG_CPP",
    101: "Utc1310_POGO_I_C",
    102: "Utc1310_POGO_I_CPP",
    103: "Utc1310_POGO_O_C",
    104: "Utc1310_POGO_O_CPP",
    105: "AliasObj710",
    106: "AliasObj710p",
    107: "Cvtpgd1310",
    108: "Cvtpgd1310p",
    109: "Utc1400_C",
    110: "Utc1400_CPP",
    111: "Utc1400_C_Std",
    112: "Utc1400_CPP_Std",
    113: "Utc1400_LTCG_C",
    114: "Utc1400_LTCG_CPP",
    115: "Utc1400_POGO_I_C",
    116: "Utc1400_POGO_I_CPP",
    117: "Utc1400_POGO_O_C",
    118: "Utc1400_POGO_O_CPP",
    119: "Cvtpgd1400",
    120: "Linker800",
    121: "Cvtomf800",
    122: "Export800",
    123: "Implib800",
    124: "Cvtres800",
    125: "Masm800",
    126: "AliasObj800",
    127: "PhoenixPrerelease",
    128: "Utc1400_CVTCIL_C",
    129: "Utc1400_CVTCIL_CPP",
    130: "Utc1400_LTCG_MSIL",
    131: "Utc1500_C",
    132: "Utc1500_CPP",
    133: "Utc1500_C_Std",
    134: "Utc1500_CPP_Std",
    135: "Utc1500_CVTCIL_C",
    136: "Utc1500_CVTCIL_CPP",
    137: "Utc1500_LTCG_C",
    138: "Utc1500_LTCG_CPP",
    139: "Utc1500_LTCG_MSIL",
    140: "Utc1500_POGO_I_C",
    141: "Utc1500_POGO_I_CPP",
    142: "Utc1500_POGO_O_C",
    143: "Utc1500_POGO_O_CPP",
    144: "Cvtpgd1500",
    145: "Linker900",
    146: "Export900",
    147: "Implib900",
    148: "Cvtres900",
    149: "Masm900",
    150: "AliasObj900",
    151: "Resource900",
    152: "AliasObj1000",
    154: "Cvtres1000",
    155: "Export1000",
    156: "Implib1000",
    157: "Linker1000",
    158: "Masm1000",
    170: "Utc1600_C",
    171: "Utc1600_CPP",
    172: "Utc1600_CVTCIL_C",
    173: "Utc1600_CVTCIL_CPP",
    174: "Utc1600_LTCG_C ",
    175: "Utc1600_LTCG_CPP",
    176: "Utc1600_LTCG_MSIL",
    177: "Utc1600_POGO_I_C",
    178: "Utc1600_POGO_I_CPP",
    179: "Utc1600_POGO_O_C",
    180: "Utc1600_POGO_O_CPP",
    183: "Linker1010",
    184: "Export1010",
    185: "Implib1010",
    186: "Cvtres1010",
    187: "Masm1010",
    188: "AliasObj1010",
    199: "AliasObj1100",
    201: "Cvtres1100",
    202: "Export1100",
    203: "Implib1100",
    204: "Linker1100",
    205: "Masm1100",
    206: "Utc1700_C",
    207: "Utc1700_CPP",
    208: "Utc1700_CVTCIL_C",
    209: "Utc1700_CVTCIL_CPP",
    210: "Utc1700_LTCG_C ",
    211: "Utc1700_LTCG_CPP",
    212: "Utc1700_LTCG_MSIL",
    213: "Utc1700_POGO_I_C",
    214: "Utc1700_POGO_I_CPP",
    215: "Utc1700_POGO_O_C",
    216: "Utc1700_POGO_O_CPP",
    219: "Cvtres1200",
    220: "Export1200",
    221: "Implib1200",
    222: "Linker1200",
    223: "Masm1200",
    # Speculation
    224: "AliasObj1200",
    237: "Cvtres1210",
    238: "Export1210",
    239: "Implib1210",
    240: "Linker1210",
    241: "Masm1210",
    # Speculation
    242: "Utc1810_C",
    243: "Utc1810_CPP",
    244: "Utc1810_CVTCIL_C",
    245: "Utc1810_CVTCIL_CPP",
    246: "Utc1810_LTCG_C ",
    247: "Utc1810_LTCG_CPP",
    248: "Utc1810_LTCG_MSIL",
    249: "Utc1810_POGO_I_C",
    250: "Utc1810_POGO_I_CPP",
    251: "Utc1810_POGO_O_C",
    252: "Utc1810_POGO_O_CPP",
    255: "Cvtres1400",
    256: "Export1400",
    257: "Implib1400",
    258: "Linker1400",
    259: "Masm1400",
    260: "Utc1900_C",
    261: "Utc1900_CPP",
    # Speculation
    262: "Utc1900_CVTCIL_C",
    263: "Utc1900_CVTCIL_CPP",
    264: "Utc1900_LTCG_C ",
    265: "Utc1900_LTCG_CPP",
    266: "Utc1900_LTCG_MSIL",
    267: "Utc1900_POGO_I_C",
    268: "Utc1900_POGO_I_CPP",
    269: "Utc1900_POGO_O_C",
    270: "Utc1900_POGO_O_CPP",
}


def vs_version(product_id: int) -> T.Optional[str]:
    """https://raw.githubusercontent.com/dishather/richprint/master/comp_id.txt"""
    h = hex(product_id)[2:]
    h = "0" * (8 - len(h)) + h
    database = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "comp_id.txt"
    )
    with open(database, "rt") as fh:
        for line in fh:
            if line.startswith(h):
                return line.rstrip()[line.find("] ") + 2 :]

    return None


def vs_version_fallback(i: int) -> T.Optional[str]:
    if i > len(KNOWN_PRODUCT_IDS) or i < 0:
        return None
    elif i in range(0x0106, 0x010A + 1):
        return "Visual Studio 2017 14.01+"
    elif i in range(0x00FD, 0x0106):
        return "Visual Studio 2015 (14.00)"
    elif i in range(0x00EB, 0x00FD):
        return "Visual Studio 2013 (12.10)"
    elif i in range(0x00D9, 0x00EB):
        return "Visual Studio 2013 (12.00)"
    elif i in range(0x00C7, 0x00D9):
        return "Visual Studio 2012 (11.00)"
    elif i in range(0x00B5, 0x00C7):
        return "Visual Studio 2010 (10.10)"
    elif i in range(0x0098, 0x00B5):
        return "Visual Studio 2010 (10.00)"
    elif i in range(0x0083, 0x0098):
        return "Visual Studio 2008 (09.00)"
    elif i in range(0x006D, 0x0083):
        return "Visual Studio 2005 (08.00)"
    elif i in range(0x005A, 0x006D):
        return "Visual Studio 2003 (07.10)"
    elif i in [0xA, 0xB, 0xD, 0x15, 0x16]:
        return "Visual Studio 6.0 (06.00)"
    elif i in [0x2, 0x6, 0xC, 0xE]:
        return "Visual Studio 97 (05.00)"
    elif i == 1:
        return "Visual Studio (00.00)"

    return None
