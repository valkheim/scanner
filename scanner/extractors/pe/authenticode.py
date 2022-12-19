#!/usr/bin/env python3

# https://github.com/lief-project/LIEF/blob/master/examples/python/authenticode/authenticode_reader.py

import sys

import lief


def print_attr(indent: int, auth: lief.PE.Attribute):
    if auth.type == lief.PE.SIG_ATTRIBUTE_TYPES.CONTENT_TYPE:
        print_content_type(indent, auth)
    elif auth.type == lief.PE.SIG_ATTRIBUTE_TYPES.PKCS9_SIGNING_TIME:
        print_signing_time(indent, auth)
    elif auth.type == lief.PE.SIG_ATTRIBUTE_TYPES.MS_SPC_STATEMENT_TYPE:
        print_ms_statement_type(indent, auth)
    elif auth.type == lief.PE.SIG_ATTRIBUTE_TYPES.PKCS9_MESSAGE_DIGEST:
        print_pkcs_msg_dg(indent, auth)
    elif auth.type == lief.PE.SIG_ATTRIBUTE_TYPES.PKCS9_COUNTER_SIGNATURE:
        print_pkcs_counter_sig(indent, auth)
    elif auth.type == lief.PE.SIG_ATTRIBUTE_TYPES.GENERIC_TYPE:
        print_generic_type(indent, auth)
    elif auth.type == lief.PE.SIG_ATTRIBUTE_TYPES.SPC_SP_OPUS_INFO:
        print_spc_sp_opus_info(indent, auth)
    elif auth.type == lief.PE.SIG_ATTRIBUTE_TYPES.MS_SPC_NESTED_SIGN:
        print_ms_nested_sig(indent, auth)
    elif auth.type == lief.PE.SIG_ATTRIBUTE_TYPES.PKCS9_AT_SEQUENCE_NUMBER:
        print_pkcs9_at_seq_number(indent, auth)
    else:
        print(" " * indent, type(auth), auth)


def print_pkcs9_at_seq_number(
    indent: int, auth: lief.PE.PKCS9AtSequenceNumber
):
    print("{} PKCS #9 sequence number: {}".format(" " * indent, auth.number))


def print_ms_nested_sig(indent: int, auth: lief.PE.MsSpcNestedSignature):
    print("{} MS Nested Signature:".format(" " * indent))
    print_all(auth.signature, indent + 2)


def print_spc_sp_opus_info(indent: int, auth: lief.PE.SpcSpOpusInfo):
    if len(auth.program_name) > 0 and len(auth.more_info) > 0:
        print(
            "{} Info: {} {}".format(
                " " * indent, auth.program_name, auth.more_info
            )
        )
    elif len(auth.program_name) > 0 and len(auth.more_info) == 0:
        print("{} Info: {}".format(" " * indent, auth.program_name))
    elif len(auth.program_name) == 0 and len(auth.more_info) > 0:
        print("{} Info: {}".format(" " * indent, auth.more_info))
    else:
        print("{} Info: <empty>".format(" " * indent))


def print_generic_type(indent: int, auth: lief.PE.GenericType):
    print(
        "{} Generic Type {} ({})".format(
            " " * indent, auth.oid, lief.PE.oid_to_string(auth.oid)
        )
    )


def print_content_type(indent: int, auth: lief.PE.ContentType):
    print(
        "{} Content Type OID: {} ({})".format(
            " " * indent, auth.oid, lief.PE.oid_to_string(auth.oid)
        )
    )


def print_signing_time(indent: int, auth: lief.PE.PKCS9SigningTime):
    print(
        "{} Signing Time: {}/{:02}/{:02} - {:02}:{:02}:{:02}".format(
            " " * indent, *auth.time
        )
    )


def print_ms_statement_type(indent: int, auth: lief.PE.MsSpcStatementType):
    print(
        "{} MS Statement type OID: {} ({})".format(
            " " * indent, auth.oid, lief.PE.oid_to_string(auth.oid)
        )
    )


def print_pkcs_msg_dg(indent: int, auth: lief.PE.PKCS9MessageDigest):
    print(
        "{} PKCS9 Message Digest: {}".format(" " * indent, auth.digest.hex())
    )


def print_crt(indent: int, crt: lief.PE.x509):
    print("{}  Version            : {:d}".format(" " * indent, crt.version))
    print("{}  Issuer             : {}".format(" " * indent, crt.issuer))
    print("{}  Subject            : {}".format(" " * indent, crt.subject))
    print(
        "{}  Serial Number      : {}".format(
            " " * indent, crt.serial_number.hex()
        )
    )
    print(
        "{}  Signature Algorithm: {}".format(
            " " * indent, lief.PE.oid_to_string(crt.signature_algorithm)
        )
    )
    print(
        "{}  Valid from         : {}/{:02d}/{:02d} - {:02d}:{:02d}:{:02d}".format(
            " " * indent, *crt.valid_from
        )
    )
    print(
        "{}  Valid to           : {}/{:02d}/{:02d} - {:02d}:{:02d}:{:02d}".format(
            " " * indent, *crt.valid_to
        )
    )
    if len(crt.key_usage) > 0:
        print(
            "{}  Key usage          : {}".format(
                " " * indent,
                " - ".join(str(e).split(".")[-1] for e in crt.key_usage),
            )
        )

    if len(crt.ext_key_usage) > 0:
        print(
            "{}  Ext key usage      : {}".format(
                " " * indent,
                " - ".join(
                    lief.PE.oid_to_string(e) for e in crt.ext_key_usage
                ),
            )
        )

    if crt.rsa_info is not None:
        rsa_info = crt.rsa_info
        print(
            "{}  RSA key size       : {}".format(
                " " * indent, rsa_info.key_size
            )
        )

    print(
        "{}  ===========================================".format(" " * indent)
    )


def print_pkcs_counter_sig(indent: int, auth: lief.PE.PKCS9CounterSignature):
    print("{} PKCS9 counter signature".format(" " * indent))
    signer = auth.signer
    print(
        "{}   Version             : {:d}".format(" " * indent, signer.version)
    )
    print(
        "{}   Serial Number       : {}".format(
            " " * indent, signer.serial_number.hex()
        )
    )
    print("{}   Issuer              : {}".format(" " * indent, signer.issuer))
    print(
        "{}   Digest Algorithm    : {}".format(
            " " * indent, signer.digest_algorithm
        )
    )
    print(
        "{}   Encryption Algorithm: {}".format(
            " " * indent, signer.encryption_algorithm
        )
    )
    print(
        "{}   Encrypted Digest    : {} ...".format(
            " " * indent, signer.encrypted_digest.hex()[:20]
        )
    )

    if len(signer.authenticated_attributes) > 0:
        print("{}   Authenticated attributes:".format(" " * indent))
        for auth in signer.authenticated_attributes:
            print_attr(indent + 4, auth)

    if len(signer.unauthenticated_attributes) > 0:
        print("{}   Un-Authenticated attributes:".format(" " * indent))
        for auth in signer.unauthenticated_attributes:
            print_attr(indent + 4, auth)


def print_all(sig: lief.PE.Signature, indent: int = 2):
    ci: lief.PE.ContentInfo = sig.content_info
    print("Authentihash: {}".format(sig.content_info.digest.hex()))
    print("{}Signature version : {}".format(" " * indent, sig.version))
    print(
        "{}Digest Algorithm  : {!s}".format(" " * indent, sig.digest_algorithm)
    )
    print("{}Content Info:".format(" " * indent))
    print(
        "{}  Content Type    : {!s} ({})".format(
            " " * indent,
            ci.content_type,
            lief.PE.oid_to_string(ci.content_type),
        )
    )
    print(
        "{}  Digest Algorithm: {!s}".format(" " * indent, ci.digest_algorithm)
    )
    print("{}  Digest          : {!s}".format(" " * indent, ci.digest.hex()))
    print("{}Certificates".format(" " * indent))
    for crt in sig.certificates:
        print_crt(indent, crt)

    print("{}Signer(s)".format(" " * indent))
    for signer in sig.signers:
        print(
            "{}  Version             : {:d}".format(
                " " * indent, signer.version
            )
        )
        print(
            "{}  Serial Number       : {}".format(
                " " * indent, signer.serial_number.hex()
            )
        )
        print(
            "{}  Issuer              : {}".format(" " * indent, signer.issuer)
        )
        print(
            "{}  Digest Algorithm    : {}".format(
                " " * indent, signer.digest_algorithm
            )
        )
        print(
            "{}  Encryption Algorithm: {}".format(
                " " * indent, signer.encryption_algorithm
            )
        )
        print(
            "{}  Encrypted Digest    : {} ...".format(
                " " * indent, signer.encrypted_digest.hex()[:20]
            )
        )
        if len(signer.authenticated_attributes) > 0:
            print("{}  Authenticated attributes:".format(" " * indent))
            for auth in signer.authenticated_attributes:
                print_attr(indent + 4, auth)

        if len(signer.unauthenticated_attributes) > 0:
            print("{}  Un-authenticated attributes:".format(" " * indent))
            for auth in signer.unauthenticated_attributes:
                print_attr(indent + 4, auth)


if __name__ == "__main__":
    file = sys.argv[1]
    if lief.PE.is_pe(file):
        binary = None
        try:
            binary: lief.PE.Binary = lief.PE.parse(file)
            if binary is None:
                print("Error while parsing {}".format(file))
                sys.exit(1)

        except lief.exception as e:
            print(e)
            sys.exit(1)

        # flags = lief.PE.Signature.VERIFICATION_CHECKS.DEFAULT
        flags = lief.PE.Signature.VERIFICATION_CHECKS.SKIP_CERT_TIME
        if (
            res := binary.verify_signature(flags)
        ) == lief.PE.Signature.VERIFICATION_FLAGS.NO_SIGNATURE:
            sys.exit(0)

        print(
            "Binary MD5     authentihash: {}".format(
                binary.authentihash_md5.hex()
            )
        )
        print(
            "Binary SHA-1   authentihash: {}".format(
                binary.authentihash_sha1.hex()
            )
        )
        print(
            "Binary SHA-256 authentihash: {}".format(
                binary.authentihash_sha256.hex()
            )
        )
        for sig in binary.signatures:
            print_all(sig)

    sys.exit(0)
