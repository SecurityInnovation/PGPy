""" util.py

utility functions for PGPY
"""
import itertools
import os
import re


def is_ascii(text):
    if not isinstance(text, (str, bytes, bytearray)):
        raise ValueError("Expected: ASCII input of type str, bytes, or bytearray")

    if isinstance(text, str):
        #                      matches all printable ASCII characters
        return bool(re.match(r'^[ -~\n]+$', text, flags=re.ASCII))

    try:
        text.decode('latin-1')

    except UnicodeDecodeError:
        return False

    else:
        return True


def is_path(ppath):
    if type(ppath) is not str:
        return False

    win_badchars = ['<', '>', ':', '"', '/', '\\', '|', '?', '*']
    badchars = itertools.chain(range(0, 32), range(127, 256), win_badchars if os.name == 'nt' else [])

    checkchars = re.match('\A[^' + ''.join([ chr(c) for c in badchars ]) + ']+\Z', ppath, flags=re.ASCII)

    if checkchars is not None:
        return True

    return False

##TODO: asn1_seqint_to_tuple needs to move
bytes_to_int = lambda x: int.from_bytes(x, 'big')
int_to_bytes = lambda x, y=1: x.to_bytes(y, 'big')

def asn1_seqint_to_tuple(asn1block):
    # very limited asn1 decoder - only intended to decode a DER encoded sequence of integers
    # returned as a tuple
    if not bytes_to_int(asn1block[:1]) == 0x30:
        raise NotImplementedError("Only decodes ASN.1 Sequences")  # pragma: no cover

    if bytes_to_int(asn1block[1:2]) & 0x80:
        llen = bytes_to_int(asn1block[1:2]) & 0x7F
        end = bytes_to_int(asn1block[2:(2 + llen)])
        pos = 2 + llen

    else:
        end = bytes_to_int(asn1block[1:2]) & 0x7F
        pos = 2

    t = tuple()
    # parse fields
    while pos < end:
        if asn1block[pos:(pos + 1)] != b'\x02':
            raise NotImplementedError("Only decodes INTEGER fields")  # pragma: no cover
        pos += 1

        if bytes_to_int(asn1block[pos:(pos + 1)]) & 0x80:
            fllen = bytes_to_int(asn1block[pos:(pos + 1)]) & 0x7F
            flen = bytes_to_int(asn1block[pos:(pos + fllen)])
            pos += fllen

        else:
            flen = bytes_to_int(asn1block[pos:(pos + 1)]) & 0x7F
            pos += 1

        t += (bytes_to_int(asn1block[pos:(pos + flen)]),)
        pos += flen

    return t


# borrowed from the development version of cryptography
# https://github.com/pyca/cryptography/blob/master/cryptography/hazmat/primitives/asymmetric/rsa.py
def modinv(e, m):
    """
    Modular Multiplicative Inverse. Returns x such that: (x * e) % m == 1
    """
    x1, y1, x2, y2 = 1, 0, 0, 1
    a, b = e, m
    while b > 0:
        q, r = divmod(a, b)
        xn, yn = x1 - q * x2, y1 - q * y2
        a, b, x1, y1, x2, y2 = b, r, x2, y2, xn, yn
    return x1 % m
