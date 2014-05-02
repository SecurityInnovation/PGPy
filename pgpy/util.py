""" util.py

utility functions for debutils.pgp
"""
import binascii
import math


def bytes_to_int(b):
    return int(binascii.hexlify(b), 16)


def int_to_bytes(i, minlen=1):
    plen = max(int(math.ceil(i.bit_length() / 8.0)) * 2, (minlen * 2))
    hexstr = '{0:0{1}x}'.format(i, plen).encode()
    return binascii.unhexlify(hexstr)


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