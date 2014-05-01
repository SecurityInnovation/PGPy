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