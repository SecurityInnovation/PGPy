""" util.py

utility functions for debutils.pgp
"""

def bytes_to_int(b):
    n = 0
    for octet in bytearray(b):
        n += octet
        n <<= 8
    n >>= 8

    return n

def int_to_bytes(i):
    b = []
    while i > 0:
        b.insert(0, i & 0xFF)
        i >>= 8

    return bytes(b) if len(bytes(b)) == len(b) else ''.join([ chr(c) for c in b ])