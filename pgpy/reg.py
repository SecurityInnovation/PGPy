""" reg.py

regex helpers
"""
from enum import Enum

class Magic(Enum):
    Signature = r'^-----BEGIN PGP SIGNATURE-----'
    PubKey = r'^-----BEGIN PGP PUBLIC KEY BLOCK-----'
    PrivKey = r'^-----BEGIN PGP PRIVATE KEY BLOCK-----'

    def __str__(self):
        if self == Magic.Signature:
            return "SIGNATURE"

        if self == Magic.PubKey:
            return "PUBLIC KEY BLOCK"

        if self == Magic.PrivKey:
            return "PRIVATE KEY BLOCK"

        return ""

ASCII_BLOCK = \
    r'^-----BEGIN PGP ([A-Z ]*)-----$\n'\
    r'(.*)\n\n'\
    r'(.*)'\
    r'^(=.{4})\n'\
    r'^-----END PGP \1-----$\n'
