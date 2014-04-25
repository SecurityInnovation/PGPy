""" signature.py

PGP Signature parsing
"""
from .reg import Magic
from .pgp import PGPBlock


class PGPSignature(PGPBlock):
    def __init__(self, sigf):
        super(PGPSignature, self).__init__(sigf, Magic.Signature)
        ##TODO: handle creating a new signature
