""" test the functionality of PGPKeyring
"""
from pgpy.pgp import PGPKeyring


class TestPGPKeyring(object):
    def test_temp_instantiate(self):
        k = PGPKeyring()
