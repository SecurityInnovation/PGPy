import os

import pytest

from pgpy.pgp import pgpload, PGPSignature
from pgpy.pgpdump import PGPDumpFormat

from conftest import TestFiles
from conftest import openssl_ver


def pytest_generate_tests(metafunc):
    ids = TestFiles.ids(TestFiles.signatures)

    if 'sigpath' in metafunc.fixturenames:
        args = "pgpsig, sigpath"
        argvals = [(pgpload('tests/testdata/' + sig), sig) for sig in TestFiles.signatures]

    else:
        args = "pgpsig"
        argvals = [pgpload('tests/testdata/' + sig) for sig in TestFiles.signatures]

    metafunc.parametrize(args, argvals, ids=ids, scope="module")


class TestPGPSignature:
    def test_parse(self, pgpsig, sigpath, pgpdump):
        assert type(pgpsig) is list
        assert len(pgpsig) == 1

        sig = pgpsig[0]

        assert type(sig) is PGPSignature
        assert sig.path is not None
        assert sig.path == os.path.abspath('tests/testdata/' + sigpath)
        assert '\n'.join(PGPDumpFormat(sig).out) + '\n' == pgpdump(sigpath).decode()

    def test_crc24(self, pgpsig):
        sig = pgpsig[0]

        assert sig.crc == sig.crc24()

    def test_str(self, pgpsig):
        sig = pgpsig[0]

        assert str(sig) == sig.bytes.decode()

    def test_bytes(self, pgpsig):
        sig = pgpsig[0]

        assert sig.__bytes__() == sig.data