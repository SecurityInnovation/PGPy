import os

import pytest

from pgpy.pgp import PGPSignature
from pgpy.pgpdump import PGPDumpFormat

from conftest import TestFiles


def pytest_generate_tests(metafunc):
    ids = TestFiles.ids(TestFiles.signatures)

    if 'sigpath' in metafunc.fixturenames:
        args = "pgpsig, sigpath"
        argvals = [(PGPSignature.load('tests/testdata/' + sig), sig) for sig in TestFiles.signatures]
        # argvals = [(pgpload('tests/testdata/' + sig), sig) for sig in TestFiles.signatures]

    else:
        args = "pgpsig"
        argvals = [(PGPSignature.load('tests/testdata/' + sig), sig) for sig in TestFiles.signatures]
        # argvals = [pgpload('tests/testdata/' + sig) for sig in TestFiles.signatures]

    metafunc.parametrize(args, argvals, ids=ids, scope="module")


class TestPGPSignature:
    def test_parse(self, pgpsig, sigpath, pgpdump):
        assert type(pgpsig) is PGPSignature
        assert pgpsig.path
        assert pgpsig.path == os.path.abspath('tests/testdata/' + sigpath)
        # assert '\n'.join(PGPDumpFormat(pgpsig).out) + '\n' == pgpdump(sigpath)

    def test_str(self, pgpsig, sigpath):
        with open('tests/testdata/' + sigpath, 'r') as sigf:
            assert str(pgpsig) == sigf.read()
