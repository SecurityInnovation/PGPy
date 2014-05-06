import pytest

from tests.conftest import TestFiles

from pgpy.pgp import PGPLoad, PGPSignature
from pgpy.pgpdump import PGPDumpFormat

tf = TestFiles()


@pytest.fixture(params=tf.sigs, ids=tf.sigids)
def pgpsig(request):
    return request.param


class TestPGPSignature:
    def test_parse(self, pgpsig, pgpdump):
        p = PGPLoad(pgpsig)
        sig = p[0]

        assert len(p) == 1
        assert type(sig) is PGPSignature
        assert '\n'.join(PGPDumpFormat(sig).out) + '\n' == pgpdump.decode()

    def test_crc24(self, pgpsig):
        sig = PGPLoad(pgpsig)[0]

        assert sig.crc == sig.crc24()

    def test_str(self, pgpsig):
        sig = PGPLoad(pgpsig)[0]

        assert str(sig) == sig.bytes.decode()

    def test_bytes(self, pgpsig):
        sig = PGPLoad(pgpsig)[0]

        assert sig.__bytes__() == sig.data