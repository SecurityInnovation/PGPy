import pytest
from pgpy.signature import PGPSignature
from pgpy.packet.pgpdump import PGPDumpFormat

test_files = [
    "tests/testdata/Release.gpg",
    "tests/testdata/Ubuntu.Precise.Release.gpg",
    "tests/testdata/Debian.Sid.Release.gpg",
    "tests/testdata/signed_message.asc",
    "tests/testdata/inline_signed_message"
]
test_ids = [
    "local",
    "ubuntu-precise",
    "debian-sid",
    "message-signed",
    "inline-signed",
]

@pytest.fixture(params=test_files, ids=test_ids)
def pgpsig(request):
    return request.param


class TestPGPSignature:
    def test_parse(self, pgpsig, pgpdump):
        sig = PGPSignature(pgpsig)
        assert '\n'.join(PGPDumpFormat(sig).out) + '\n' == pgpdump.decode()


    def test_crc24(self, pgpsig):
        sig = PGPSignature(pgpsig)
        assert sig.crc == sig.crc24()

    def test_print(self, pgpsig, capsys):
        sig = PGPSignature(pgpsig)

        print(sig)
        out, _ = capsys.readouterr()
        assert out == sig.bytes.decode() + '\n'

    def test_bytes(self, pgpsig):
        sig = PGPSignature(pgpsig)
        sigpkt = sig.packets[0]

        assert sigpkt.__bytes__() == sig.data