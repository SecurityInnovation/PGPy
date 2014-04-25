import pytest
import requests
from pgpy.signature import PGPSignature


test_files = [
    open("tests/testdata/Release.gpg", 'rb').read(),
    requests.get("http://us.archive.ubuntu.com/ubuntu/dists/precise/Release.gpg").content,
    requests.get("http://http.debian.net/debian/dists/sid/Release.gpg").content,
    open("tests/testdata/signed_message.asc", 'rb').read(),
    open("tests/testdata/inline_signed_message", 'rb').read(),
]
test_ids = [
    "local", "ubuntu-precise", "debian-sid", "message-sig", "inline-sig",
]


@pytest.fixture(params=test_files, ids=test_ids)
def pgpsig(request):
    return PGPSignature(request.param)


@pytest.fixture()
def pgpd(request):
    import pgpdump
    param = test_files[test_ids.index(request.node._genid)]

    return list(pgpdump.AsciiData(param).packets())[0]


class TestPGPSignature:
    def test_parse(self, pgpsig, pgpd):
        sigpkt = pgpsig.packets[0]
        # packet header
        #  packet tag
        assert sigpkt.header.always_1 == 1
        assert (sigpkt.header.format == 1) == pgpd.new
        assert sigpkt.header.tag == 2
        # packet header
        assert sigpkt.header.length == pgpd.length
        # packet body
        assert sigpkt.version == pgpd.sig_version
        assert sigpkt.type == pgpd.raw_sig_type
        assert sigpkt.key_algorithm == pgpd.raw_pub_algorithm
        assert sigpkt.hash_algorithm == pgpd.raw_hash_algorithm
        # hashed subpackets
        #  creation time
        assert sigpkt.hashed_subpackets.SigCreationTime.payload == pgpd.creation_time
        # unhashed subpackets
        #  key id
        assert sigpkt.unhashed_subpackets.Issuer.payload == pgpd.key_id
        # left 16 of hash
        assert sigpkt.hash2 == pgpd.hash2


    def test_crc24(self, pgpsig):
        assert pgpsig.crc == pgpsig.crc24()

    def test_print(self, pgpsig, capsys):
        print(pgpsig)
        out, _ = capsys.readouterr()

        assert out == pgpsig.bytes.decode() + '\n'

    def test_bytes(self, pgpsig):
        sigpkt = pgpsig.packets[-1]

        assert sigpkt.__bytes__() == pgpsig.data