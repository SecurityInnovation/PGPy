import pytest
import requests
from pgpy.signature import PGPSignature


test_files = [
    open("tests/testdata/Release.gpg", 'rb').read(),
    requests.get("http://us.archive.ubuntu.com/ubuntu/dists/precise/Release.gpg").content,
    requests.get("http://http.debian.net/debian/dists/sid/Release.gpg").content
]
test_ids = [
    "local", "ubuntu-precise", "debian-sid"
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
        # packet header
        #  packet tag
        assert pgpsig.fields.header.always_1 == 1
        assert (pgpsig.fields.header.format == 1) == pgpd.new
        assert pgpsig.fields.header.tag == 2
        # packet header
        assert pgpsig.fields.header.length == pgpd.length
        # packet body
        assert pgpsig.fields.version == pgpd.sig_version
        assert pgpsig.fields.type == pgpd.raw_sig_type
        assert pgpsig.fields.key_algorithm == pgpd.raw_pub_algorithm
        assert pgpsig.fields.hash_algorithm == pgpd.raw_hash_algorithm
        # hashed subpackets
        #  creation time
        assert pgpsig.fields.hashed_subpackets.CreationTime.payload == pgpd.creation_time
        # unhashed subpackets
        #  key id
        assert pgpsig.fields.unhashed_subpackets.Issuer.payload == pgpd.key_id
        # left 16 of hash
        assert pgpsig.fields.hash2 == pgpd.hash2


    def test_crc24(self, pgpsig):
        assert pgpsig.crc == pgpsig.crc24()

    def test_print(self, pgpsig, capsys):
        print(pgpsig)
        out, _ = capsys.readouterr()

        assert out == pgpsig.bytes.decode() + '\n'

    def test_bytes(self, pgpsig):
        # python 2.7
        if bytes is str:
            assert pgpsig.__bytes__() == pgpsig.signature_packet

        # python 3
        else:
            assert bytes(pgpsig) == pgpsig.signature_packet