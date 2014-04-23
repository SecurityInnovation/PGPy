import pytest
from pgpy.signature import PGPSignature

test_files = [
    "tests/testdata/Release.gpg",
    "http://us.archive.ubuntu.com/ubuntu/dists/precise/Release.gpg",
    "http://http.debian.net/debian/dists/sid/Release.gpg"
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
    import requests

    path = test_files[test_ids.index(request.node._genid)]

    if "://" in path:
        raw = requests.get(path).content
    else:
        with open(path, 'rb') as r:
            raw = r.read()

    return list(pgpdump.AsciiData(raw).packets())[0]


class TestPGPSignature:
    def test_parse(self, pgpsig, pgpd):
        # packet header
        #  packet tag
        assert pgpsig.fields.header.tag.always_1 == 1
        assert (pgpsig.fields.header.tag.format == 1) == pgpd.new
        assert pgpsig.fields.header.tag.tag == 2
        # packet header
        assert pgpsig.fields.header.length == pgpd.length
        # packet body
        assert pgpsig.fields.version == pgpd.sig_version
        assert pgpsig.fields.type == pgpd.raw_sig_type
        assert pgpsig.fields.key_algorithm == pgpd.raw_pub_algorithm
        assert pgpsig.fields.hash_algorithm == pgpd.raw_hash_algorithm
        # hashed subpackets
        #  creation time
        assert pgpsig.fields.hashed_subpackets["packets"]["CreationTime"].payload == pgpd.creation_time
        # unhashed subpackets
        #  key id
        assert pgpsig.fields.unhashed_subpackets["packets"]["Issuer"].payload == pgpd.key_id
        # left 16 of hash
        assert pgpsig.fields.hash2 == pgpd.hash2


    def test_crc24(self, pgpsig):
        assert pgpsig.crc == pgpsig.crc24()

    def test_print(self, pgpsig, capsys):
        print(pgpsig)
        out, _ = capsys.readouterr()

        assert out == pgpsig.bytes.decode() + '\n'