import pytest
import requests
from pgpy.fileloader import FileLoader

import os.path

try:
    e = FileNotFoundError
except NameError:
    e = IOError

skipurls = False
try:
    test_request = requests.get("https://www.google.com/robots.txt")
except ConnectionError:
    skipurls = True

@pytest.fixture(
    params=[
        None,
        pytest.mark.skipif(skipurls, "http://www.dancewithgrenades.com/robots.txt", reason="No Internet"),
        pytest.mark.skipif(skipurls, "https://www.google.com/robots.txt", reason="No Internet"),
        "tests/testdata/unsigned_message",
        "tests/testdata/sym_to_unsigned_message",
        open("tests/testdata/unsigned_message", 'rb'),
        open("tests/testdata/unsigned_message", 'rb').read(),
        open("tests/testdata/Release.gpg", 'rb').read(),
        open("tests/testdata/testkeys.gpg", 'rb').read(),
    ],
    ids=[
        "None",
        "http",
        "https",
        "path",
        "symlink",
        "fileobj",
        "unsigned-text-bytes",
        "gpg-signature-bytes",
        "gpg-keyring-bytes",
    ]
)
def load(request):
    return request.param


class TestFileLoader:
    def test_load(self, load):
        loaded = FileLoader(load)

    # def test_load_none(self):
    #     loaded = FileLoader(None)
    #
    #     assert loaded.bytes == b''
    #     assert loaded.path is None
    #
    # def test_load_url(self, load_url):
    #     assert load_url.bytes != b''
    #     assert load_url.path is None
    #
    # def test_load_local(self, load_local):
    #     assert load_local.bytes != b''
    #     assert load_local.path is not None
    #     assert len(load_local.bytes) == os.path.getsize(load_local.path)
    #
    # def test_load_newfile(self):
    #     newfile_path = os.path.realpath(os.path.dirname(".")) + "/newfile"
    #     loaded = FileLoader(newfile_path)
    #
    #     assert loaded.bytes == b''
    #     assert loaded.path is not None
    #     assert loaded.path == newfile_path
    #
    # def test_load_invalid_path(self):
    #     with pytest.raises(e):
    #         FileLoader("/this/path/does/not/exist")
    #
    # def test_load_bytes(self, load_bytes):
    #     loaded = FileLoader(load_bytes)
    #
    #     assert loaded.bytes != b''
    #     assert loaded.path is None
    #     assert len(loaded.bytes) == len(load_bytes)
    #     assert loaded.bytes == load_bytes