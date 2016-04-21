# coding=utf-8
""" test types
"""
import pytest

import glob

from pgpy.types import Armorable, PGPObject


# read txt files in tests/testdata/text/*.txt and yield ids and strings
# TODO: figure out how to set ids
# @pytest.yield_fixture
def get_text():
    for tf in sorted(glob.glob('tests/testdata/text/*.txt')):
        with open(tf, 'r') as f:
            for line in f:
                # skip comments and blank lines
                if line.startswith('#') or line == "":
                    continue
                yield line.split(': ')

text = {
    # some basic utf-8 test strings - these should all pass
    'english': u'The quick brown fox jumped over the lazy dog',
    # this hiragana pangram comes from http://www.columbia.edu/~fdc/utf8/
    'hiragana': u'いろはにほへど　ちりぬるを\n'
                u'わがよたれぞ　つねならむ\n'
                u'うゐのおくやま　けふこえて\n'
                u'あさきゆめみじ　ゑひもせず',

    'poo': u'Hello, \U0001F4A9!',
}

# some alternate encodings to try
# these should fail
encoded_text = {
    # try some alternate encodings as well
    #          'crunch the granite of science'
    'cyrillic': u'грызть гранит науки'.encode('iso8859_5'),
    #          'My hovercraft is full of eels'
    'cp865': u'Mit luftpudefartøj er fyldt med ål'.encode('cp865'),
}


# test harness for pgpy.types.PGPObject, since it defines a couple of abstract methods
class FakePGPObject(PGPObject):
    @classmethod
    def new(cls, text):
        obj = FakePGPObject()
        obj.data = cls.text_to_bytes(text)
        return obj

    def __init__(self):
        self.data = bytearray()

    def __bytearray__(self):
        return bytearray(b'_fake_') + self.data

    def parse(self, packet):
        self.data = packet


class TestPGPObject(object):
    params = {
        'text': [ v for _, v in sorted(text.items()) ],
        'encoded_text': [ v for _, v in sorted(encoded_text.items()) ],
    }
    ids = {
        'test_text_to_bytes': [ k for k, _ in sorted(text.items()) ],
        'test_text_to_bytes_encodings': [ k for k, _ in sorted(encoded_text.items()) ],
    }
    def test_text_to_bytes(self, text):
        pgpo = FakePGPObject.new(text)

        assert pgpo.__bytearray__() == bytearray(b'_fake_') + bytearray(text, 'utf-8')

    def test_text_to_bytes_encodings(self, encoded_text):
        pgpo = FakePGPObject.new(encoded_text)
        # this should fail
        with pytest.raises(UnicodeDecodeError):
            pgpo.data.decode('utf-8')

    def test_text_to_bytes_none(self):
        assert PGPObject.text_to_bytes(None) is None

    def test_bytes_to_text_none(self):
        assert PGPObject.bytes_to_text(None) is None

    def test_bytes_to_text_text(self):
        assert PGPObject.bytes_to_text('asdf') == 'asdf'
