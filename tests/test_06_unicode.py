""" test doing things with unicode
"""
from contextlib import contextmanager
from warnings import catch_warnings

import pytest

import six

from pgpy import PGPMessage


@pytest.fixture(scope='module')
def unicode_string():
    """
    String with a special character.  Note it is not specified as
    u'...' because doing so breaks the py2 case as well.

    I have also tried the following:

        string = b'Hello \U0001F4A9!'.decode('utf-8')
        string = r'''Hello \U0001F4A9!'''
        string = b'Hello \xf0\x9f\x92\xa9!'.decode('utf-8')

    or

        from __future__ import unicode_literals
        string = 'Hello \U0001F4A9!'

    None result in green tests across both py2 and py3.

    String courtesy of https://bit.ly/1VFLiJP
    """
    return "Hello \U0001F4A9!"


@pytest.fixture(scope='module')
def binary_string():
    """ unicode_string() in bytes form. """
    string = unicode_string()
    if six.PY3:
        return bytes(unicode_string(), encoding="utf-8")
    return string


@pytest.fixture(scope='module')
def bytearray_string():
    """ binary_string() in bytearray form. """
    return bytearray(binary_string())


@pytest.fixture(scope='module')
def unicode_message():
    """ PGPMessage generated with unicode_string() """
    return PGPMessage.new(unicode_string())


@pytest.fixture(scope='module')
def unicode_message_bytearray():
    """ unicode_message().message in bytearray form """
    msg = unicode_message().message
    if isinstance(msg, six.text_type):
        return bytearray(msg, encoding="utf-8")
    return bytearray(msg)


@pytest.fixture(scope='module')
def unicode_text_to_bytes():
    """ unicode_string() passed through PGPObject.text_to_bytes() """
    return PGPMessage.text_to_bytes(unicode_string())


@pytest.fixture(scope='module')
def bytearray_message():
    """ PGPMessage generated with bytearray_string() """
    return PGPMessage.new(bytearray_string())


@pytest.fixture(scope='module')
def bytearray_message_bytearray():
    """ bytearray_message().message in bytearray form """
    msg = bytearray_message().message
    if isinstance(msg, six.text_type):
        return bytearray(msg, encoding="utf-8")
    return bytearray(msg)


@pytest.fixture(scope='module')
def bytearray_text_to_bytes():
    """ bytearray_string() passed through PGPObject.text_to_bytes() """
    return PGPMessage.text_to_bytes(bytearray_string())


class TestUnicode(object):
    """ Test unicode special character support.  Currently only supports
    PGPMessage.new() and PGPMessage.text_to_bytes()
    """

    @contextmanager
    def assert_warnings(self):
        with catch_warnings(record=True) as warns:
            try:
                yield

            finally:
                for warning in warns:
                    try:
                        assert warning.filename == __file__

                    except AssertionError as exc:
                        exc.args += (warning.message,)
                        raise

    def test_unicode_message_message(self, binary_string, unicode_message):
        assert binary_string == unicode_message.message

    def test_unicode_bytearrays(self, bytearray_string, unicode_message_bytearray):
        assert list(bytearray_string) == list(unicode_message_bytearray)

    def test_unicode_text_to_bytes(self, binary_string, unicode_text_to_bytes):
        assert binary_string == unicode_text_to_bytes

    def test_unicode_decode(self, unicode_string, unicode_message_bytearray):
        assert unicode_string == unicode_message_bytearray.decode('utf-8')

    def test_bytearray_message_message(self, binary_string, bytearray_message):
        assert binary_string == bytearray_message.message

    def test_bytearray_bytearrays(self, bytearray_string, bytearray_message_bytearray):
        assert list(bytearray_string) == list(bytearray_message_bytearray)

    def test_bytearray_text_to_bytes(self, binary_string, bytearray_text_to_bytes):
        assert binary_string == bytearray_text_to_bytes

    def test_bytearray_decode(self, unicode_string, bytearray_message_bytearray):
        assert unicode_string == bytearray_message_bytearray.decode('utf-8')
