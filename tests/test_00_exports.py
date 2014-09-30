""" check the export list to ensure only the public API is exported by pgpy.__init__
"""
import inspect

import pgpy


def test_exports():
    _ignore = {'__all__', '__builtins__', '__cached__', '__doc__', '__file__', '__loader__', '__name__', '__package__',
               '__path__', '__spec__'}
    members = { n for n, _ in inspect.getmembers(pgpy) if n not in _ignore }
    errors = { n for n, _ in inspect.getmembers(pgpy.errors) if n not in _ignore  }
    constants = { n for n, _ in inspect.getmembers(pgpy.constants) if n not in _ignore  }

    expected_members = {'PGPKey', 'PGPSignature', 'PGPUID', 'PGPMessage', 'PGPKeyring', 'constants', 'errors'}
    expected_errors = {'PGPError', 'PGPDecryptionError', 'PGPOpenSSLCipherNotSupported', 'WontImplementError'}
    expected_constants = {'CompressionAlgorithm', 'Features', 'HashAlgorithm', 'ImageEncoding', 'KeyFlags',
                          'KeyServerPreferences', 'NotationDataFlags', 'PubKeyAlgorithm', 'RevocationKeyClass',
                          'RevocationReason', 'SignatureType', 'SymmetricKeyAlgorithm', 'TrustFlags', 'TrustLevel'}

    assert expected_members <= members
    assert expected_errors <= errors
    assert expected_constants <= constants
