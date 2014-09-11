""" check the export list to ensure only the public API is exported by pgpy.__init__
"""
import inspect

import pgpy.__init__

from pgpy import constants
from pgpy import errors
from pgpy.pgp import PGPKey
from pgpy.pgp import PGPSignature
from pgpy.pgp import PGPMessage
from pgpy.pgp import PGPKeyring

def test_exports():
    members = [ m for _, m in inspect.getmembers(pgpy.__init__) ]

    assert constants in members
    assert errors in members
    assert PGPKey in members
    assert PGPSignature in members
    assert PGPMessage in members
    assert PGPKeyring in members
