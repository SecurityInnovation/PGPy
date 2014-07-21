""" Tests for bug #56 - https://github.com/Commod0re/PGPy/issues/56

Methodology:
 - Once each for TestRSA-2048 and TestDSA-2048:
     - Loop 1000 times:
         - Generate a signature
         - Verify the signature with PGPy
         - Write the signature to disk
         - Verify the signature with GPG
         - Verify the signature again with PGPy
 - If the signature fails verification at any stage, write it to disk with a different filename for examination

"""

import pytest

import os
import time

from distutils.version import LooseVersion

import pgpy
from pgpy.packet.types import PubKeyAlgo

from conftest import openssl_ver
from fixtures import gpg_verify, gpg_getfingerprint


class TestIssue56(object):
    def createsigdoc(self):
        # our test document
        testdoc = "Hello!" \
                  "I'm a test document." \
                  "I'm going to get signed a bunch of times." \
                  "KBYE!"

        # write out a test document if it does not exist
        if not os.path.exists("testdoc_bug_56.txt"):
            with open("testdoc_bug_56.txt", 'w') as tdf:
                tdf.write(testdoc)
                tdf.flush()

    @pytest.fixture(scope='class')
    def keyring(self):
        kr = pgpy.PGPKeyring()
        kr.load([ "tests/testdata/{pubsec}keys/TestRSA-2048.key".format(pubsec=pubsec) for pubsec in ["pub", "sec"] ])

        return kr

    @pytest.fixture(scope='class', autouse=True,
                    params=[gpg_getfingerprint("TestRSA-2048")] * 1000,
                    ids=['rsa-{x}'.format(x=i) for i in range(0, 1000)])
    def gensig(self, request, keyring):
        self.createsigdoc()
        key = request.param

        # generate a signature and return it
        with keyring.key(key):
            sig = keyring.sign("testdoc_bug_56.txt")

        sig.path = "./sig_{id}.asc".format(id=request._parent_request.node._genid)
        sig.write()

        return sig

    def test_1_verify_memory(self, keyring, gensig):
        with keyring.key():
            try:
                assert keyring.verify("testdoc_bug_56.txt", gensig)

            except AssertionError:
                import shutil
                shutil.copyfile(gensig.path, gensig.path + "_")
                raise

    def test_2_verify_disk(self, keyring, gensig):
        with keyring.key():
            assert keyring.verify("testdoc_bug_56.txt", gensig.path)

    def test_3_verify_gpg(self, gensig, gpg_verify):
        try:
            assert 'Good signature from' in gpg_verify('../../testdoc_bug_56.txt', '../../' + gensig.path)

        except AssertionError:
            raise

        else:
            os.remove(gensig.path)

        finally:
            # try to prevent more than one signature being generated per second
            time.sleep(0.8)