"""PGPy conftest"""
import pytest

import glob
try:
    import gpg
except ImportError:
    gpg = None
    gpg_ver = 'unknown'
else:
    # get the GnuPG version
    gpg_ver = list(filter(lambda x: x.protocol == gpg.constants.PROTOCOL_OpenPGP, gpg.core.get_engine_info()))[0].version

import os
import sys

from cryptography.hazmat.backends import openssl

openssl_ver = openssl.backend.openssl_version_text().split(' ')[1]
gnupghome = os.path.join(os.path.dirname(__file__), 'gnupghome')

# ensure external commands we need to run exist

# set the CWD and add to sys.path if we need to
os.chdir(os.path.join(os.path.abspath(os.path.dirname(__file__)), os.pardir))

if os.getcwd() not in sys.path:
    sys.path.insert(0, os.getcwd())
else:
    sys.path.insert(0, sys.path.pop(sys.path.index(os.getcwd())))

if os.path.join(os.getcwd(), 'tests') not in sys.path:
    sys.path.insert(1, os.path.join(os.getcwd(), 'tests'))


# pytest hooks

# pytest_configure
# called after command line options have been parsed and all plugins and initial conftest files been loaded.
def pytest_configure(config):
    print("== PGPy Test Suite ==")

    if gpg:
        # clear out gnupghome
        clear_globs = [os.path.join(gnupghome, 'private-keys-v1.d', '*.key'),
                       os.path.join(gnupghome, '*.kbx*'),
                       os.path.join(gnupghome, '*.gpg*'),
                       os.path.join(gnupghome, '.*'),
                       os.path.join(gnupghome, 'random_seed')]
        for fpath in iter(f for cg in clear_globs for f in glob.glob(cg)):
            os.unlink(fpath)

        # check that there are no keys loaded, now
        with gpg.Context(offline=True) as c:
            c.set_engine_info(gpg.constants.PROTOCOL_OpenPGP, home_dir=gnupghome)

            assert len(list(c.keylist())) == 0
            assert len(list(c.keylist(secret=True))) == 0

    else:
        # we're not running integration tests
        print("running without integration tests")
        # if we're on GitHub CI, this is an error
        if os.getenv('CI'):
            sys.exit(1)

    # display the working directory and the OpenSSL/GPG/pgpdump versions
    print("Working Directory: " + os.getcwd())
    print("Using OpenSSL " + str(openssl_ver))
    print("Using GnuPG   " + str(gpg_ver))
    print("")
