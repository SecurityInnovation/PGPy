import os
import sys

from distutils.version import LooseVersion

from cryptography.hazmat.backends import openssl

openssl_ver = LooseVersion(openssl.backend.openssl_version_text().split(' ')[1])

# set the CWD to the project root if it isn't already
if 'PGPy' in os.getcwd():
    while os.path.basename(os.getcwd()) != 'PGPy':
        os.chdir('..')

else:
    raise Exception("Could not set the proper expected working directory!")

# make sure path is how we want it
if os.getcwd() not in sys.path:
    sys.path.insert(0, os.getcwd())
else:
    sys.path.insert(0, sys.path.pop(sys.path.index(os.getcwd())))

if os.path.join(os.getcwd(), 'tests') not in sys.path:
    sys.path.insert(1, os.path.join(os.getcwd(), 'tests'))

# now import stuff from fixtures so it can be imported by test modules
from fixtures import TestFiles, gpg_getfingerprint, pgpdump, gpg_verify, gpg_fingerprint

# pytest hooks
# called after command line options have been parsed and all plugins and initial conftest files been loaded.
def pytest_configure(config):
    assert os.path.basename(os.getcwd()) == 'PGPy'

    # display the working directory and the OpenSSL version
    print("Working Directory: " + os.getcwd())
    print("Using OpenSSL " + str(openssl_ver))
    print()


# and set __all__
__all__ = [openssl_ver, TestFiles, gpg_getfingerprint, pgpdump, gpg_verify, gpg_fingerprint]