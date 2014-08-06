import functools
import os
import re
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
# from fixtures import TestFiles, gpg_getfingerprint, pgpdump, gpg_verify, gpg_fingerprint

# fixtures
class CWD_As(object):
    def __init__(self, newwd):
        if not os.path.exists(newwd):
            raise FileNotFoundError(newwd)

        self.oldwd = os.getcwd()
        self.newwd = newwd

    def __call__(self, func):
        @functools.wraps(func)
        def setcwd(*args, **kwargs):
            os.chdir(self.newwd)
            fo = func(*args, **kwargs)
            os.chdir(self.oldwd)
            return fo
        return setcwd


# pytest hooks
# called after command line options have been parsed and all plugins and initial conftest files been loaded.
def pytest_configure(config):
    assert os.path.basename(os.getcwd()) == 'PGPy'

    # display the working directory and the OpenSSL version
    print("Working Directory: " + os.getcwd())
    print("Using OpenSSL " + str(openssl_ver))
    print("")


def pytest_generate_tests(metafunc):
    spdir = 'tests/testdata/subpackets/'
    pdir = 'tests/testdata/packets/'
    
    params = []
    argvals = []
    ids = []

    tdata = []

    if 'spheader' in metafunc.fixturenames:
        params = ['spheader']
        argvals = [
            # 1 byte length - 191
            bytearray(b'\xbf'                 + b'\x00' + (b'\x00' * 190)),
            # 2 byte length - 192
            bytearray(b'\xc0\x00'             + b'\x00' + (b'\x00' * 191)),
            # 2 byte length - 8383
            bytearray(b'\xdf\xff'             + b'\x00' + (b'\x00' * 8382)),
            # 5 byte length - 8384
            bytearray(b'\xff\x00\x00 \xc0'    + b'\x00' + (b'\x00' * 0x8383)),
            # 5 byte length - 65535
            bytearray(b'\xff\x00\x00\xff\xff' + b'\x00' + (b'\x00' * 65534)),
        ]

        ids = ['1_191', '2_192', '2_8383', '5_8384', '5_65535']

    if 'pheader' in metafunc.fixturenames:
        params = ['pheader']
        argvals = [
            # new format
            # 1 byte length - 191
            bytearray(b'\xc2' + b'\xbf' +                 (b'\x00' * 191)),
            # 2 byte length - 192
            bytearray(b'\xc2' + b'\xc0\x00' +             (b'\x00' * 192)),
            # 2 byte length - 8383
            bytearray(b'\xc2' + b'\xdf\xff' +             (b'\x00' * 8383)),
            # 5 byte length - 8384
            bytearray(b'\xc2' + b'\xff\x00\x00 \xc0' +    (b'\x00' * 8384)),
            # old format
            # 1 byte length - 255
            bytearray(b'\x88' + b'\xff' +                 (b'\x00' * 255)),
            # 2 byte length - 256
            bytearray(b'\x89' + b'\x01\x00' +             (b'\x00' * 256)),
            # 4 byte length - 65536
            bytearray(b'\x8a' + b'\x00\x01\x00\x00' +     (b'\x00' * 65536)),
        ]

        ids = ['new_1_191', 'new_2_192', 'new_2_8383', 'new_5_8384',
               'old_1_255', 'old_2_256', 'old_4_65536']


    if 'sigsubpacket' in metafunc.fixturenames:
        params = ['sigsubpacket']
        tdata = sorted([ spdir + f for f in os.listdir(spdir) if f.startswith('signature') ])

    if 'uasubpacket' in metafunc.fixturenames:
        params = ['uasubpacket']
        tdata = sorted([ spdir + f for f in os.listdir(spdir) if f.startswith('userattr') ])

    if 'packet' in metafunc.fixturenames:
        params = ['packet']
        tdata = sorted([ pdir + f for f in os.listdir(pdir) ])

    if 'ekpacket' in metafunc.fixturenames:
        params = ['ekpacket']
        tdata = sorted([ pdir + f for f in os.listdir(pdir) if 'enc' in f ])

    if tdata != []:
        argvals = [bytearray(os.path.getsize(sp)) for sp in tdata]

        for i, spf in enumerate(tdata):
            with open(spf, 'rb') as sp:
                sp.readinto(argvals[i])

        ids = [ '_'.join(re.split('\.', f)[1:]) for f in tdata ]

    if params != []:
        metafunc.parametrize(','.join(params), argvals, ids=ids, scope="class")