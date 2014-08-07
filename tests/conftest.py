import pytest

import functools
import keyword
import os
import re
import subprocess
import sys

from itertools import product

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

# utils and data for fixtures
_gpg_args = ['/usr/bin/gpg',
             '--no-default-keyring',
             '--keyring', './testkeys.gpg',
             '--secret-keyring', './testkeys.sec.gpg',
             '--trustdb-name', './testkeys.trust']

class CWD_As(object):
    def __init__(self, newwd):
        if not os.path.exists(newwd):
            raise FileNotFoundError(newwd + " not found within " + os.getcwd())

        self.oldwd = os.getcwd()
        self.newwd = newwd

    def __call__(self, func):
        @functools.wraps(func)
        def setcwd(*args, **kwargs):
            # set new working directory
            os.chdir(self.newwd)

            # fallback value
            fo = None

            try:
                fo = func(*args, **kwargs)

            finally:
                # always return to self.oldwd even if there was a failure
                os.chdir(self.oldwd)

            return fo

        return setcwd

# fixtures
@pytest.fixture()
def gpg_verify():
     @CWD_As('tests/testdata')
     def _gpg_verify(gpg_subjpath, gpg_sigpath=None):
         gpg_args = _gpg_args + ['-vv', '--verify']

         if gpg_sigpath is not None:
             gpg_args += [gpg_sigpath]
         gpg_args += [gpg_subjpath]

         try:
             return subprocess.check_output(gpg_args, stderr=subprocess.STDOUT).decode()

         except subprocess.CalledProcessError as e:
             return "/usr/bin/gpg returned {ret}\n"\
                    "===========================\n"\
                    "{out}".format(ret=e.returncode, out=e.output.decode())
     return _gpg_verify

# pytest hooks
# called after command line options have been parsed and all plugins and initial conftest files been loaded.
def pytest_configure(config):
    assert os.path.basename(os.getcwd()) == 'PGPy'

    # display the working directory and the OpenSSL version
    print("Working Directory: " + os.getcwd())
    print("Using OpenSSL " + str(openssl_ver))
    print("")


def pytest_generate_tests(metafunc):
    if not keyword.iskeyword('nonlocal'):
        _outer = locals()

    spdir = 'subpackets/'
    pdir = 'packets/'

    params = []
    argvals = []
    ids = []

    tdata = []

    def pheader():
        if keyword.iskeyword('nonlocal'):
            nonlocal params
            nonlocal argvals
            nonlocal ids

        else:
            params = _outer['params']
            argvals = _outer['argvals']
            ids = _outer['ids']

        params += ['pheader']
        argvals += [[
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
        ]]

        ids = ['new_1_191', 'new_2_192', 'new_2_8383', 'new_5_8384',
               'old_1_255', 'old_2_256', 'old_4_65536']

    def spheader():
        if keyword.iskeyword('nonlocal'):
            nonlocal params
            nonlocal argvals
            nonlocal ids

        else:
            params = _outer['params']
            argvals = _outer['argvals']
            ids = _outer['ids']

        params += ['spheader']
        argvals += [[
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
        ]]

        ids += ['1_191', '2_192', '2_8383', '5_8384', '5_65535']

    def sis2k():
        if keyword.iskeyword('nonlocal'):
            nonlocal params
            nonlocal argvals
            nonlocal ids

        else:
            params = _outer['params']
            argvals = _outer['argvals']
            ids = _outer['ids']

        params += ['sis2k']
        argvals += [[ (bytearray(i) +
                      b'\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF') # iv
                      for i in product(b'\xff',                                         # usage
                                       b'\x01\x02\x03\x04\x07\x08\x09\x0B\x0C\x0D',     # symmetric cipher algorithm
                                       b'\x00',                                         # specifier (simple)
                                       b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B') # hash algorithm
                    ]]
        ids = ['sis2k_' + str(i) for i in range(len(argvals[-1]))]

    def sas2k():
        if keyword.iskeyword('nonlocal'):
            nonlocal params
            nonlocal argvals
            nonlocal ids

        else:
            params = _outer['params']
            argvals = _outer['argvals']
            ids = _outer['ids']

        params += ['sas2k']
        argvals += [[ (bytearray(i) +
                      b'\xCA\xFE\xBA\xBE\xCA\xFE\xBA\xBE' + # salt
                      b'\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF')  # iv
                      for i in product(b'\xff',                                         # usage
                                       b'\x01\x02\x03\x04\x07\x08\x09\x0B\x0C\x0D',     # symmetric cipher algorithm
                                       b'\x01',                                         # specifier (simple)
                                       b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B') # hash algorithm
                    ]]
        ids = ['sis2k_' + str(i) for i in range(len(argvals[-1]))]

    def is2k():
        if keyword.iskeyword('nonlocal'):
            nonlocal params
            nonlocal argvals
            nonlocal ids

        else:
            params = _outer['params']
            argvals = _outer['argvals']
            ids = _outer['ids']

        params += ['is2k']
        argvals += [[ (bytearray(i) +
                       b'\xCA\xFE\xBA\xBE\xCA\xFE\xBA\xBE' + # salt
                       b'\x10' +                             # count
                       b'\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF')  # iv
                      for i in product(b'\xff',                                         # usage
                                       b'\x01\x02\x03\x04\x07\x08\x09\x0B\x0C\x0D',     # symmetric cipher algorithm
                                       b'\x03',                                         # specifier (simple)
                                       b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B') # hash algorithm
                    ]]
        ids = ['is2k_' + str(i) for i in range(len(argvals[-1]))]

    @CWD_As('tests/testdata')
    def sigsubpacket():
        if keyword.iskeyword('nonlocal'):
            nonlocal params
            nonlocal tdata
            nonlocal spdir

        else:
            params = _outer['params']
            tdata = _outer['tdata']

        params += ['sigsubpacket']
        tdata += [sorted([ spdir + f for f in os.listdir(spdir) if f.startswith('signature') ])]

    @CWD_As('tests/testdata')
    def uasubpacket():
        if keyword.iskeyword('nonlocal'):
            nonlocal params
            nonlocal tdata
            nonlocal spdir

        else:
            params = _outer['params']
            tdata = _outer['tdata']

        params += ['uasubpacket']
        tdata += [sorted([ spdir + f for f in os.listdir(spdir) if f.startswith('userattr') ])]

    @CWD_As('tests/testdata')
    def packet():
        if keyword.iskeyword('nonlocal'):
            nonlocal params
            nonlocal tdata
            nonlocal pdir

        else:
            params = _outer['params']
            tdata = _outer['tdata']

        params += ['packet']
        tdata += [sorted([ pdir + f for f in os.listdir(pdir) ])]

    @CWD_As('tests/testdata')
    def ekpacket():
        if keyword.iskeyword('nonlocal'):
            nonlocal params
            nonlocal tdata
            nonlocal pdir

        else:
            params = _outer['params']
            tdata = _outer['tdata']

        params += ['ekpacket']
        tdata += [sorted([ pdir + f for f in os.listdir(pdir) if f.startswith('privkey.enc') ])]

    @CWD_As('tests/testdata')
    def ukpacket():
        if keyword.iskeyword('nonlocal'):
            nonlocal params
            nonlocal tdata
            nonlocal pdir

        else:
            params = _outer['params']
            tdata = _outer['tdata']

        params += ['ukpacket']
        tdata += [sorted([ pdir + f for f in os.listdir(pdir) if f.startswith('privkey.unc') ])]

    # run all inner functions that match fixturenames
    # I organized it like this for easy code folding in PyCharm :)
    for fn in metafunc.fixturenames:
        if fn in locals():
            locals()[fn]()

    @CWD_As('tests/testdata')
    def _loadbytearrays():
        if keyword.iskeyword('nonlocal'):
            nonlocal argvals
            nonlocal tdata
            nonlocal ids

        else:
            argvals = _outer['argvals']
            ids = _outer['ids']
            tdata = _outer['tdata']

        # quick error checking
        if len(set([len(stl) for stl in tdata])) > 1:
            raise ValueError("All sublists of tdata must be the same length! "
                             "param(s): " + ", ".join(params) +
                             "; " + ", ".join([str(len(stl)) for stl in tdata]))

        # zip sublists together
        tdata = list(zip(*tdata))

        argvals = []
        for i, fa in enumerate(tdata):
            at = []
            for a, f in enumerate(fa):
                _b = bytearray(os.path.getsize(f))
                with open(f, 'rb') as fo:
                    fo.readinto(_b)
                at.append(_b)
            argvals += [tuple(at)]

        ids = [ '_'.join(re.split('\.', f[0])[1:]) for f in tdata ]


    if tdata != []:
        _loadbytearrays()

    if params != []:
        para = ','.join(params)
        al = set(len(a) for a in argvals)

        # make sure argvals is a list of tuples if it isn't already
        if not isinstance(argvals[0], tuple):
            argvals = list(zip(*argvals))

        # if there is only one param, it should actually just be a list of arguments
        if len(params) == 1 and isinstance(argvals[0], tuple):
            argvals = [i[0] for i in argvals]

        # some error checking here with output that makes debugging easier
        if len(al) > 1:
            raise ValueError("All sublists of tdata must be the same length! param(s): " + para)

        if len(argvals) != len(ids):
            raise ValueError("length of ids not matched! param(s): {p:s}; {pl:d} vs {id:d}".format(p=para,
                                                                                                   pl=len(argvals),
                                                                                                   id=len(ids)))

        metafunc.parametrize(para, argvals, ids=ids, scope="class")
