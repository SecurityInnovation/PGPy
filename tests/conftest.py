import pytest

import functools
import os
import re
import subprocess
import sys

from itertools import product

from distutils.version import LooseVersion

from cryptography.hazmat.backends import openssl

openssl_ver = LooseVersion(openssl.backend.openssl_version_text().split(' ')[1])
gpg_ver = LooseVersion()

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
    def _gpg_verify(gpg_subjpath, gpg_sigpath=None, keyring='./testkeys.gpg'):
        _gpg_args = ['/usr/bin/gpg',
                     '--no-default-keyring',
                     '--keyring', keyring]
        gpg_args = _gpg_args + ['-vv', '--verify']

        if gpg_sigpath is not None:
            gpg_args += [gpg_sigpath]
        gpg_args += [gpg_subjpath]

        try:
            gpgo = subprocess.check_output(gpg_args, stderr=subprocess.STDOUT).decode()

        except subprocess.CalledProcessError as e:
            gpgo = e.output.decode()

        finally:
            return ("Good signature from" in gpgo and "BAD signature" not in gpgo)
    return _gpg_verify


@pytest.fixture
def gpg_decrypt():
    @CWD_As('tests/testdata')
    def _gpg_decrypt(gpg_encmsgpath, passphrase=None, keyring='./testkeys.gpg', secring='./testkeys.sec.gpg'):
        _gpg_args = ['/usr/bin/gpg',
                     '--no-default-keyring',
                     '--keyring', keyring,
                     '--secret-keyring', secring,
                     '--decrypt']

        _cokwargs = {'stdout': subprocess.PIPE,
                     'stderr': subprocess.PIPE}
        _comargs = ()

        if passphrase is not None:
            _gpg_args[:-1] += ['--batch',
                               '--passphrase-fd', '0',
                               '--decrypt']

            _cokwargs['stdin'] = subprocess.PIPE
            _comargs = (passphrase.encode(),)

        _gpg_args += [gpg_encmsgpath]

        try:
            gpgdec = subprocess.Popen(_gpg_args, **_cokwargs)
            gpgo, gpge = gpgdec.communicate(*_comargs)

        finally:
            pass

        return gpgo.decode() if gpgo is not None else gpge

    return _gpg_decrypt


@pytest.fixture
def gpg_print():
    @CWD_As('tests/testdata')
    def _gpg_print(infile):
        _gpg_args = ['/usr/bin/gpg', '--no-default-keyring', '-o-', infile]
        try:
            # return subprocess.check_output(_gpg_args, stderr=subprocess.STDOUT).decode()
            gpgdec = subprocess.Popen(_gpg_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            gpgo, gpge = gpgdec.communicate()

        finally:
            pass

        return gpgo.decode() if gpgo is not None else ""

    return _gpg_print


# pytest hooks

# pytest_configure
# called after command line options have been parsed and all plugins and initial conftest files been loaded.
def pytest_configure(config):
    assert os.path.basename(os.getcwd()) == 'PGPy'

    # display the working directory and the OpenSSL version
    print("Working Directory: " + os.getcwd())
    print("Using OpenSSL " + str(openssl_ver))
    print("")


# pytest_generate_tests
# called when each test method is collected to generate parametrizations
def pytest_generate_tests(metafunc):
    global argvals
    global ids
    global tdata

    params = []
    argvals = []
    ids = []
    tdata = []

    def pheader():
        # in 3.x this can be 'nonlocal' but that causes syntax errors in 2.7
        global argvals
        global ids

        argvals += [[
            # new format
            # 1 byte length - 191
            bytearray(b'\xc2' + b'\xbf' +                 (b'\x00' * 191)   + b'\xca\xfe\xba\xbe'),
            # 2 byte length - 192
            bytearray(b'\xc2' + b'\xc0\x00' +             (b'\x00' * 192)   + b'\xca\xfe\xba\xbe'),
            # 2 byte length - 8383
            bytearray(b'\xc2' + b'\xdf\xff' +             (b'\x00' * 8383)  + b'\xca\xfe\xba\xbe'),
            # 5 byte length - 8384
            bytearray(b'\xc2' + b'\xff\x00\x00 \xc0' +    (b'\x00' * 8384)  + b'\xca\xfe\xba\xbe'),
            # old format
            # 1 byte length - 255
            bytearray(b'\x88' + b'\xff' +                 (b'\x00' * 255)   + b'\xca\xfe\xba\xbe'),
            # 2 byte length - 256
            bytearray(b'\x89' + b'\x01\x00' +             (b'\x00' * 256)   + b'\xca\xfe\xba\xbe'),
            # 4 byte length - 65536
            bytearray(b'\x8a' + b'\x00\x01\x00\x00' +     (b'\x00' * 65536) + b'\xca\xfe\xba\xbe'),
        ]]

        ids += ['new_1_191', 'new_2_192', 'new_2_8383', 'new_5_8384',
               'old_1_255', 'old_2_256', 'old_4_65536']

    def spheader():
        global argvals
        global ids

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
        global argvals
        global ids

        argvals += [[ (bytearray(i) +
                      b'\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF') # iv
                      for i in product(b'\xff',                                         # usage
                                       b'\x01\x02\x03\x04\x07\x08\x09\x0B\x0C\x0D',     # symmetric cipher algorithm
                                       b'\x00',                                         # specifier (simple)
                                       b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B') # hash algorithm
                    ]]
        ids = ['sis2k_' + str(i) for i in range(len(argvals[-1]))]

    def sas2k():
        global argvals
        global ids

        argvals += [[ (bytearray(i) +
                      b'\xCA\xFE\xBA\xBE\xCA\xFE\xBA\xBE' + # salt
                      b'\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF')  # iv
                      for i in product(b'\xff',                                         # usage
                                       b'\x01\x02\x03\x04\x07\x08\x09\x0B\x0C\x0D',     # symmetric cipher algorithm
                                       b'\x01',                                         # specifier (simple)
                                       b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B') # hash algorithm
                    ]]
        ids += ['sis2k_' + str(i) for i in range(len(argvals[-1]))]

    def is2k():
        global argvals
        global ids

        argvals += [[ (bytearray(i) +
                       b'\xCA\xFE\xBA\xBE\xCA\xFE\xBA\xBE' + # salt
                       b'\x10' +                             # count
                       b'\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF')  # iv
                      for i in product(b'\xff',                                         # usage
                                       b'\x01\x02\x03\x04\x07\x08\x09\x0B\x0C\x0D',     # symmetric cipher algorithm
                                       b'\x03',                                         # specifier (simple)
                                       b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B') # hash algorithm
                    ]]
        ids += ['is2k_' + str(i) for i in range(len(argvals[-1]))]

    def comp_alg():
        global argvals
        global ids
        argvals += [[0, 1, 2, 3]]
        ids = ['Uncompressed', 'ZIP', 'ZLIB', 'BZ2']

    @CWD_As('tests/testdata/subpackets')
    def sigsubpacket():
        global tdata
        tdata += [sorted([ os.path.abspath(f) for f in os.listdir('.') if f.endswith('signature') ])]

    @CWD_As('tests/testdata/subpackets')
    def uasubpacket():
        global tdata
        tdata += [sorted([ os.path.abspath(f) for f in os.listdir('.') if f.endswith('userattr') ])]

    @CWD_As('tests/testdata/packets')
    def packet():
        global tdata
        tdata += [sorted([ os.path.abspath(f) for f in os.listdir('.') ])]

    @CWD_As('tests/testdata/packets')
    def ekpacket():
        global tdata
        tdata += [sorted([ os.path.abspath(f) for f in os.listdir('.') if f.startswith('05.v4.enc') ])]

    @CWD_As('tests/testdata/packets')
    def ukpacket():
        global tdata
        tdata += [sorted([ os.path.abspath(f) for f in os.listdir('.') if f.startswith('05.v4.unc') ])]

    @CWD_As('tests/testdata/blocks')
    def block():
        global tdata
        tdata += [sorted([ os.path.abspath(f) for f in os.listdir('.') if f.endswith('.asc') ])]

    @CWD_As('tests/testdata/blocks')
    def rsasigblock():
        global tdata
        tdata += [[os.path.abspath('rsasignature.asc')]]

    @CWD_As('tests/testdata/blocks')
    def rsapubblock():
        global tdata
        tdata += [[os.path.abspath('rsapubkey.asc')]]

    @CWD_As('tests/testdata/blocks')
    def rsaprivblock():
        global tdata
        tdata += [[os.path.abspath('rsaseckey.asc')]]

    @CWD_As('tests/testdata/blocks')
    def clearblock():
        global tdata
        tdata += [[os.path.abspath(f) for f in os.listdir('.') if f.startswith('cleartext')]]

    @CWD_As('tests/testdata/blocks')
    def litblock():
        global tdata
        tdata += [[os.path.abspath('message.literal.asc')]]

    @CWD_As('tests/testdata/blocks')
    def compblock():
        global tdata
        tdata += [[os.path.abspath('message.compressed.asc')]]

    @CWD_As('tests/testdata/blocks')
    def onepassblock():
        global tdata
        tdata += [[os.path.abspath('message.onepass.asc'), os.path.abspath('message.two_onepass.asc')]]

    @CWD_As('tests/testdata/blocks')
    def encblock():
        global tdata
        tdata += [[os.path.abspath('message.encrypted.asc'), os.path.abspath('message.encrypted.signed.asc')]]

    @CWD_As('tests/testdata/signatures')
    def sigf():
        global argvals
        global ids
        argvals += [ sorted(set(os.path.abspath(f.split('.')[0]) for f in os.listdir('.'))) ]
        ids += sorted(set(f.split('.')[0] for f in os.listdir('.')))

    @CWD_As('tests/testdata/keys')
    def revkey():
        global tdata
        tdata += [[os.path.abspath(f) for f in os.listdir('.') if '.rev.' in f and f.endswith('.asc')]]

    @CWD_As('tests/testdata/keys')
    def rsakey():
        global tdata
        tdata += [[os.path.abspath('rsa.asc')]]

    @CWD_As('tests/testdata/keys')
    def dsakey():
        global tdata
        tdata += [[os.path.abspath('dsa.asc')]]

    @CWD_As('tests/testdata/keys')
    def encrsakey():
        global tdata
        tdata += [[os.path.abspath('rsa.cast5.asc')]]

    @CWD_As('tests/testdata/messages')
    def rsamessage():
        global tdata
        tdata += [sorted([os.path.abspath(f) for f in os.listdir('.') if f.startswith('message') and '.rsa.' in f])]

    @CWD_As('tests/testdata/messages')
    def dsamessage():
        global tdata
        tdata += [sorted([os.path.abspath(f) for f in os.listdir('.') if f.startswith('message') and '.dsa.' in f])]

    @CWD_As('tests/testdata/messages')
    def passmessage():
        global tdata
        tdata += [sorted([os.path.abspath(f) for f in os.listdir('.') if f.startswith('message') and '.pass.' in f])]

    @CWD_As('tests/testdata/messages')
    def ctmessage():
        global tdata
        tdata += [sorted([os.path.abspath(f) for f in os.listdir('.') if f.startswith('cleartext')])]

    @CWD_As('tests/testdata')
    def ascrings():
        global argvals
        global ids
        argvals += [[[os.path.abspath('pubtest.asc'), os.path.abspath('sectest.asc')]]]
        ids += ['ascrings']

    @CWD_As('tests/testdata')
    def lit():
        global argvals
        global ids
        argvals += [[os.path.abspath('lit')]]
        ids += ['lit']

    @CWD_As('tests/testdata')
    def lit2():
        global argvals
        global ids
        argvals += [[os.path.abspath('lit2')]]
        ids += ['lit2']

    @CWD_As('tests/testdata')
    def lit_de():
        global argvals
        global ids
        argvals += [[os.path.abspath('lit_de')]]
        ids += ['lit_de']

    # run all inner functions that match fixturenames
    # I organized it like this for easy code folding in PyCharm :)
    for fn in metafunc.fixturenames:
        if fn in locals():
            params += [fn]
            locals()[fn]()

    if tdata != []:
        # zip sublists together
        tdata = list(zip(*tdata))

        for i, fa in enumerate(tdata):
            at = []
            for a, f in enumerate(fa):
                if not f.endswith('.asc'):
                    _b = bytearray(os.path.getsize(f))
                    with open(f, 'rb') as fo:
                        fo.readinto(_b)

                    _b += b'\xca\xfe\xba\xbe'

                else:
                    with open(f, 'r') as fo:
                        _b = fo.read()

                at.append(_b)
            argvals += [tuple(at)]

        if len(ids) == 0:
            ids = [ '_'.join(re.split('\.', os.path.basename(f[0]))[:-1]) for f in tdata ]

    if params != []:
        para = ','.join(params)
        al = set(len(a) for a in argvals)

        # make sure argvals is a list of tuples if it isn't already
        if not isinstance(argvals[0], tuple):
            argvals = list(zip(*argvals))

        # if there is only one param, it should actually just be a list of arguments
        if len(params) == 1 and isinstance(argvals[0], tuple):
            argvals = [i[0] for i in argvals]

        try:
            metafunc.parametrize(para, argvals, ids=ids, scope="class")

        except ValueError:
            print("params: " + str(para))
            print("argvals: " + str(argvals))
            print("ids: " + str(ids))
            raise
