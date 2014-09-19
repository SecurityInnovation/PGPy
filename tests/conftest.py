import pytest

import contextlib
import functools
import glob
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


_gpg_args = ['/usr/bin/gpg', '--options', './pgpy.gpg.conf']
_gpg_env = os.environ.copy()
_gpg_env['GNUPGHOME'] = os.path.abspath(os.path.abspath('tests/testdata'))
_gpg_kwargs = dict()
_gpg_kwargs['cwd'] = 'tests/testdata'
_gpg_kwargs['env'] = _gpg_env
_gpg_kwargs['stdout'] = subprocess.PIPE
_gpg_kwargs['stderr'] = subprocess.STDOUT


# fixtures
@pytest.fixture()
def write_clean():
    @contextlib.contextmanager
    def _write_clean(fpath, mode='w', data=''):
        with open(fpath, mode) as wf:
            wf.write(data)
            wf.flush()

        try:
            yield

        finally:
            os.remove(fpath)

    return _write_clean


@pytest.fixture()
def gpg_import():
    @contextlib.contextmanager
    def _gpg_import(*keypaths):
        gpg_args = _gpg_args + ['--import',] + list(keypaths)
        gpg_kwargs = _gpg_kwargs.copy()

        gpgdec = subprocess.Popen(gpg_args, **gpg_kwargs)
        gpgdec.wait()
        gpgo, _ = gpgdec.communicate()

        try:
            yield gpgo.decode()

        finally:
            [os.remove(f) for f in glob.glob('tests/testdata/testkeys.*')]

    return _gpg_import


@pytest.fixture()
def gpg_check_sigs():
    def _gpg_check_sigs(*keyids):
        gpg_args = _gpg_args + ['--check-sigs'] + list(keyids)
        gpg_kwargs = _gpg_kwargs.copy()

        gpgdec = subprocess.Popen(gpg_args, **gpg_kwargs)
        gpgdec.wait()
        gpgo, _ = gpgdec.communicate()
        gpgo = gpgo.decode()
        return 'sig-' not in gpgo

    return _gpg_check_sigs


@pytest.fixture()
def gpg_verify():
    def _gpg_verify(gpg_subjpath, gpg_sigpath=None, keyid=None):
        gpg_args = _gpg_args + [ a for a in ['--verify', gpg_sigpath, gpg_subjpath] if a is not None ]
        gpg_kwargs = _gpg_kwargs.copy()

        gpgdec = subprocess.Popen(gpg_args, **gpg_kwargs)
        gpgdec.wait()
        gpgo, _ = gpgdec.communicate()
        gpgo = gpgo.decode()
        sigs = dict(re.findall(r'^gpg: Signature made .+\ngpg: \s+ using [A-Z]+ key ([0-9A-F]+)\n'
                               r'(?:gpg: using .+\n)*gpg: ([^\s]+) signature', gpgo, flags=re.MULTILINE))

        if keyid is not None:
            return sigs.get(keyid, '') == 'Good'

        else:
            return all(v == 'Good' for v in sigs.values())

    return _gpg_verify


@pytest.fixture
def gpg_decrypt():
    def _gpg_decrypt(encmsgpath, passphrase=None):
        gpg_args = _gpg_args + ['--decrypt', encmsgpath]
        gpg_kwargs = _gpg_kwargs.copy()
        gpg_kwargs['stderr'] = subprocess.PIPE
        _comargs = ()

        if passphrase is not None:
            gpg_args = _gpg_args + ['--batch', '--passphrase-fd', '0', '--decrypt', encmsgpath]
            gpg_kwargs['stdin'] = subprocess.PIPE
            _comargs = (passphrase.encode(),)

        gpgdec = subprocess.Popen(gpg_args, **gpg_kwargs)
        gpgo, gpge = gpgdec.communicate(*_comargs)
        gpgdec.wait()

        return gpgo.decode() if gpgo is not None else gpge

    return _gpg_decrypt


@pytest.fixture
def gpg_print():
    def _gpg_print(infile):
        gpg_args = _gpg_args + ['-o-', infile]
        gpg_kwargs = _gpg_kwargs.copy()
        gpg_kwargs['stderr'] = subprocess.PIPE

        gpgdec = subprocess.Popen(gpg_args, **gpg_kwargs)
        gpgdec.wait()
        gpgo, gpge = gpgdec.communicate()

        if gpgo.decode() is not None:
            return gpgo.decode()
        return ''

    return _gpg_print


@pytest.fixture()
def pgpdump():
    def _pgpdump(infile):
        _args = ['/usr/bin/pgpdump', '-agimplu', infile]
        return subprocess.check_output(_args).decode()

    return _pgpdump


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
    if metafunc.cls is not None and hasattr(metafunc.cls, 'params'):
        funcargs = [ (k, v) for k, v in metafunc.cls.params.items() if k in metafunc.fixturenames ]

        metafunc.parametrize(','.join(k for k, _ in funcargs),
                             list(zip(*[v for _, v in funcargs])) if len(funcargs) > 1 else [vi for _, v in funcargs for vi in v])
