import pytest

import contextlib
import functools
import glob
import os
import re
import six
import subprocess
import sys
import time

from distutils.version import LooseVersion

from cryptography.hazmat.backends import openssl

openssl_ver = LooseVersion(openssl.backend.openssl_version_text().split(' ')[1])
gpg_ver = LooseVersion('0')
pgpdump_ver = LooseVersion('0')


# ensure external commands we need to run exist

# set the CWD and add to sys.path if we need to
os.chdir(os.path.join(os.path.abspath(os.path.dirname(__file__)), os.pardir))

if os.getcwd() not in sys.path:
    sys.path.insert(0, os.getcwd())
else:
    sys.path.insert(0, sys.path.pop(sys.path.index(os.getcwd())))

if os.path.join(os.getcwd(), 'tests') not in sys.path:
    sys.path.insert(1, os.path.join(os.getcwd(), 'tests'))


def _which(cmd):
    for d in iter(p for p in os.getenv('PATH').split(':') if os.path.isdir(p)):
        if cmd in os.listdir(d) and os.access(os.path.realpath(os.path.join(d, cmd)), os.X_OK):
            return os.path.join(d, cmd)


# run a subprocess command, wait for it to complete, and then return decoded output
def _run(bin, *binargs, **pkw):
    _default_pkw = {'stdout': subprocess.PIPE,
                    'stderr': subprocess.PIPE}

    popen_kwargs = _default_pkw.copy()
    popen_kwargs.update(pkw)

    cmd = subprocess.Popen([bin] + list(binargs), **popen_kwargs)
    cmd.wait()
    cmdo, cmde = cmd.communicate()

    cmdo = cmdo.decode('latin-1') if cmdo is not None else ""
    cmde = cmde.decode('latin-1') if cmde is not None else ""

    return cmdo, cmde

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


_gpg_bin = _which('gpg2')
_gpg_args = ['--options', './pgpy.gpg.conf', '--expert']
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
        gpg_args = _gpg_args + ['--import', ] + list(keypaths)
        gpg_kwargs = _gpg_kwargs.copy()
        gpgo, _ = _run(_gpg_bin, *gpg_args, **gpg_kwargs)

        # if GPG version is 2.1 or newer, we need to add a setup/teardown step in creating the keybox folder
        if gpg_ver >= '2.1':
            if not os.path.exists('tests/testdata/private-keys-v1.d'):
                os.mkdir('tests/testdata/private-keys-v1.d')
                time.sleep(5)

        try:
            yield gpgo

        finally:
            [os.remove(f) for f in glob.glob('tests/testdata/testkeys.*')]
            if gpg_ver >= '2.1':
                [os.remove(f) for f in glob.glob('tests/testdata/private-keys-v1.d/*')]
            #     os.rmdir('tests/testdata/private-keys-v1.d')

            time.sleep(0.5)

    return _gpg_import


@pytest.fixture()
def gpg_check_sigs():
    def _gpg_check_sigs(*keyids):
        gpg_args = _gpg_args + ['--check-sigs'] + list(keyids)
        gpg_kwargs = _gpg_kwargs.copy()
        gpgo, _ = _run(_gpg_bin, *gpg_args, **gpg_kwargs)
        return 'sig-' not in gpgo

    return _gpg_check_sigs


@pytest.fixture()
def gpg_verify():
    def _gpg_verify(gpg_subjpath, gpg_sigpath=None, keyid=None):
        gpg_args = _gpg_args + [ a for a in ['--verify', gpg_sigpath, gpg_subjpath] if a is not None ]
        gpg_kwargs = _gpg_kwargs.copy()
        gpgo, _ = _run(_gpg_bin, *gpg_args, **gpg_kwargs)

        sigs = dict(re.findall(r'^gpg: Signature made .+\ngpg: \s+ using [A-Z]+ key ([0-9A-F]+)\n'
                               r'(?:gpg: using .+\n)*gpg: ([^\s]+) signature', gpgo, flags=re.MULTILINE))

        if keyid is not None:
            return sigs.get(keyid, '') in ['Good', 'Expired']

        else:
            return all(v in ['Good', 'Expired'] for v in sigs.values())

    return _gpg_verify


@pytest.fixture
def gpg_decrypt():
    def _gpg_decrypt(encmsgpath, passphrase=None, keyid=None):
        gpg_args = [_gpg_bin] + _gpg_args[:]
        gpg_kwargs = _gpg_kwargs.copy()
        gpg_kwargs['stderr'] = subprocess.PIPE
        _comargs = ()

        if passphrase is not None:
            gpg_args += ['--batch', '--passphrase-fd', '0']
            gpg_kwargs['stdin'] = subprocess.PIPE
            _comargs = (passphrase.encode(),)

        if keyid is not None:
            gpg_args += ['--recipient', keyid]

        gpg_args += ['--decrypt', encmsgpath]

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

        gpgo, _ = _run(_gpg_bin, *gpg_args, **gpg_kwargs)
        return gpgo

    return _gpg_print


@pytest.fixture
def gpg_keyid_file():
    def _gpg_keyid_file(infile):
        gpg_args = _gpg_args + ['--list-packets', infile]
        gpg_kwargs = _gpg_kwargs.copy()

        gpgo, _ = _run(_gpg_bin, *gpg_args, **gpg_kwargs)
        return re.findall(r'^\s+keyid: ([0-9A-F]+)', gpgo, flags=re.MULTILINE)

    return _gpg_keyid_file


@pytest.fixture()
def pgpdump():
    def _pgpdump(infile):
        return _run(_which('pgpdump'), '-agimplu', infile)[0]

    return _pgpdump


# pytest hooks

# pytest_configure
# called after command line options have been parsed and all plugins and initial conftest files been loaded.
def pytest_configure(config):
    # ensure commands we need exist
    for cmd in ['gpg2', 'pgpdump']:
        if _which(cmd) is None:
            print("Error: Missing Command: " + cmd)
            exit(-1)

    # get the GnuPG version
    gpg_ver.parse(_run(_which('gpg'), '--version')[0].splitlines()[0].split(' ')[-1])

    # get the pgpdump version
    v, _ = _run(_which('pgpdump'), '-v', stderr=subprocess.STDOUT)
    pgpdump_ver.parse(v.split(' ')[2].strip(','))

    # display the working directory and the OpenSSL version
    print("Working Directory: " + os.getcwd())
    print("Using OpenSSL " + str(openssl_ver))
    print("Using GnuPG   " + str(gpg_ver))
    print("Using pgpdump " + str(pgpdump_ver))
    print("")


# pytest_generate_tests
# called when each test method is collected to generate parametrizations
def pytest_generate_tests(metafunc):
    if metafunc.cls is not None and hasattr(metafunc.cls, 'params'):
        funcargs = [ (k, v) for k, v in metafunc.cls.params.items() if k in metafunc.fixturenames ]

        args = [','.join(k for k, _ in funcargs),
                list(zip(*[v for _, v in funcargs])) if len(funcargs) > 1 else [vi for _, v in funcargs for vi in v]]
        kwargs = {}

        if hasattr(metafunc.cls, 'ids') and metafunc.function.__name__ in metafunc.cls.ids:
            kwargs['ids'] = metafunc.cls.ids[metafunc.function.__name__]

        metafunc.parametrize(*args, **kwargs)
