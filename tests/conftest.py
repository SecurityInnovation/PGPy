"""PGPy conftest"""
import pytest

import contextlib
import glob
import os
import re
import select
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


_gpg_bin = _which('gpg2')
_gpg_args = ('--options', './pgpy.gpg.conf', '--expert', '--status-fd')
_gpg_env = {}
_gpg_env['GNUPGHOME'] = os.path.abspath(os.path.abspath('tests/testdata'))
_gpg_kwargs = dict()
_gpg_kwargs['cwd'] = 'tests/testdata'
_gpg_kwargs['env'] = _gpg_env
_gpg_kwargs['stdout'] = subprocess.PIPE
_gpg_kwargs['stderr'] = subprocess.STDOUT
_gpg_kwargs['close_fds'] = False


# GPG boilerplate function
def _gpg(*gpg_args, **popen_kwargs):
    # gpgfd is our "read" end of the pipe
    # _gpgfd is gpg's "write" end
    gpgfd, _gpgfd = os.pipe()

    # on python >= 3.4, we need to set _gpgfd as inheritable
    # older versions do not have this function
    if sys.version_info >= (3, 4):
        os.set_inheritable(_gpgfd, True)

    args = (_gpg_bin,) + _gpg_args + (str(_gpgfd),) + gpg_args
    kwargs = _gpg_kwargs.copy()
    kwargs.update(popen_kwargs)

    try:
        # use this as the buffer for collecting status-fd output
        c = bytearray()

        cmd = subprocess.Popen(args, **kwargs)
        while cmd.poll() is None:
            while gpgfd in select.select([gpgfd,], [], [], 0)[0]:
                c += os.read(gpgfd, 1)

            else:
                # sleep for a bit
                time.sleep(0.010)

        # finish reading if needed
        while gpgfd in select.select([gpgfd,], [], [], 0)[0]:
            c += os.read(gpgfd, 1)

        # collect stdout and stderr
        o, e = cmd.communicate()

    finally:
        # close the pipes we used for this
        os.close(gpgfd)
        os.close(_gpgfd)

    return c.decode('latin-1'), (o or b'').decode('latin-1'), (e or b'').decode('latin-1')


# fixtures
@pytest.fixture()
def gpg_import():
    @contextlib.contextmanager
    def _gpg_import(*keypaths):
        # if GPG version is 2.1 or newer, we need to add a setup/teardown step in creating the keybox folder
        if gpg_ver >= '2.1':
            if not os.path.exists('tests/testdata/private-keys-v1.d'):
                os.mkdir('tests/testdata/private-keys-v1.d')
                time.sleep(0.5)

        gpgc, gpgo, gpge = _gpg('--batch', '--import', *list(keypaths))

        try:
            yield gpgo

        finally:
            [os.remove(f) for f in glob.glob('tests/testdata/testkeys.*')]
            if gpg_ver >= '2.1':
                [os.remove(f) for f in glob.glob('tests/testdata/private-keys-v1.d/*')]

            time.sleep(0.5)

    return _gpg_import


@pytest.fixture()
def gpg_check_sigs():
    def _gpg_check_sigs(*keyids):
        gpgc, gpgo, gpge = _gpg('--check-sigs', *keyids)
        return 'sig-' not in gpgo

    return _gpg_check_sigs


@pytest.fixture()
def gpg_verify():
    sfd_verify = re.compile(r'^\[GNUPG:\] (?:GOOD|EXP)SIG (?P<keyid>[0-9A-F]+) .*'
                            r'^\[GNUPG:\] VALIDSIG (?:[0-9A-F]{,24})\1', flags=re.MULTILINE | re.DOTALL)

    def _gpg_verify(gpg_subjpath, gpg_sigpath=None, keyid=None):
        rargs = [gpg_sigpath, gpg_subjpath] if gpg_sigpath is not None else [gpg_subjpath,]

        gpgc, gpgo, gpge = _gpg('--verify', *rargs)

        sigs = [ sv.group('keyid') for sv in sfd_verify.finditer(gpgc) ]

        if keyid is not None:
            return keyid in sigs

        return sigs

    return _gpg_verify


@pytest.fixture
def gpg_decrypt():
    sfd_decrypt = re.compile(r'^\[GNUPG:\] BEGIN_DECRYPTION\n'
                             r'^\[GNUPG:\] DECRYPTION_INFO \d+ \d+\n'
                             r'^\[GNUPG:\] PLAINTEXT (?:62|74|75) (?P<tstamp>\d+) (?P<fname>.*)\n'
                             r'^\[GNUPG:\] PLAINTEXT_LENGTH \d+\n'
                             r'\[GNUPG:\] DECRYPTION_OKAY\n'
                             r'(?:^\[GNUPG:\] GOODMDC\n)?'
                             r'^\[GNUPG:\] END_DECRYPTION', flags=re.MULTILINE)

    def _gpg_decrypt(encmsgpath, passphrase=None, keyid=None):
        a = []

        if passphrase is not None:
            # create a pipe to send the passphrase to GnuPG through
            pfdr, pfdw = os.pipe()

            # write the passphrase to the pipe buffer right away
            os.write(pfdw, passphrase.encode())
            os.write(pfdw, b'\n')

            # on python >= 3.4, we need to set pfdr as inheritable
            # older versions do not have this function
            if sys.version_info >= (3, 4):
                os.set_inheritable(pfdr, True)

            a.extend(['--batch', '--passphrase-fd', str(pfdr)])

        elif keyid is not None:
            a.extend(['--recipient', keyid])

        a.extend(['--decrypt', encmsgpath])

        gpgc, gpgo, gpge = _gpg(*a, stderr=subprocess.PIPE)

        status = sfd_decrypt.match(gpgc)
        return gpgo

    return _gpg_decrypt


@pytest.fixture
def gpg_print():
    sfd_text = re.compile(r'^\[GNUPG:\] PLAINTEXT (?:62|74|75) (?P<tstamp>\d+) (?P<fname>.*)\n'
                          r'^\[GNUPG:\] PLAINTEXT_LENGTH (?P<len>\d+)\n', re.MULTILINE)

    gpg_text = re.compile(r'(?:- gpg control packet\n)?(?P<text>.*)', re.MULTILINE | re.DOTALL)

    def _gpg_print(infile):
        gpgc, gpgo, gpge = _gpg('-o-', infile, stderr=subprocess.PIPE)
        status = sfd_text.match(gpgc)
        tlen = len(gpgo) if status is None else int(status.group('len'))

        return gpg_text.match(gpgo).group('text')[:tlen]

    return _gpg_print


@pytest.fixture
def gpg_keyid_file():
    def _gpg_keyid_file(infile):
        c, o, e = _gpg('--list-packets', infile)
        return re.findall(r'^\s+keyid: ([0-9A-F]+)', o, flags=re.MULTILINE)
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
    print("== PGPy Test Suite ==")

    # ensure commands we need exist
    for cmd in ['gpg2', 'pgpdump']:
        if _which(cmd) is None:
            print("Error: Missing Command: " + cmd)
            exit(-1)

    # get the GnuPG version
    gpg_ver.parse(_run(_which('gpg2'), '--version')[0].splitlines()[0].split(' ')[-1])

    # get the pgpdump version
    v, _ = _run(_which('pgpdump'), '-v', stderr=subprocess.STDOUT)
    pgpdump_ver.parse(v.split(' ')[2].strip(','))

    # display the working directory and the OpenSSL/GPG/pgpdump versions
    print("Working Directory: " + os.getcwd())
    print("Using OpenSSL " + str(openssl_ver))
    print("Using GnuPG   " + str(gpg_ver))
    print("Using pgpdump " + str(pgpdump_ver))
    print("")
