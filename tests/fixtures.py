import functools
import os
import subprocess

import pytest

# fixture utilities
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


class ClassProperty(property):
    def __get__(self, cls, owner):
        return self.fget.__get__(None, owner)()


# test fixtures


class TestFiles(object):
    # this is a purely static class.
    # there are two reasons I am grouping these fixture methods into a class:
    # 1. to group them syntactically because they are similar and related
    # 2. to group them syntactically with abstracted support functions that are used by the fixture methods

    # keys under testdata/pubkeys/
    _public___keys = [ k for k in os.listdir('tests/testdata/pubkeys')
                              if k.split('.')[-1] == 'key']
    _private__keys = [ k for k in os.listdir('tests/testdata/seckeys')
                              if k.split('.')[-1] == '.sec.key']
    _detached_sigs = sorted([ s for s in os.listdir('tests/testdata/signatures')
                              if s.split('.')[0]  == 'signed_message'])
    _inline___sigs = sorted([ s for s in os.listdir('tests/testdata/signatures')
                              if s.split('.')[0]  == 'inline_signed_message'])
    _deb__releases = sorted([ os.path.join(d, r)
                                for d in ['aa-testing', 'debian-sid', 'ubuntu-precise']
                                for r in os.listdir('tests/testdata/' + d)
                              if r == 'Release' ])
    _deb_rel__sigs = sorted([ r + '.gpg' for r in _deb__releases ])

    @staticmethod
    def test_id(file):
        # generate a test_id from a filename
        f = file.split('/')[-1]

        if f[:4] == "Test":
            if f[-8:] == '.sec.key':
                return 'sec-{kalg}{encalg}-{bitlen}'.format(
                    kalg=f.split('-')[0][4:].lower(),
                    encalg='' if 'Enc' not in f else '-' + f.split('-')[1][3:].lower(),
                    bitlen=f.split('-')[-1][:4]
                )

            else:
                return '{kalg}{encalg}-{bitlen}'.format(
                    kalg=f.split('-')[0][4:].lower(),
                    encalg='' if 'Enc' not in f else '-' + f.split('-')[1][3:].lower(),
                    bitlen=f.split('-')[-1][:4]
                )

        if f[-4:] == '.key':
            return file.replace('_', '-').split('.')[0].split('/')[-1]

        if f.split('.')[0] == 'signed_message':
            return f.split('.')[1].lower()

        if f[:7] == 'Release':
            return file.split('/')[-2]

    @staticmethod
    def ids(params):
        return [ TestFiles.test_id(param) for param in params ]

    @ClassProperty
    @classmethod
    def signatures(cls):
        return [ 'signatures/' + s for s in cls._detached_sigs ] + cls._deb_rel__sigs

    @ClassProperty
    @classmethod
    def sigsubjects(cls):
        return [ 'signatures/' + s for s in (['signed_message',] * len(cls._detached_sigs)) ] + cls._deb__releases

    @ClassProperty
    @classmethod
    def pubkeys(cls):
        return [ 'pubkeys/' + pk
                 for pk in sorted(cls._public___keys) ]

    @ClassProperty
    @classmethod
    def privkeys(cls):
        return sorted(cls._private__keys)

    @ClassProperty
    @classmethod
    def unprotected_privkeys(cls):
        return [ 'seckeys/' + pk
                 for pk in sorted([ pk for pk in cls._private__keys if 'Enc' not in pk ]) ]

    @ClassProperty
    @classmethod
    def protected_privkeys(cls):
        return [ 'seckeys/' + pk
                 for pk in sorted([ pk for pk in cls._private__keys if 'Enc' in pk ]) ]
@CWD_As('tests/testdata')
def gpg_getfingerprint(keyname):
    gpg_args = _gpg_args + ['--with-colons', '--list-keys', '--fingerprint', keyname]

    try:
        gpgo = subprocess.check_output(gpg_args, stderr=subprocess.STDOUT).decode()
        return re.search(r'fpr:::::::::(.*):', gpgo).group(1)

    except subprocess.CalledProcessError as e:
        return "/usr/bin/gpg returned {ret}\n"\
               "===========================\n"\
               "{out}".format(ret=e.returncode, out=e.output.decode())


# test fixtures #


@pytest.fixture()
def pgpdump():
    @CWD_As('tests/testdata')
    def _pgpdump(pgpdpath):
        if not os.path.exists(pgpdpath):
            raise FileNotFoundError(pgpdpath)

        pgpd_args = ['/usr/bin/pgpdump', '-i', '-l', '-m', '-p', '-u', '--', pgpdpath]

        try:
            return subprocess.check_output(pgpd_args, stderr=subprocess.STDOUT)

        ##TODO: add another exception clause here for catching when pgpdump does not exist
        # pgpdump execution returned non-zero for some reason
        except subprocess.CalledProcessError as e:
            return "/usr/bin/pgpdump returned {ret}\n"\
                   "===============================\n"\
                   "{out}".format(ret=e.returncode, out=e.output)

    return _pgpdump

@pytest.fixture()
def gpg_verify():
    @CWD_As('tests/testdata')
    def _gpg_verify(gpg_subjpath, gpg_sigpath=None):
        gpg_args = ['/usr/bin/gpg',
                '--no-default-keyring',
                '--keyring', './testkeys.gpg',
                '--secret-keyring', './testkeys.sec.gpg',
                '--trustdb-name', './testkeys.trust',
                '-vv', '--verify']

        if gpg_sigpath is not None:
            gpg_args += [gpg_sigpath]
        gpg_args += gpg_subjpath

        try:
            return subprocess.check_output(gpg_args, stderr=subprocess.STDOUT)

        except subprocess.CalledProcessError as e:
            return "/usr/bin/gpg returned {ret}\n"\
                   "===========================\n"\
                   "{out}".format(ret=e.returncode, out=e.output)

    return _gpg_verify


# only allow a handful of things to be imported
__all__ = [pgpdump, gpg_verify]