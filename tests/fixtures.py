# import functools
# import os
# import re
# import subprocess
# #
# import pytest
#
# #
# # # fixture utilities
# #
# #
# #
# #
# # class ClassProperty(property):
# #     def __get__(self, cls, owner):
# #         return self.fget.__get__(None, owner)()
# #
# #
# # # parametrization helpers #
# #
# #
# # class TestFiles(object):
# #     # this is a purely static class.
# #     # there are two reasons I am grouping these fixture methods into a class:
# #     # 1. to group them syntactically because they are similar and related
# #     # 2. to group them syntactically with abstracted support functions that are used by the fixture methods
# #
# #     # keys under testdata/pubkeys/
# #     _public___keys = [ 'pubkeys/' + k for k in os.listdir('tests/testdata/pubkeys')
# #                               if k.split('.')[-1] == 'key']
# #     _private__keys = [ 'seckeys/' + k for k in os.listdir('tests/testdata/seckeys')
# #                               if k.split('.')[-1] == 'key']
# #     _detached_sigs = [ s for s in os.listdir('tests/testdata/signatures')
# #                               if s.split('.')[0]  == 'signed_message']
# #     _inline___sigs = [ s for s in os.listdir('tests/testdata/signatures')
# #                               if s.split('.')[0]  == 'inline_signed_message']
# #     _deb__releases = [ os.path.join(d, r)
# #                                 for d in ['aa-testing', 'debian-sid', 'ubuntu-precise']
# #                                 for r in os.listdir('tests/testdata/' + d)
# #                               if r == 'Release' ]
# #     _deb_rel__sigs = [ r + '.gpg' for r in _deb__releases ]
# #
# #     @staticmethod
# #     def test_id(file):
# #         # generate a test_id from a filename
# #         f = file.split('/')[-1]
# #
# #         if f[:4] == "Test":
# #             if f[:9] == "TestMulti":
# #                 return "multi"
# #
# #             else:
# #                 return '{alg}-{bitlen}'.format(
# #                     alg=f.split('-')[1].lower() if 'Enc' in f else f.split('-')[0][4:].lower(),
# #                     bitlen=f.split('-')[-1][:4]
# #                 )
# #
# #         if f[-4:] == '.key':
# #             return file.replace('_', '-').split('.')[0].split('/')[-1]
# #
# #         if f.split('.')[0] == 'signed_message':
# #             return f.split('.')[1].lower()
# #
# #         if f[:7] == 'Release':
# #             return file.split('/')[0]
# #
# #     @staticmethod
# #     def ids(params):
# #         return [ TestFiles.test_id(param) for param in params ]
# #
# #     @ClassProperty
# #     @classmethod
# #     def signatures(cls):
# #         return sorted([ 'signatures/' + s for s in cls._detached_sigs ] + cls._deb_rel__sigs,
# #                       key=lambda k: TestFiles.test_id(k))
# #
# #     @ClassProperty
# #     @classmethod
# #     def sigsubjects(cls):
# #         return sorted([ s for s in (['signed_message',] * len(cls._detached_sigs)) ] + cls._deb__releases)
# #
# #     @ClassProperty
# #     @classmethod
# #     def pubkeys(cls):
# #         return sorted(cls._public___keys,
# #                       key=lambda k: cls.test_id(k))
# #
# #     @ClassProperty
# #     @classmethod
# #     def privkeys(cls):
# #         return sorted(cls._private__keys,
# #                       key=lambda k: cls.test_id(k))
# #
# #     @ClassProperty
# #     @classmethod
# #     def keys(cls):
# #         return sorted([ k for k in cls.pubkeys + cls.privkeys],
# #                       key=lambda k: cls.test_id(k) if 'sec' not in k else cls.test_id(k)[4:])
# #
# #     @ClassProperty
# #     @classmethod
# #     def unprotected_privkeys(cls):
# #         return sorted([ pk for pk in cls._private__keys if 'Enc' not in pk ],
# #                       key=lambda k: cls.test_id(k))
# #
# #     @ClassProperty
# #     @classmethod
# #     def protected_privkeys(cls):
# #         return sorted([ pk for pk in cls._private__keys if 'Enc' in pk ],
# #                       key=lambda k: cls.test_id(k))
# #
# #
# class CWD_As(object):
#     def __init__(self, newwd):
#         if not os.path.exists(newwd):
#             raise FileNotFoundError(newwd + " not found within " + os.getcwd())
#
#         self.oldwd = os.getcwd()
#         self.newwd = newwd
#
#     def __call__(self, func):
#         @functools.wraps(func)
#         def setcwd(*args, **kwargs):
#             # set new working directory
#             os.chdir(self.newwd)
#
#             # fallback value
#             fo = None
#
#             try:
#                 fo = func(*args, **kwargs)
#
#             finally:
#                 # always return to self.oldwd even if there was a failure
#                 os.chdir(self.oldwd)
#
#             return fo
#
#         return setcwd
#
#
# # @CWD_As('tests/testdata')
# @CWD_As('testdata')
# def gpg_getfingerprint(keyname):
#     gpg_args = _gpg_args + ['--with-colons', '--list-keys', '--fingerprint', keyname]
#
#     try:
#         gpgo = subprocess.check_output(gpg_args, stderr=subprocess.STDOUT).decode()
#         return re.search(r'fpr:::::::::(.*):', gpgo).group(1)
#
#     except subprocess.CalledProcessError as e:
#         return "/usr/bin/gpg returned {ret}\n"\
#                "===========================\n"\
#                "{out}".format(ret=e.returncode, out=e.output.decode())
#
#
# # test fixtures #
# #
# #
# # @pytest.fixture()
# # def pgpdump():
# #     @CWD_As('tests/testdata')
# #     def _pgpdump(pgpdpath):
# #         if not os.path.exists(pgpdpath):
# #             raise FileNotFoundError(pgpdpath)
# #
# #         pgpd_args = ['/usr/bin/pgpdump', '-i', '-l', '-m', '-p', '-u', '--', pgpdpath]
# #
# #         try:
# #             return subprocess.check_output(pgpd_args, stderr=subprocess.STDOUT).decode()
# #
# #         ##TODO: add another exception clause here for catching when pgpdump does not exist
# #         # pgpdump execution returned non-zero for some reason
# #         except subprocess.CalledProcessError as e:
# #             return "/usr/bin/pgpdump returned {ret}\n"\
# #                    "===============================\n"\
# #                    "{out}".format(ret=e.returncode, out=e.output.decode())
# #
# #     return _pgpdump
# #
# #
# #
# #
# # @pytest.fixture()
# # def gpg_fingerprint():
# #     @CWD_As('tests/testdata')
# #     def _gpg_fingerprint(gpg_fp):
# #         gpg_args = _gpg_args + ['--fingerprint', gpg_fp]
# #
# #         try:
# #             return subprocess.check_output(gpg_args, stderr=subprocess.STDOUT).decode()
# #
# #         except subprocess.CalledProcessError as e:
# #             return "/usr/bin/gpg returned {ret}\n"\
# #                    "===========================\n"\
# #                    "{out}".format(ret=e.returncode, out=e.output.decode())
# #     return _gpg_fingerprint
# #
# # # only allow a handful of things to be imported
# # __all__ = [TestFiles, pgpdump, gpg_verify, gpg_fingerprint]
