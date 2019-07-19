#!/usr/bin/python
# from distutils.core import setup
import sys

from setuptools import setup

if sys.version_info[:2] >= (3, 3):
    # on Python 3.3+, we can import a file directly using importlib.machinery.SourceFileLoader
    import importlib.machinery
    _loader = importlib.machinery.SourceFileLoader('_author', 'pgpy/_author.py')
    _author = _loader.load_module()

else:
    # on Python 2 and 3.2, importlib.machinery.SourceFileLoader doesn't exist
    # so we have to use imp to accomplish the same thing
    import imp
    _author = imp.load_source('_author', 'pgpy/_author.py')

# long_description is the contents of README.rst
with open('README.rst') as readme:
    long_desc = readme.read()


_requires = [
    'cryptography>=1.5',
    'pyasn1',
    'six>=1.9.0',
]

_doc_requires = [
    'sphinx',
    'sphinx-better-theme'
]

if sys.version_info[:2] < (3, 4):
    # only depend on enum34 and singledispatch if Python is older than 3.4
    _requires += ['singledispatch']
    _requires += ['enum34']

setup(
    # metadata
    name             = 'PGPy',
    version          = _author.__version__,
    description      = 'Pretty Good Privacy for Python',
    long_description = long_desc,
    author           = _author.__author__,
    author_email     = "mgreene@securityinnovation.com",
    license          = _author.__license__,
    classifiers      = ['Development Status :: 4 - Beta',
                        'Operating System :: POSIX :: Linux',
                        'Operating System :: MacOS :: MacOS X',
                        'Operating System :: Microsoft :: Windows',
                        'Intended Audience :: Developers',
                        'Programming Language :: Python',
                        'Programming Language :: Python :: 3.7',
                        'Programming Language :: Python :: 3.6',
                        'Programming Language :: Python :: 3.5',
                        'Programming Language :: Python :: 3.4',
                        'Programming Language :: Python :: 2.7',
                        'Programming Language :: Python :: Implementation :: CPython',
                        'Topic :: Security',
                        'Topic :: Security :: Cryptography',
                        'Topic :: Software Development :: Libraries',
                        'Topic :: Software Development :: Libraries :: Python Modules',
                        'License :: OSI Approved :: BSD License'],
    keywords        = ["OpenPGP",
                       "PGP",
                       "Pretty Good Privacy",
                       "GPG",
                       "GnuPG",
                       "openpgp",
                       "pgp",
                       "gnupg",
                       "gpg",
                       "encryption",
                       "signature", ],

    # dependencies
    install_requires = _requires,

    # urls
    url              = "https://github.com/SecurityInnovation/PGPy",
    download_url     = "https://github.com/SecurityInnovation/PGPy/archive/{pgpy_ver}.tar.gz".format(pgpy_ver=_author.__version__),
    # bugtrack_url     = "https://github.com/SecurityInnovation/PGPy/issues",

    # package hierarchy
    packages = [
        "pgpy",
        "pgpy.packet",
        "pgpy.packet.subpackets"
    ],
)
