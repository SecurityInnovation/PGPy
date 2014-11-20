#!/usr/bin/python
# from distutils.core import setup
from setuptools import setup

# this is dirty
import sys
sys.path.append('pgpy')
import _author

# long_description is the contents of README.rst
with open('README.rst') as readme:
    long_desc = readme.read()

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
                        'Programming Language :: Python :: 3.4',
                        'Programming Language :: Python :: 3.3',
                        'Programming Language :: Python :: 3.2',
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
    install_requires = ['cryptography==0.6',
                        'enum34',
                        'six',
                        'singledispatch'],

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
