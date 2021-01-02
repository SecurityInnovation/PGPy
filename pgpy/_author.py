"""_author.py

Canonical location for authorship information
__version__ is a PEP-386 compliant version string,
making use of distutils.version.LooseVersion
"""

from distutils.version import LooseVersion

__all__ = ['__author__',
           '__copyright__',
           '__license__',
           '__version__']

__author__ = "Michael Greene"
__copyright__ = "Copyright (c) 2014-2019 Security Innovation, Inc"
__license__ = "BSD"
__version__ = str(LooseVersion("0.5.3"))
