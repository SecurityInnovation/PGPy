"""_version.py

Canonical location for authorship information
__version__ is a PEP-386 compliant version string,
making use of distutils.version.StrictVersion
"""

from distutils.version import LooseVersion

__author__ = "Michael Greene"
__copyright__ = "Copyright (c) 2014 Michael Greene"
__license__ = "MIT"
__version__ = str(LooseVersion("0.0.0"))
