************
Installation
************

.. highlight:: console

Platform Specific Notes
=======================

Windows
-------

PGPy has not been formally tested on Windows. I see no reason why it wouldn't work, but your mileage may vary.
If you try it out and run into any issues, please submit bug reports on the `issue tracker <https://github.com/SecurityInnovation/PGPy/issues>`_!

Linux
-----

Debian
^^^^^^

PGPy is now in `Debian Testing <https://packages.debian.org/buster/python3-pgpy>`_, and can be installed simply::

    $ sudo apt install python3-pgpy

Arch Linux
^^^^^^^^^^

PGPy is available on the `AUR <https://aur.archlinux.org/packages/python-pgpy/>`_

Gentoo
^^^^^^

There are gentoo ebuilds available in the `gentoo branch <https://github.com/SecurityInnovation/PGPy/tree/gentoo>`_

RedHat/CentOS
^^^^^^^^^^^^^

Coming Soon!

Other Linux
^^^^^^^^^^^

Building PGPy on Linux requires a C compiler, headers for Python, headers for OpenSSL, and libffi, to support building Cryptography.

For Debian/Ubuntu, these requirements can be installed like so::

    $ sudo apt install build-essential libssl-dev libffi-dev python-dev

For Alpine linux, the build requirements can be installed like so::

    $ apk add build-base libressl-dev libffi-dev python-dev

You may need to install ``python3-dev`` if you are using PGPy on Python 3.

For Fedora/RHEL derivatives, the build requirements can be installed like so::

    $ sudo yum install gcc libffi-devel python-devel openssl-devel

Mac OS X
--------

If you are on Mac OS, you may experience more limited functionality without installing a more capable version of OpenSSL.

You may refer to Cryptography's documentation on `Building cryptography on macOS <https://cryptography.io/en/latest/installation.html#building-cryptography-on-macos>`_ for information on how to do so.


Installation
============

Once you have the prerequisites specified above, PGPy can be installed from PyPI using pip, like so::

    $ pip install PGPy
