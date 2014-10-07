************
Installation
************

.. highlight:: bash

Linux
=====

Building PGPy on Linux requires a C compiler, headers for Python, headers for OpenSSL, and libffi.

For Debian/Ubuntu, these requirements can be installed like so::

    $ sudo apt-get install build-essential libssl-dev libffi-dev python-dev

You may need to install ``python3-dev`` if you are using PGPy on Python 3.


Mac OS X
--------

If you are on Mac OS, you may experience more limited functionality without installing a more capable version of OpenSSL.



Installation
------------

Once you have the prerequisites specified above, PGPy can be installed from PyPI using pip, like so::

    $ pip install PGPy

