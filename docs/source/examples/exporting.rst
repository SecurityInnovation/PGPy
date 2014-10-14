Exporting PGP* Objects
======================

PGPKey, PGPMessage, and PGPSignature objects can all be exported to OpenPGP-compatible binary and ASCII-armored formats.

To export in ASCII-armored format::

    # This works in both Python 2.x and 3.x
    # ASCII-armored format
    # cleartext PGPMessages will also have properly canonicalized and dash-escaped
    # message text
    pgpstr = str(pgpobj)

To export to binary format in Python 3::

    # binary format
    pgpbytes = bytes(pgpobj)

To export to binary format in Python 2::

    # binary format
    pgpbytes = pgpobj.__bytes__()

