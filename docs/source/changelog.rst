:tocdepth: 2

*********
Changelog
*********

v0.6.0
======

Released: Nov 23, 2022

.. note::

New Features
------------
* added the ability to ignore usage flags

Bugs Fixed
----------
* accept passphrases formatted as ``bytes``
* default to 3DES when no preferred algorithms are supported
* generate TZ-aware datetime objects
* works with Cryptography 38

Other Changes
-------------

* dropped support for Python 2 and Python 3 <= 3.5
* renamed ``PGPOpenSSLCipherNotSupported`` to ``PGPOpenSSLCipherNotSupportedError``
* renamed ``PGPOpenSSLCipherNotSupported`` to ``PGPOpenSSLCipherNotSupportedError``
* renamed ``PGPInsecureCipher`` to ``PGPInsecureCipherError``
* fixed a bunch of typos
* improve code style, increase consistency

v0.5.4
======

Released: April 16, 2021

.. note::

    PGPy v0.5.x is still compatible with Python 2.7 and 3.4. Support for those versions will be dropped in PGPy v0.6.0.

Bugs Fixed
----------

* Fixed compatibility break with Python < 3.8 (#368)
* Fixed importing ABCs from ``collections`` (#328)

Other Changes
-------------

* Documentation updates


v0.5.3
======

Released: October 6, 2020

.. warning::

    This is the last release that will support Python 2.7 and 3.4. Future releases will require Python 3.5 or greater.

Bugs fixed
----------

* Passphrases are now encoded as utf-8 instead of latin-1 (#294)
* PGPUIDs without a selfsig no longer cause crashes (#315)
* Fixed dash un-escaping to be applied unconditionally (#341, #342)
* Fix the ordering of one-pass signatures (#302)

Other Changes
-------------

* Updated unit tests to use `gpg 1.10 <https://pypi.org/project/gpg/1.10.0/>`_
* Lots of documentation updates and cleanup

v0.5.2
======

Released: August 1, 2019

Bugs Fixed
----------

 * Signature subpackets of type 0 cause an infinite parse loop (#252)

v0.5.0
======
Released: August 1, 2019

New Features
------------

 * Add support for Curve25519
 * Greatly improved Elliptic Curve Point format handling code (special thanks @rot42)
 * Add support for IssuerFingerprint subpackets (thanks @J08nY)
 * Add support for Key Revocation signatures

Bugs Fixed
----------

 * PGPy now correctly resynchronizes the block cipher stream when decrypting EncryptedDataPackets (the ones without MDC). (#160)
 * PGPy now correctly defaults to SHA256 for keys that have no hash preferences set

Other Changes
-------------

 * updated library dependencies and unit tests

v0.4.3
======

Released: August 16, 2017

Bugs Fixed
----------

 * Private key checksum calculations were not getting stored for ECDSA keys; this has been fixed.
 * The test suite gpg wrappers have been replaced with use of the `gpg <https://pypi.python.org/pypi/gpg/1.8.0>`_ package. (#171)

v0.4.2
======

Released: August 9, 2017

New Features
------------

 * Packets with partial body lengths can now be parsed. For now, these packets are converted to have definite lengths instead. (#95) (#208)

Bugs Fixed
----------
 * Private key checksums are now calculated correctly (#172)
 * PGPKey.decrypt was mistakenly using message.issuers instead of message.encrypters when determining whether or not the key was eligible
   to attempt decrypting the message (#183)
 * Fixed an issue with parsing some cleartext messages (#184)
 * Fixed signing already-encrypted messages (encrypt-then-sign) (#186) (#191)
 * PGP*.from_blob now correctly raises an exception if given zero-length input (#199) (#200)
 * Fixed an issue where PGPKey.decrypt would fail with an arcane traceback if the key is passphrase-protected and not unlocked. (#204)

v0.4.1
======

Released: April 13, 2017

Bugs Fixed
----------
 * Fixed an issue with dearmoring ASCII-armored PGP blocks with windows-style newlines (#156)
 * Improved the robustness of the code that tunes the hash count for deriving symmetric encryption keys (#157)
 * Fixed an issue with how public keys are created from private keys that was causing exports to become malformed (#168)
 * Added explicit support for Python 3.6 (#166)

New Features
------------
 * Added support for Brainpool Standard curves for users who have OpenSSL 1.0.2 available

v0.4.0
======

Released: April 21, 2016

Bugs Fixed
----------
 * Armorable.from_blob was incorrectly not accepting bytes objects; this has been fixed (#140)
 * Fixed an issue where string-formatting PGPUID objects would sometimes raise an exception (#142)
 * Occasionally, the ASN.1 encoding of DSA signatures was being built in a way that although GPG could parse and verify them,
   it was incorrect, and PGPy incorrectly failed to verify them. (#143)
 * Fixed an issue where keys with expiration dates set would have the wrong value returned from the ``key.is_expired`` property (#151)
 * Fixed an issue where PGPy would try to incorrectly coerce non-ASCII-compatible characters to ASCII-compatible bytes, potentially resulting in mojibake. (#154)

New Features
------------
 * ECDSA and ECDH keys can now be loaded (#109, #110)
 * Keys can be generated with the following algorithms:

   - RSA
   - DSA
   - ECDSA
   - ECDH

 * Keys can now be passphrase-protected. It is also possible to change the passphrase on a key that is already protected. (#149)
 * ECDSA keys can now be used to sign and verify (#111)
 * ECDH keys can now be used to encrypt and decrypt
 * It is now possible to recover a public key from a private key (#92)
 * Marker packets are now understood

Other Changes
-------------
 * Removed support for Python 3.2, as multiple dependency libraries have already done so
 * Added explicit support for Python 3.5
 * Updated library dependencies where required or useful
 * Reworked some IO-intensive routines to be less IO-intensive, and therefore faster

v0.3.0
======

Released: November 19, 2014

PGPy v0.3.0 is a major feature release.

.. warning::
    The API changed significantly in this version. It is likely that anything using a previous version will need to be
    updated to work correctly with PGPy 0.3.0 or later.

Bugs Fixed
----------
 * When keys are exported, any certification signatures that are marked as being non-exportable are now skipped (#101)
 * When the wrong key is used to validate a signature, the error message in the raised exception
   now makes that clear (#106)

New Features
------------
 * Standalone signatures can now be generated
 * Can now specify which User ID to use when signing things (#121)
 * Can now create new User IDs and User Attributes (#118)
 * Can now add new User IDs and User Attributes to keys (#119)
 * Timestamp signatures can now be generated
 * Can now sign keys, user ids, and user attributes (#104)
 * Can now create new PGPMessages (#114)
 * Key flags are now respected by PGPKey objects (#99)
 * Multiple signatures can now be validated at once in cases where that makes sense, such as when validating
   self-signatures on keys/user ids (#120)
 * Message signatures can now be verified (#117)
 * Messages can now be encrypted/decrypted using a passphrase (#113)
 * Cleartext messages can now be created and signed (#26)
 * Cleartext messages with inline signatures can now be verified (#27)
 * Messages can now be loaded (#102)
 * Messages can now be compressed (#100)

Other Changes
-------------
 * CRC24 computation is now much faster than previous versions (#68)
 * PGPKey and PGPKeyring APIs have changed significantly (#76)
 * String2Key computation is now much faster than previous versions (#94)
 * key material parts are now stored as integers (or ``long`` on Python 2.x) (#94)

v0.2.3
======

Released: July 31, 2014

PGPy v0.2.3 is a bugfix release

Bugs Fixed
----------
 * Fixed an issue where explicitly selecting a key and then trying to validate with it would erroneously raise an exception as though the wrong key were selected.

v0.2.2
======

Released: July 31, 2014

PGPy v0.2.2 is primarily a bugfix release.

Bugs Fixed
----------
 * Fixed a typo that would cause TypeError to be raised as bytecode was being generated (#85)
 * Fixed an issue where unicode input on Python 2.7 could result in unexpected UnicodeDecodeError exceptions being raised

New Features
------------
 * Switched the main parse loop to use a bytearray instead of slicing a bytes, resulting in a ~160x speedup in parsing large blocks of passing. (#87)

v0.2.1
======

Released: July 31, 2014

PGPy v0.2.1 is primarily a bugfix release.

Bugs Fixed
----------

 * Critical bit on signature subpackets was being ignored, and when set, causing a ValueError to be raised when trying to parse it.
   The critical bit is now being parsed and masked out correctly. (#81)
 * No longer raises exceptions on unrecognized subpackets; instead, it now treats them as opaque.
 * No longer raises exceptions on unrecognized packets; instead, it now treats them as opaque.
   This also applies to signature and key packets with versions other than v4.
 * Fixed an issue where a User ID packet that lacked both a comment and an email address was failing to be found by the uid regex in KeyCollection.
 * Fixed an issue where an old-format packet header with a length_type set longer than needed was resulting in the packet getting truncated.
 * Fixed an issue where parsing a subpacket with a 2-byte length was erroneously being parsed as a 5-byte length.
 * Fixed an issue where parsing a subpacket with a 5-byte length where the value was < 8434 was causing an error
 * Fixed an issue where a packet or subpacket reporting a value marked reserved in RFC 4880 would cause ValueError to be raised during parsing.
 * Key material marked as public key algorithm 20 (Reserved - Formerly ElGamal Encrypt or Sign) is now parsed as ElGamal key material.
 * Fixed an issue where parsing a new-format packet header length where the first octet was 223 was erroneously reported as being malformed.

New Features
------------
 * Added support for parsing the 'Preferred Key Server' signature subpacket
 * Added support for loading unsupported or unrecognized signature subpackets.
 * Added support for loading unsupported or unrecognized packets.

v0.2.0
======

Released: July 20, 2014

Starting with v0.2.0, PGPy is now using the BSD 3-Clause license. v0.1.0 used the MIT license.

New Features
------------

 * Subkeys can now be accessed and used for actions supported by PGPKeyring (#67)
 * DSA:

   - Signing of binary documents now works (#16)
   - Verification of signatures of binary documents now works (#15)

 * Can now decrypt secret key material that was encrypted using:

   - Camellia128 (#36)
   - Camellia192 (#37)
   - Camellia256 (#38)
   - AES128 (#32)
   - AES192 (#33)
   - AES256 (#34)
   - Blowfish (#31)
   - Triple-DES (#30)
   - IDEA (#29)

 * PGP packets generated by PGPy now exclusively use new-style header lengths (#47)
 * GPG Trust Packets are now understood and fully parsed (#14)
 * Lots more packet types are now fully parsed

Known Issues
------------

 * Signing with 1024-bit DSA keys does not work with OpenSSL 0.9.8 (#48) - this primarily affects Mac OS X.
 * Verifying signatures signed with any DSA key length other than 2048-bits does not work with OpenSSL 0.9.8 -
   this primarily affects Mac OS X.

Bugs Fixed
----------

 * PGP blocks loaded from ASCII armored blocks now retain their ASCII headers (#54)
 * PGP new-style packet headers were not being properly parsed in all cases
 * Many unit test enhancements

v0.1.0
======

Released: May 02, 2014

 * Initial release.
