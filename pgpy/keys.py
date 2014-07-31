""" keys.py
"""
import collections
import contextlib
import functools
import hashlib
import math
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, padding, rsa

from .packet.packets import PrivKey
from .packet.packets import PubKey
from .packet.packets import UserID
from .packet.types import PubKeyAlgo

from .errors import PGPError
from .pgp import pgpload
from .pgp import PGPKey
from .pgp import PGPSignature
from .types import SignatureVerification
from .util import asn1_seqint_to_tuple
from .util import bytes_to_int
from .util import int_to_bytes
from .util import modinv


class Managed(object):
    def __init__(self, selection_required=False, pub_required=False, priv_required=False):
        self.required = selection_required
        self.pub_required = pub_required
        self.priv_required = priv_required

    def __call__(self, fn):
        @functools.wraps(fn)
        def decorated(iself, *args, **kwargs):
            if not iself.ctx:
                raise PGPError("Invalid usage - this method must be invoked from a context managed state!")

            if self.required:
                if iself.using is None:
                    raise PGPError("Must select a loaded key!")

                if iself.using not in iself._keys:
                    raise PGPError("Key {keyid} is not loaded!".format(keyid=iself.using))

            if self.pub_required and iself.using is not None and iself.selected.pubkey is None:
                raise PGPError("Public Key {keyid} is not loaded!".format(keyid=iself.using))

            if self.priv_required and iself.using is not None and iself.selected.privkey is None:
                raise PGPError("Private Key {keyid} is not loaded!".format(keyid=iself.using))

            return fn(iself, *args, **kwargs)

        return decorated


# just an alias; nothing to see here
managed = Managed


class KeyCollection(collections.MutableMapping):
    """
    A many-to-one addressable mapping for public and private PGP keys.
    """

    KeyPair = collections.namedtuple('KeyPair', ['pubkey', 'privkey'])

    class _UserName(str):
        pass

    class _UserComment(str):
        pass

    class _UserEmail(str):
        pass

    class _Fingerprint(str):
        @property
        def keyid(self):
            return KeyCollection._KeyID(self.replace(' ', '')[-16:])

        @property
        def shortid(self):
            return KeyCollection._ShortID(self.replace(' ', '')[-8:])

        def __new__(cls, content):
            # validate input before continuing: this should be a string of 40 hex digits
            content = content.upper().replace(' ', '')
            if len(content) != 40 or (not bool(re.match(r'^[A-Z0-9]+$', content))):
                raise ValueError("Expected: String of 40 hex digits")  # pragma: no cover

            # store in the format: "AAAA BBBB CCCC DDDD EEEE  FFFF 0000 1111 2222 3333"
            content = ''.join([ j for i in zip([ content[x:(x + 4)] for x in range(0, 40, 4) ],
                                               [' '] * 4 + ['  '] + [' '] * 5) for j in i ][:-1])
            return str.__new__(cls, content)

        def __eq__(self, other):
            other = str(other).replace(' ', '')

            if self.replace(' ', '') == other:
                return True

            if self.keyid == other:
                return True  # pragma: no cover

            if self.shortid == other:
                return True  # pragma: no cover

            return False

        def __hash__(self):
            return hash(str(self))

    class _KeyID(str):
        def __new__(cls, content):
            # validate input before continuing: this should be a string of 16 hex digits
            content = content.upper().replace(' ', '')
            if len(content) != 16 or (not bool(re.match(r'^[A-Z0-9]+$', content))):
                raise ValueError("Expected: String of 16 hex digits")  # pragma: no cover

            return str.__new__(cls, content)

        def __eq__(self, other):
            # case-insensitive matching
            return hash(self) == hash(str(other))

        def __hash__(self):
            return hash(str(self))

    class _ShortID(str):
        def __new__(cls, content):
            # validate input before continuing: this should be a string of 8 hex digits
            content = content.upper().replace(' ', '')
            if len(content) != 8 or (not bool(re.match(r'^[A-Z0-9]+$', content))):
                raise ValueError("Expected: String of 8 hex digits")  # pragma: no cover

            return str.__new__(cls, content)

        def __eq__(self, other):
            # case-insensitive matching
            return hash(self) == hash(str(other))

        def __hash__(self):
            return hash(str(self))

    @property
    def __pubkeys__(self):
        """
        :return: a ValuesView of public keys
        """
        return collections.ValuesView(self._pubkeys)

    @property
    def __privkeys__(self):
        """
        :return: a ValuesView of private keys
        """
        return collections.ValuesView(self._privkeys)

    # @property
    # def __userids__(self):
    #     """
    #     :return: a KeysView of user ids which includes (Name, Email, Comment)
    #     """
    #     pass

    @property
    def __fingerprints__(self):
        """
        :return: an iterable of fingerprints
        """
        for fp in self._aliases.keys():
            if isinstance(fp, KeyCollection._Fingerprint):
                yield fp

    @property
    def __keyids__(self):
        """
        :return: an iterable of key ids
        """
        for kid in self._aliases.keys():
            if isinstance(kid, KeyCollection._KeyID):
                yield kid

    @property
    def __shortids__(self):
        """
        :return: an iterable of short (8-digit) key ids
        """
        for sid in self._aliases.keys():
            if isinstance(sid, KeyCollection._ShortID):
                yield sid

    def __init__(self):
        self._pubkeys = collections.OrderedDict()  # {fingerprint: }
        self._privkeys = collections.OrderedDict()  # {fingerprint: }
        self._aliases = {}  # {alias: fingerprint}

    def __getitem__(self, key):
        """
        :param key: Fingerprint, Key ID, Short ID, or User ID component of a key in the collection
        :return: The PubKey, PubSubKey, PrivKey, or PrivSubKey that corresponds to the key requested
        """
        fp = self._aliases[key]
        pubkeys = [ k for k in self._pubkeys[fp].keypkts if fp == k.fingerprint ] if fp in self._pubkeys else [None]
        privkeys = [ k for k in self._privkeys[fp].keypkts if fp == k.fingerprint ] if fp in self._privkeys else [None]

        return KeyCollection.KeyPair(pubkey=pubkeys[0], privkey=privkeys[0])

    def __setitem__(self, key, value):
        # sanity check
        if key != value.primarykey.fingerprint:
            raise KeyError("key should be the fingerprint of the primary key in the PGPKey object provided")

        if not isinstance(value, PGPKey):
            raise ValueError("Unexpected value of type {} - should be a PGPKey".format(type(value)))

        key = KeyCollection._Fingerprint(key)

        # add the key to the correct substore
        if isinstance(value.primarykey, PubKey):
            self._pubkeys[key] = value

        if isinstance(value.primarykey, PrivKey):
            self._privkeys[key] = value

        # update self._aliases if necessary
        if key not in self._aliases.values():
            # user ids
            for uid in [ pkt for pkt in value.packets if isinstance(pkt, UserID) ]:
                # this new regex now always at least matches the name field
                # and optionally matches a comment
                # and optionally matches an email (which must always be last if it exists)
                uid_reg = r'^(?P<name>[^\(<]*)' \
                          r'( \()?(?(2)(?P<comment>.*)\))' \
                          r'( <)?(?(4)(?P<email>.*)>)$'
                uidm = re.match(uid_reg, uid.data.decode()).groupdict()

                if uidm['name'] is not None:
                    self._aliases[KeyCollection._UserName(uidm['name'])] = key

                if uidm['comment'] is not None:
                    self._aliases[KeyCollection._UserComment(uidm['comment'])] = key

                if uidm['email'] is not None:
                    self._aliases[KeyCollection._UserEmail(uidm['email'])] = key

            # primary key and subkey fingerprints
            for kp in value.keypkts:
                k = KeyCollection._Fingerprint(kp.fingerprint)
                self._aliases[k] = key  # fingerprint with spaces
                self._aliases[k.replace(' ', '')] = key  # fingerprint without spaces
                self._aliases[k.keyid] = key  # keyid
                self._aliases[k.shortid] = key  # short keyid

    def __delitem__(self, key):
        if key not in self._aliases.keys():
            raise KeyError("{} not present".format(key))

        # delete the key(pair) itself and then update the aliases dict
        # del self._keys[self._aliases[key]]
        if self._aliases[key] in self._pubkeys:
            del self._pubkeys[self._aliases[key]]

        if self._aliases[key] in self._privkeys:
            del self._privkeys[self._aliases[key]]

        self._aliases = { k: v for k, v in self._aliases.items if
                          v not in self._pubkeys.keys() or
                          v not in self._privkeys.keys() }

    def __iter__(self):
        pass  # pragma: no cover

    def __len__(self):
        return len([ fp for fp in self._aliases if isinstance(fp, KeyCollection._Fingerprint) ])

    def __contains__(self, key):
        return key in self._aliases.keys()

    def add(self, pgpkey):
        """
        Add a PGPKey object representing a PGP KEY BLOCK to this mapping
        :param pgpkey: a PGPKey object
        :raises TypeError: if pgpkey is not a PGPKey object
        """
        if not isinstance(pgpkey, PGPKey):
            raise TypeError("Unexpected Type: {}".format(type(pgpkey)))

        fp = pgpkey.primarykey.fingerprint

        self[fp] = pgpkey

    def get_pgpkey(self, key):
        """
        :param key: Fingerprint, Key ID, Short ID, or User ID component of a key in the collection
        :return: A namedtuple containing the private, public, or both PGPKey blocks
        """
        # return self._keys[self._aliases[key]]
        k = self._aliases[key]
        return KeyCollection.KeyPair(pubkey=self._pubkeys[k] if k in self._pubkeys else None,
                                     privkey=self._privkeys[k] if k in self._privkeys else None)

    def index(self, key):
        if key not in self._aliases.keys():
            raise KeyError("{} not present".format(key))

        return self._aliases[key]


class PGPKeyring(object):
    """
    PGPKeyring objects represent in-memory keyrings.

    .. seealso::

        :py:meth:`~pgpy.PGPKeyring.load` for parameters

    """

    @property
    def __pubkeys__(self):
        return self._keys.__pubkeys__

    @property
    def __privkeys__(self):
        return self._keys.__privkeys__

    @property
    def __fingerprints__(self):
        return self._keys.__fingerprints__

    @property
    @managed(selection_required=True)
    def selected(self):
        return self._keys[self.using] if self.using else None

    def __init__(self, *args):
        self._keys = KeyCollection()

        self.using = None
        self.ctx = False

        self.load(*args)

    def __bytes__(self):
        # return all the public key bytes, followed by the private key bytes
        _b = ""
        _b += b''.join(key.__bytes__() for key in self._keys.__pubkeys__)
        _b += b''.join(key.__bytes__() for key in self._keys.__privkeys__)
        return _b

    def load(self, *args):
        """
        :param \*args: Zero or more of the following:

                * ``None``
                * a valid path
                * a valid URL
                * a file-like object
                * a byte-string containing ASCII or binary encoded PGP/GPG keys.
                * a list comprised of any combination of the above

        :type \*args:
            ``str``, ``bytes``, file-like-object, ``list``, ``None``

        .. note::

                The type for each argument is determined using the following methodology:

                    1. ``None`` is ignored

                    2. If the object has a ``read()`` method:

                        - it is considered to be file-like
                        - the ``read()`` method is invoked
                        - the output of that is converted to ``bytes`` and that is then parsed

                    3. If the object is of type ``str``:

                        - It is considered to be a local file path if it:

                            - appears to be a relative or absolute path
                            - does not contain any non-printable or newline (\\n) characters
                            - the path exists and is a file

                        - It is loaded directly if it contains a valid ASCII PGP KEY BLOCK

                    4. If the object is of type ``bytes``:

                        - It is loaded directly if it contains:

                            - a valid ASCII PGP KEY BLOCK
                            - a valid binary PGP Key blob

        :raises:
            If one or more of the inputs is an invalid path:

             - :py:exc:`FileNotFoundError` if Python >= 3.3

             - :py:exc:`IOError` if Python <= 3.2

        :raises:
            :py:exc:`TypeError` if the input type cannot be determined by the file loader

        :raises:
            :py:exc:`~pgpy.exc.PGPError` if one or more keys being loaded was not a PGP key.

        """
        # recurse inputs as this is expected to be sometimes non-uniform
        def _load_keys(input):
            if type(input) is list:
                for item in input:
                    _load_keys(item)

            elif input is None:
                return

            else:
                # try to load
                kb = pgpload(input)

                for k in kb:
                    if not isinstance(k, PGPKey):
                        raise PGPError("Expected: PGPKey")

                    self._keys.add(k)

        _load_keys(list(args))

    @contextlib.contextmanager
    def key(self, fp=None):
        """
        Context manager method. Select a key to use in the context managed block::

            k = pgpy.PGPKeyring([os.environ['HOME'] + '/.gnupg/pubring.gpg', os.environ['HOME'] + '/.gnupg/secring.gpg'])
            with k.key('DEADBEEF'):
                # do things with that key here
                ...

        .. versionadded:: 0.2.0
           subkeys can now be selected by fingerprint or ID

        :param str id:
            Specify a Key ID to use. This can be:
                - 8 hex-digit key ID
                - 16 hex-digit key ID
                - 40 hex-digit key fingerprint, with or without spaces
                - User ID Name
                - User ID Email
                - User ID Comment

            Specifying no key (or ``None``) is acceptable for signature verification.

        :raises:
            :py:exc:`~pgpy.errors.PGPError` is raised if the key specified is not loaded.

        """
        # store the current state
        _ctx = self.ctx
        _using = self.using

        if fp is not None:
            if fp in self._keys:
                self.using = self._keys.index(fp)

            else:
                raise PGPError("Key {input} not loaded".format(input=fp))  # pragma: no cover

        self.ctx = True

        # trap exceptions raised while in the context managed state momentarily so cleanup is ensured
        # even when an exception is raised
        try:
            yield self

        finally:
            # destroy all decrypted secret key material here (if any) if it was encrypted when loaded
            for dekey in [ dekey for key in self._keys.__privkeys__ for dekey in key.keypkts ]:
                dekey.undecrypt_keymaterial()

            # now restore the previous state
            self.ctx = _ctx
            self.using = _using

    @managed(selection_required=True)
    def export_key(self, pub=True, priv=False):
        """
        .. versionadded:: 0.2.0

        Export the selected PGP Key(s) of the type(s) requested.
        If a subkey is selected, the entire key block that it belongs to is exported.

        Example::

            k = pgpy.PGPKeyring([os.environ['HOME'] + '/.gnupg/pubring.gpg', os.environ['HOME'] + '/.gnupg/secring.gpg'])
            with k.key("0FF1CECAFED00D"):
                with open("office_cafe_dude.asc", 'w') as keyfile:
                    keyfile.write(str(k.export_key().pubkey))

        :param bool pub=True: Export public key
        :param bool priv=False: Export private key
        :return:
            A namedtuple with two attributes: pubkey and privkey.
            The attribute(s), if requested and loaded, will be of type :py:obj:`~pgpy.pgp.PGPKey`
            If one of the two types is not requested, or the requested type is not loaded, that attribute will be ``None``.

        """

        return KeyCollection.KeyPair(pubkey=self._keys.get_pgpkey(self.using).pubkey if pub else None,
                                     privkey=self._keys.get_pgpkey(self.using).privkey if priv else None)

    @managed(selection_required=True, priv_required=True)
    def unlock(self, passphrase):
        """
        Decrypt encryted key material in a protected private key::

            k = pgpy.PGPKeyring([os.environ['HOME'] + '/.gnupg/pubring.gpg', os.environ['HOME'] + '/.gnupg/secring.gpg'])
            with k.key('DEADBEEF'):
                k.unlock('Dead Beef')
                # now that the private key is unlocked, use it for things

        .. versionadded: 0.2.0
           Subkeys can now be unlocked

        :param str passphrase:
            The passphrase used to decrypt the encrypted private key material.

        :raises:
            :py:exc:`~pgpy.errors.PGPError` if the key specified is not encrypted

        :raises:
            :py:exc:`~pgpy.errors.PGPKeyDecryptionError` if the passphrase was incorrect

        :raises:
            :py:exc:`~pgpy.errors.PGPOpenSSLCipherNotSupported` if the OpenSSL currently installed does not support
            the symmetric key cipher required to decrypt the selected secret key material.

        """
        # we shouldn't try this if the key isn't encrypted
        if not self.selected.privkey.encrypted:
            raise PGPError("Key {keyid} is not encrypted".format(keyid=self.using))  # pragma: no cover

        self.selected.privkey.decrypt_keymaterial(passphrase)

    @managed(selection_required=True, priv_required=True)
    def sign(self, subject, inline=False):
        """
        sign(self, subject)

        Sign a document using the selected private key::

            k = pgpy.PGPKeyring([os.environ['HOME'] + '/.gnupg/pubring.gpg', os.environ['HOME'] + '/.gnupg/secring.gpg'])
            with k.key('DEADBEEF'):
                sig1 = k.sign('This is an unsigned document')
                sig2 = k.sign('path/to/another/unsigned/document')

        :param subject:
            Accepts a path, URL, file-like object, or byte-string containing the thing you would like to sign
        :type subject:
            ``str``, ``bytes``, file-like object

        .. note::

            The ``subject`` parameter functions identically to arguments supplied to :py:meth:`~pgpy.PGPKeyring.load`
            except for how it deals with `bytes` or a `str` with the following considerations:

                - If the ``str`` does not appear to be a path, it is used as-is
                - ``bytes`` input is used directly

        .. note::

            This is generally most useful if the subject is a path to a file on disk, or an object representing
            a file on disk. A signature cannot be verified later if the document it signed no longer exists or is not
            accessible to the application verifying that signature.

        .. note::

            As of PGPy v0.2.0, only detached signatures of binary documents can be generated

        .. note::

            As of PGPy v0.2.0, the default hashing function used by the signer is SHA256, and this cannot yet be changed.
            The ability to select the hashing function to be used is planned for a future release.

        .. warning::

            As of PGPy v0.2.0, :py:obj:`~pgpy.PGPKeyring` does not yet respect key usage flags.
            This is currently planned for the next release.

        .. seealso::

            :py:meth:`pgpy.PGPKeyring.load`

        :return:
            newly created signature of the specified document.
        :rtype:
            :py:obj:`~pgpy.pgp.PGPSignature`
        :raises:
            :py:exc:`NotImplementedError` if the selected key is not an RSA or DSA key

        """
        # if the key material was encrypted, did we decrypt it yet?
        if self.selected.privkey.encrypted and self.selected.privkey.key_material.privempty:
            raise PGPError("The selected key is not unlocked!")

        ##TODO: if the selected key is a primary key and does not have the signing flag set,
        ##      but one or more of its subkeys does, reselect the first eligible subkey
        ##TODO: if the selected key or subkey does not have the signing flag set, raise an error

        ##TODO: type-check subject

        # alright, we have a key selected at this point, let's load it into cryptography
        if self.selected.privkey.key_algorithm == PubKeyAlgo.RSAEncryptOrSign:
            km = self.selected.privkey.key_material
            p = bytes_to_int(km.p['bytes'])
            q = bytes_to_int(km.q['bytes'])
            d = bytes_to_int(km.d['bytes'])
            pk = rsa.RSAPrivateKey(
                p=p,
                q=q,
                private_exponent=d,
                dmp1=d % (p - 1),
                dmq1=d % (q - 1),
                iqmp=modinv(p, q),
                public_exponent=bytes_to_int(km.e['bytes']),
                modulus=bytes_to_int(km.n['bytes'])
            )

            ##TODO: select the hash algorithm
            signer = pk.signer(padding.PKCS1v15(), hashes.SHA256(), default_backend())

        elif self.selected.privkey.key_algorithm == PubKeyAlgo.DSA:
            km = self.selected.privkey.key_material
            p = bytes_to_int(km.p['bytes'])
            q = bytes_to_int(km.q['bytes'])
            g = bytes_to_int(km.g['bytes'])
            y = bytes_to_int(km.y['bytes'])
            x = bytes_to_int(km.x['bytes'])
            pk = dsa.DSAPrivateKey(
                modulus=p,
                subgroup_order=q,
                generator=g,
                x=x,
                y=y
            )

            ##TODO: select the hash algorithm
            signer = pk.signer(hashes.SHA256(), default_backend())

        else:
            raise NotImplementedError(self.selected.privkey.key_algorithm.name)  # pragma: no cover

        # create a new PGPSignature object
        sig = PGPSignature.new(self.using.keyid, alg=self.selected.privkey.key_algorithm)

        # get our full hash data
        data = sig.hashdata(subject)

        # set the hash2 field
        sig.packets[0].hash2 = hashlib.new('sha256', data).digest()[:2]

        # finally, sign the data and load the signature into sig
        signer.update(data)
        s = signer.finalize()

        if self.selected.privkey.key_algorithm == PubKeyAlgo.RSAEncryptOrSign:
            siglen = bytes_to_int(s).bit_length()
            sf = int_to_bytes(siglen, 2) + s[-1 * ((siglen + 7) // 8):]  # truncate leading nul bytes with math
            sig.packets[0].signature.parse(sf, sig.packets[0].header.tag, sig.packets[0].key_algorithm)

        elif self.selected.privkey.key_algorithm == PubKeyAlgo.DSA:
            sf = asn1_seqint_to_tuple(s)
            sig.packets[0].signature.parse(
                int_to_bytes(sf[0].bit_length(), 2) +
                int_to_bytes(sf[0]) +
                int_to_bytes(sf[1].bit_length(), 2) +
                int_to_bytes(sf[1]),
                sig.packets[0].header.tag,
                sig.packets[0].key_algorithm
            )

        else:
            raise NotImplementedError(self.selected.privkey.key_algorithm.name)  # pragma: no cover

        # set the signature header length stuff
        ##TODO: this probably shouldn't have to happen here
        pktlen = len(sig.packets[0].__bytes__()) - len(sig.packets[0].header.__bytes__())
        ltype = \
            0 if math.ceil(pktlen.bit_length() / 8.0) == 1 else \
            1 if math.ceil(pktlen.bit_length() / 8.0) == 2 else \
            2 if math.ceil(pktlen.bit_length() / 8.0) < 5 else 3

        sig.packets[0].header.length_type = ltype
        sig.packets[0].header.length = pktlen
        ##TODO: get rid of this when PGPBlock.crc24() works on the output of its __bytes__() method
        sig.data = sig.__bytes__()

        return sig

    @managed(pub_required=True)
    def verify(self, subject, signature):
        """
        Verify the integrity of something using its signature and a loaded public key::

            k = pgpy.PGPKeyring([os.environ['HOME'] + '/.gnupg/pubring.gpg', os.environ['HOME'] + '/.gnupg/secring.gpg'])
            with k.key():
                sv = k.verify('path/to/an/unsigned/document', 'path/to/signature')
                if sv:
                    print('Signature verified with {key}'.format(sv.key.fingerprint))

        :param subject:
            See :py:meth:`~pgpy.PGPKeyring.sign`

        :type subject:
            ``str``, ``bytes``, file-like object

        :param signature:
            Accepts a path, URL, file-like object, byte-string, or :py:obj:`~pgpy.pgp.PGPSignature`
            containing the signature of the document you would like to verify.

        :type signature:
            ``str``, ``bytes``, file-like object, :py:obj:`~pgpy.pgp.PGPSignature`

        :return: :py:obj:`~pgpy.types.SignatureVerification` object indicating whether or not the signature verified.


        """
        ##TODO: more type-checking
        if not isinstance(signature, PGPSignature):
            sig = pgpload(signature)[0]

        else:
            sig = signature

        sigdata = sig.hashdata(subject)

        sigv = SignatureVerification()
        sigv.signature = sig
        sigv.subject = subject

        # check to see if we have the public key half of the key that created the signature
        skeyid = sig.sigpkt.unhashed_subpackets.issuer.payload.decode()

        # is the key used to create this signature loaded?
        if skeyid not in self._keys or self._keys[skeyid].pubkey is None:
            raise PGPError("Key {key} is not loaded!".format(key=self.using if self.using is not None else skeyid))

        # respect the selected key, even if it's not the one that was used to generate the signature to be verified
        if self.using is not None and (not self.using == skeyid):
            raise PGPError("Wrong key selected")

        # if we get to this point, it should be safe to assume that the requested public key is loaded
        if self.using is None:
            sigv.key = pubkey = self._keys[skeyid].pubkey

        else:
            sigv.key = pubkey = self.selected.pubkey

        # first check - compare the left 16 bits of sh against the signature packet's hash2 field
        dhash = hashlib.new(sig.sigpkt.hash_algorithm.name, sigdata)

        if dhash.digest()[:2] == sig.sigpkt.hash2:
            # the quick check passed; now we should do an actual signature verification

            # create the verifier
            if sig.sigpkt.key_algorithm == PubKeyAlgo.RSAEncryptOrSign:
                # public key components
                e = bytes_to_int(pubkey.key_material.e['bytes'])
                n = bytes_to_int(pubkey.key_material.n['bytes'])
                # signature
                s = sig.sigpkt.signature.md_mod_n['bytes']

                # when a signature is generated, it is thesame number of bits long as the key that generated it
                # However, PGP discards null octets at the start of the signature field, counting bits starting from
                # the most significant non-zero bit.
                # So, we may need to zero-pad the signature to the right length for Cryptography/OpenSSL
                while ((pubkey.key_material.n['bitlen'] + 7) // 8) > len(s):
                    s = b'\x00' + s

                # public key object and verifier
                pk = rsa.RSAPublicKey(e, n)
                verifier = pk.verifier(bytes(s), padding.PKCS1v15(), sig.sigpkt.hash_algorithm.hasher, default_backend())

            elif sig.sigpkt.key_algorithm == PubKeyAlgo.DSA:
                # public key components
                p = bytes_to_int(pubkey.key_material.p['bytes'])
                q = bytes_to_int(pubkey.key_material.q['bytes'])
                g = bytes_to_int(pubkey.key_material.g['bytes'])
                y = bytes_to_int(pubkey.key_material.y['bytes'])
                # signature
                s = bytes(sig.sigpkt.signature.as_asn1_der)

                # public key object
                pk = dsa.DSAPublicKey(
                    modulus=p,
                    subgroup_order=q,
                    generator=g,
                    y=y
                )
                verifier = pk.verifier(s, sig.sigpkt.hash_algorithm.hasher, default_backend())

            else:
                raise NotImplementedError(sig.sigpkt.key_algorithm)  # pragma: no cover

            # now verify!
            verifier.update(sigdata)

            try:
                verifier.verify()

            except InvalidSignature:
                # signature verification failed; nothing more to do.
                pass

            else:
                sigv._verified = True

        return sigv
