""" keys.py

"""
import collections
import contextlib
import hashlib
import functools
import math

from cryptography.hazmat.primitives.asymmetric import rsa, dsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

from .pgp import PGPLoad, PGPSignature
from .signature import SignatureVerification
from .errors import PGPError
from .packet import PubKeyAlgo
from .util import bytes_to_int, int_to_bytes, modinv, asn1_seqint_to_tuple


class Managed(object):
    def __init__(self, selection_required=False, pubonly=False, privonly=False):
        self.required = selection_required
        self.pubonly = pubonly
        self.privonly = privonly

    def __call__(self, fn):
        @functools.wraps(fn)
        def decorated(iself, *args, **kwargs):
            if not iself.ctx:
                raise PGPError("Invalid usage - this method must be invoked from a context managed state!")

            if self.required and iself.using is None:
                raise PGPError("Must select a loaded key!")

            if self.required and iself.using not in iself.keyids:
                raise PGPError("Key {keyid} is not loaded!".format(keyid=iself.using))

            if self.pubonly and iself.using is not None and iself.using not in iself.pubkeyids:
                raise PGPError("Key {keyid} is not loaded!".format(keyid=iself.using))

            if self.privonly and iself.using is not None and iself.using not in iself.pubkeyids:
                raise PGPError("Key {keyid} is not loaded!".format(keyid=iself.using))

            return fn(iself, *args, **kwargs)

        return decorated


# just an alias; nothing to see here
managed = Managed


class PGPKeyring(object):
    """
    PGPKeyring objects represent in-memory keyrings.

    :param keys:
        Accepts None, a path, URL, file-like object, or byte-string containing ASCII or binary encoded PGP/GPG keys.
        Can also accept a list of any of the above types, or combination therein.
    :type keys:
        str, bytes, file-like object, list, None

    """

    @property
    def packets(self):
        if self.using is None:
            return [ pkt for keys in list(self.pubkeys.values()) + list(self.seckeys.values()) for pkt in keys.packets ]

        raise NotImplementedError()  # pragma: no cover

    @property
    def publickeys(self):
        return list(self.pubkeys.values())

    @property
    def privatekeys(self):
        return list(self.seckeys.values())

    @property
    def keys(self):
        return self.publickeys + self.privatekeys

    @property
    def pubkeyids(self):
        return list(self.pubkeys.keys())

    @property
    def privkeyids(self):
        return list(self.seckeys.keys())

    @property
    def keyids(self):
        return list(set(self.pubkeyids + self.privkeyids))

    @property
    def pubkeyfingerprints(self):
        return [ k.fingerprint for k in self.publickeys ]

    @property
    def privkeyfingerprints(self):
        return [ k.fingerprint for k in self.privatekeys ]

    @property
    def keyfingerprints(self):
        return list(set(self.pubkeyfingerprints + self.privkeyfingerprints))

    @property
    def selected_pubkey(self):
        return self.pubkeys[self.using]

    @property
    def selected_privkey(self):
        return self.seckeys[self.using]

    def __init__(self, keys=None):
        self.pubkeys = collections.OrderedDict()
        self.seckeys = collections.OrderedDict()

        self.using = None
        self.ctx = False

        if keys is not None:
            self.load(keys)

    def __bytes__(self):
        if self.using is None:
            return b''.join(k.__bytes__() for k in list(self.pubkeys.values()) + list(self.seckeys.values()))

    def load(self, keys):
        """
        :param keys:
            Accepts a path, URL, file-like object, or byte-string containing ASCII or binary encoded PGP/GPG keys.
            Can also accept a list of any of the above types, or combination therein.
        :type keys:
            str, bytes, file-like object, list

        """
        ##TODO: type-check keys
        # create one or more PGPKey objects in self.keys
        if type(keys) is not list:
            keys = [keys]

        for key in keys:
            # load the key (or keys) using PGPLoad
            kb = PGPLoad(key)

            for k in kb:
                if k.secret:
                    self.seckeys[k.keyid] = k

                else:
                    self.pubkeys[k.keyid] = k

    @contextlib.contextmanager
    def key(self, id=None):
        """
        Context manager method. Select a key to use in the context managed block::

            k = pgpy.PGPKeyring([os.environ['HOME'] + '/.gnupg/pubring.gpg', os.environ['HOME'] + '/.gnupg/secring.gpg'])
            with k.key('DEADBEEF'):
                # do things with that key here

        :param str id:
            Specify a Key ID to use. This can be an 8 or 16 hex digit key ID, or a full key fingerprint, with or without spaces.
            Specifying no key (or None) is acceptable for key verification.
        :raises:
            :py:exc:`~pgpy.errors.PGPError` is raised if the key specified is not loaded.

        """
        if id is not None:
            # half-key-id
            if len(id) == 8:
                keyids = {key.keyid[-8:]: key.keyid for key in self.keys}

            # key-id
            if len(id) == 16:
                keyids = {key.keyid: key.keyid for key in self.keys}

            # signature, with or without spaces
            if len(id) >= 40:
                keyids = {key.fingerprint: key.keyid for key in self.keys}
                id = id.replace(' ', '')

            if id not in keyids.keys():
                raise PGPError("Key {keyid} not loaded".format(keyid=id))

            self.using = keyids[id]
        self.ctx = True
        yield

        # erase decrypted key material here (if any)
        for dekey in [ key for key in self.privatekeys if key.encrypted ]:
            dekey.undecrypt_keymaterial()
        self.using = None
        self.ctx = False

    @managed(selection_required=True, privonly=True)
    def unlock(self, passphrase):
        """
        Decrypt encryted key material in a protected private key::

            k = pgpy.PGPKeyring([os.environ['HOME'] + '/.gnupg/pubring.gpg', os.environ['HOME'] + '/.gnupg/secring.gpg'])
            with k.key('DEADBEEF'):
                k.unlock('Dead Beef')
                # now that the private key is unlocked, use it for things

        :param str passphrase:
            The passphrase used to decrypt the encrypted private key material.
        :raises:
            :py:exc:`~pgpy.errors.PGPError` if the key specified is not encrypted
        :raises:
            :py:exc:`~pgpy.errors.PGPKeyDecryptionError` if the passphrase was incorrect

        """
        # we shouldn't try this if the key isn't encrypted
        if not self.selected_privkey.encrypted:
            raise PGPError("Key {keyid} is not encrypted".format(keyid=self.using))

        self.selected_privkey.decrypt_keymaterial(passphrase)

    @managed(selection_required=True, privonly=True)
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
            str, bytes, file-like object
        :return:
            newly created signature of the specified document.
        :rtype:
            :py:obj:`~pgpy.pgp.PGPSignature`
        :raises:
            :py:exc:`NotImplementedError` if the selected key is not an RSA key

        """
        # if the key material was encrypted, did we decrypt it yet?
        if self.selected_privkey.encrypted and self.selected_privkey.keypkt.key_material.privempty:
            raise PGPError("The selected key is not unlocked!")

        # alright, we have a key selected at this point, let's load it into cryptography
        if self.selected_privkey.keypkt.key_algorithm == PubKeyAlgo.RSAEncryptOrSign:
            km = self.selected_privkey.keypkt.key_material
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

        elif self.selected_privkey.keypkt.key_algorithm == PubKeyAlgo.DSA:
            km = self.selected_privkey.keypkt.key_material
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
            raise NotImplementedError(self.selected_privkey.keypkt.key_algorithm.name)

        # create a new PGPSignature object
        sig = PGPSignature.new(self.using, alg=self.selected_privkey.keypkt.key_algorithm)

        # get our full hash data
        data = sig.hashdata(subject)

        # set the hash2 field
        sig.packets[0].hash2 = hashlib.new('sha256', data).digest()[:2]

        # finally, sign the data and load the signature into sig
        signer.update(data)
        s = signer.finalize()

        if self.selected_privkey.keypkt.key_algorithm == PubKeyAlgo.RSAEncryptOrSign:
            sf = int_to_bytes(bytes_to_int(s).bit_length(), 2) + s
            sig.packets[0].signature.parse(sf, sig.packets[0].header.tag, sig.packets[0].key_algorithm)

        elif self.selected_privkey.keypkt.key_algorithm == PubKeyAlgo.DSA:
            sf = asn1_seqint_to_tuple(s)
            sig.packets[0].signature.parse(
                int_to_bytes(sf[0].bit_length(), 2) + int_to_bytes(sf[0]) +
                int_to_bytes(sf[1].bit_length(), 2) + int_to_bytes(sf[1]),
                sig.packets[0].header.tag,
                sig.packets[0].key_algorithm
            )

        else:
            raise NotImplementedError(self.selected_privkey.keypkt.key_algorithm.name)

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

    @managed(pubonly=True)
    def verify(self, subject, signature):
        """
        Verify the integrity of something using its signature and a loaded public key::

            k = pgpy.PGPKeyring([os.environ['HOME'] + '/.gnupg/pubring.gpg', os.environ['HOME'] + '/.gnupg/secring.gpg'])
            with k.key():
                sv = k.verify('path/to/an/unsigned/document', 'path/to/signature')
                if sv:
                    print('Signature verified with {key}'.format(key=sv.key.keyid)

        :param subject:
            Accepts a path, URL, file-like object, or byte-string containing the thing you would like to verify
        :type subject:
            str, bytes, file-like object
        :param signature:
            Accepts a path, URL, file-like object, or byte-string containing the signature of the thing you would like to verify
        :type signature:
            str, bytes, file-like object
        :return:
            indicating whether or not the signature verified.
        :rtype:
            :py:obj:`~pgpy.signature.SignatureVerification`

        """
        ##TODO: type-checking
        sig = PGPLoad(signature)[0]
        sigdata = sig.hashdata(subject)

        sigv = SignatureVerification()
        sigv.signature = sig
        sigv.subject = subject

        # check to see if we have the public key half of the key that created the signature
        skeyid = sig.sigpkt.unhashed_subpackets.Issuer.payload.decode()
        if self.using is not None and skeyid != self.using:
            raise PGPError("Key {skeyid} is not selected!".format(skeyid=skeyid))

        if skeyid not in [key.keyid for key in self.publickeys]:
            raise PGPError("Public key {skeyid} is not loaded!".format(skeyid=skeyid))

        pubkey = self.pubkeys[skeyid]
        sigv.key = pubkey

        # first check - compare the left 16 bits of sh against the signature packet's hash2 field
        dhash = hashlib.new(sig.sigpkt.hash_algorithm.name, sigdata)

        if dhash.digest()[:2] == sig.sigpkt.hash2:
            # the quick check passed; now we should do an actual signature verification

            # create the verifier
            if sig.sigpkt.key_algorithm == PubKeyAlgo.RSAEncryptOrSign:
                # public key components
                e = bytes_to_int(pubkey.keypkt.key_material.e['bytes'])
                n = bytes_to_int(pubkey.keypkt.key_material.n['bytes'])
                # signature
                s = sig.sigpkt.signature.md_mod_n['bytes']

                # public key object and verifier
                pk = rsa.RSAPublicKey(e, n)
                verifier = pk.verifier(s, padding.PKCS1v15(), sig.sigpkt.hash_algorithm.hasher, default_backend())

            elif sig.sigpkt.key_algorithm == PubKeyAlgo.DSA:
                # public key components
                p = bytes_to_int(pubkey.keypkt.key_material.p['bytes'])
                q = bytes_to_int(pubkey.keypkt.key_material.q['bytes'])
                g = bytes_to_int(pubkey.keypkt.key_material.g['bytes'])
                y = bytes_to_int(pubkey.keypkt.key_material.y['bytes'])
                # signature
                s = sig.sigpkt.signature.as_asn1_der

                # public key object
                pk = dsa.DSAPublicKey(
                    modulus=p,
                    subgroup_order=q,
                    generator=g,
                    y=y
                )
                verifier = pk.verifier(s, sig.sigpkt.hash_algorithm.hasher, default_backend())

            else:
                raise NotImplementedError(sig.sigpkt.key_algorithm)

            # now verify!
            verifier.update(sigdata)

            try:
                verifier.verify()
                sigv.verified = True

            except InvalidSignature:
                # signature verification failed; nothing more to do.
                pass

        return sigv
