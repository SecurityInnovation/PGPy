""" key.py

"""
import collections
import contextlib
import hashlib
import functools

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import openssl
from cryptography.exceptions import InvalidSignature

from .pgp import PGPLoad
from .signature import SignatureVerification
from .errors import PGPError
from .packet import PubKeyAlgo
from .util import bytes_to_int


class PGPKeyring(object):
    def managed(func):
        @functools.wraps(func)
        def inner(self, *args, **kwargs):
            if not self.ctx:
                raise PGPError("Invalid usage - this method must be invoked from a context managed state!")

            return func(self, *args, **kwargs)

        return inner

    @property
    def packets(self):
        if self.using is None:
            return [ pkt for keys in list(self.pubkeys.values()) + list(self.seckeys.values()) for pkt in keys.packets ]

        raise NotImplementedError()

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
        if id is not None:
            if id not in [ key.keyid for key in list(self.pubkeys.values()) + list(self.seckeys.values()) ]:
                raise PGPError("Key {keyid} not loaded".format(keyid=id))

        self.using = id
        self.ctx = True
        yield

        self.using = None
        self.ctx = False

    @managed
    def sign(self, subject, inline=False):
        ##TODO: create PGPSignature object
        pass

    @managed
    def verify(self, subject, signature):
        ##TODO: type-checking
        sig = PGPLoad(signature)[0]
        sigdata = sig.hashdata(subject)

        sigv = SignatureVerification()
        sigv.signature = sig
        sigv.subject = subject

        # check to see if we have the public key half of the key that created the signature
        skeyid = sig.sigpkt.unhashed_subpackets.Issuer.payload.decode()
        if self.using is not None and skeyid[-8:] != self.using:
            raise PGPError("Key {skeyid} is not selected!".format(skeyid=skeyid))

        if skeyid not in [key.keyid for key in self.publickeys]:
            raise PGPError("Key {skeyid} is not loaded!".format(skeyid=skeyid))

        pubkey = self.pubkeys[skeyid]
        sigv.key = pubkey

        # first check - compare the left 16 bits of sh against the signature packet's hash2 field
        dhash = hashlib.new(sig.sigpkt.hash_algorithm.name, sigdata)

        if dhash.name == 'SHA1':
            h = hashes.SHA1()

        elif dhash.name == 'SHA256':
            h = hashes.SHA256()

        else:
            raise NotImplementedError(dhash.name)

        if dhash.digest()[:2] == sig.sigpkt.hash2:
            # if this check passes, now we should do an actual signature verification
            sigv.message = "basic hash check passed"

            # create the verifier
            if sig.sigpkt.key_algorithm == PubKeyAlgo.RSAEncryptOrSign:
                # public key components
                e = bytes_to_int(pubkey.keypkt.key_material.fields['e']['bytes'])
                n = bytes_to_int(pubkey.keypkt.key_material.fields['n']['bytes'])
                # signature
                s = sig.sigpkt.signature.fields['md_mod_n']['bytes']

                # public key object
                pk = rsa.RSAPublicKey(e, n)

                verifier = pk.verifier(s, padding.PKCS1v15(), h, openssl.backend)

            else:
                raise NotImplementedError(sig.sigpkt.key_algorithm)

            # now verify!
            verifier.update(sigdata)

            try:
                verifier.verify()
                sigv.verified = True

            except InvalidSignature:
                sigv.message += "; verify() failed"

        return sigv