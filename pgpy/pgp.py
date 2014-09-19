""" pgp.py

this is where the armorable PGP block objects live
"""
import binascii
import bisect
import collections
import contextlib
import itertools
import os
import re
import warnings

import six

from datetime import datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from .errors import PGPError

from .constants import CompressionAlgorithm
from .constants import Features
from .constants import HashAlgorithm
from .constants import KeyFlags
from .constants import KeyServerPreferences
from .constants import PacketTag
from .constants import PubKeyAlgorithm
from .constants import SignatureType
from .constants import SymmetricKeyAlgorithm

from .packet import Key
from .packet import Packet
from .packet import Primary
from .packet import Private
from .packet import Public
from .packet import Sub
from .packet import UserID
from .packet import UserAttribute

from .packet.packets import CompressedData
from .packet.packets import IntegrityProtectedSKEData
from .packet.packets import IntegrityProtectedSKEDataV1
from .packet.packets import LiteralData
from .packet.packets import OnePassSignature
from .packet.packets import OnePassSignatureV3
from .packet.packets import PKESessionKey
from .packet.packets import PKESessionKeyV3
from .packet.packets import Signature
from .packet.packets import SignatureV4
from .packet.packets import SKEData
from .packet.packets import SKESessionKey
from .packet.packets import SKESessionKeyV4

from .packet.types import Opaque

from .types import Exportable
from .types import PGPObject
from .types import SignatureVerification


class PGPKey(PGPObject, Exportable):
    """
    11.1.  Transferable Public Keys

    OpenPGP users may transfer public keys.  The essential elements of a
    transferable public key are as follows:

     - One Public-Key packet

     - Zero or more revocation signatures
     - One or more User ID packets

     - After each User ID packet, zero or more Signature packets
       (certifications)

     - Zero or more User Attribute packets

     - After each User Attribute packet, zero or more Signature packets
       (certifications)

     - Zero or more Subkey packets

     - After each Subkey packet, one Signature packet, plus optionally a
       revocation

    The Public-Key packet occurs first.  Each of the following User ID
    packets provides the identity of the owner of this public key.  If
    there are multiple User ID packets, this corresponds to multiple
    means of identifying the same unique individual user; for example, a
    user may have more than one email address, and construct a User ID
    for each one.

    Immediately following each User ID packet, there are zero or more
    Signature packets.  Each Signature packet is calculated on the
    immediately preceding User ID packet and the initial Public-Key
    packet.  The signature serves to certify the corresponding public key
    and User ID.  In effect, the signer is testifying to his or her
    belief that this public key belongs to the user identified by this
    User ID.

    Within the same section as the User ID packets, there are zero or
    more User Attribute packets.  Like the User ID packets, a User
    Attribute packet is followed by zero or more Signature packets
    calculated on the immediately preceding User Attribute packet and the
    initial Public-Key packet.

    User Attribute packets and User ID packets may be freely intermixed
    in this section, so long as the signatures that follow them are
    maintained on the proper User Attribute or User ID packet.

    After the User ID packet or Attribute packet, there may be zero or
    more Subkey packets.  In general, subkeys are provided in cases where
    the top-level public key is a signature-only key.  However, any V4
    key may have subkeys, and the subkeys may be encryption-only keys,
    signature-only keys, or general-purpose keys.  V3 keys MUST NOT have
    subkeys.

    Each Subkey packet MUST be followed by one Signature packet, which
    should be a subkey binding signature issued by the top-level key.
    For subkeys that can issue signatures, the subkey binding signature
    MUST contain an Embedded Signature subpacket with a primary key
    binding signature (0x19) issued by the subkey on the top-level key.

    Subkey and Key packets may each be followed by a revocation Signature
    packet to indicate that the key is revoked.  Revocation signatures
    are only accepted if they are issued by the key itself, or by a key
    that is authorized to issue revocations via a Revocation Key
    subpacket in a self-signature by the top-level key.

    Transferable public-key packet sequences may be concatenated to allow
    transferring multiple public keys in one operation.

    11.2.  Transferable Secret Keys

    OpenPGP users may transfer secret keys.  The format of a transferable
    secret key is the same as a transferable public key except that
    secret-key and secret-subkey packets are used instead of the public
    key and public-subkey packets.  Implementations SHOULD include self-
    signatures on any user IDs and subkeys, as this allows for a complete
    public key to be automatically extracted from the transferable secret
    key.  Implementations MAY choose to omit the self-signatures,
    especially if a transferable public key accompanies the transferable
    secret key.
    """
    @property
    def __key__(self):
        return self._key.keymaterial

    @property
    def __sig__(self):
        return self.signatures

    @property
    def created(self):
        return self._key.created

    @property
    def cipherprefs(self):
        if self.is_primary or len(self._uids) > 0:
            return self._uids[0].selfsig.cipherprefs

        elif self.parent is not None:
            return self.parent.cipherprefs

        else:
            raise PGPError("Incomplete key")

    @property
    def compprefs(self):
        if self.is_primary or len(self._uids) > 0:
            return self._uids[0].selfsig.compprefs

        elif self.parent is not None:
            return self.parent.compprefs

        else:
            raise PGPError("Incomplete key")

    @property
    def fingerprint(self):
        return self._key.fingerprint

    @property
    def hashdata(self):
        # when signing a key, only the public portion of the keys is hashed
        # if this is a private key, the private components of the key material need to be left out
        if self.is_public:
            return self._key.__bytes__()[len(self._key.header):]

        publen = len(self._key) - len(self._key.header) - len(self._key.keymaterial) + 1 + self._key.keymaterial.publen()
        return self._key.__bytes__()[len(self._key.header):publen]

    @property
    def hashprefs(self):
        if self.is_primary or len(self._uids) > 0:
            return self._uids[0].selfsig.hashprefs

        elif self.parent is not None:
            return self.parent.hashprefs

        else:
            raise PGPError("Incomplete key")

    @property
    def is_primary(self):
        return isinstance(self._key, Primary) and not isinstance(self._key, Sub)

    @property
    def is_protected(self):
        if self.is_public:
            return False

        return self._key.protected

    @property
    def is_public(self):
        return isinstance(self._key, Public) and not isinstance(self._key, Private)

    @property
    def is_unlocked(self):
        if self.is_public:
            return True

        return self._key.unlocked

    @property
    def key_algorithm(self):
        return self._key.pkalg

    @property
    def magic(self):
        return '{:s} KEY BLOCK'.format('PUBLIC' if (isinstance(self._key, Public) and not isinstance(self._key, Private)) else
                                       'PRIVATE' if isinstance(self._key, Private) else '')

    @property
    def parent(self):
        if isinstance(self, Primary):
            return None
        return self._parent

    @property
    def signatures(self):
        return list(self._signatures)

    @property
    def signers(self):
        return set(sig.signer for sig in self.__sig__)

    @property
    def subkeys(self):
        return self._children

    @property
    def usageflags(self):
        if self.is_primary:
            return self._uids[0]._signatures[0].key_flags

        else:
            return self._signatures[0].key_flags

    @property
    def userids(self):
        return [u for u in self._uids if isinstance(u._uid, UserID)]

    @property
    def userattributes(self):
        return [u for u in self._uids if isinstance(u._uid, UserAttribute)]

    @classmethod
    def generate(cls):
        raise NotImplementedError()

    def __init__(self):
        super(PGPKey, self).__init__()
        self._key = None
        self._children = collections.OrderedDict()
        self._parent = None
        self._signatures = collections.deque()
        self._uids = collections.deque()

    def __bytes__(self):
        _bytes = bytearray()
        # us
        _bytes += self._key.__bytes__()
        # our signatures; ignore embedded signatures
        for sig in [ s for s in self.signatures if not s.embedded ]:
            _bytes += sig.__bytes__()
        # one or more User IDs, followed by their signatures
        for uid in self._uids:
            _bytes += uid._uid.__bytes__()
            _bytes += b''.join(s.__bytes__() for s in uid._signatures)
        # subkeys
        for sk in self._children.values():
            _bytes += sk.__bytes__()

        return bytes(_bytes)

    def protect(self):
        raise NotImplementedError()

    @contextlib.contextmanager
    def unlock(self, passphrase):
        if self.is_public:
            ##TODO: we can't unprotect public keys because only private key material is ever protected
            return

        if not self.is_protected:
            ##TODO: we can't unprotect private keys that are not protected, because there is no ciphertext to decrypt
            return

        try:
            for sk in itertools.chain([self], self.subkeys.values()):
                sk._key.unprotect(passphrase)
            del passphrase
            yield

        finally:
            # clean up here by deleting the previously decrypted secret key material
            for sk in itertools.chain([self], self.subkeys.values()):
                sk._key.keymaterial.clear()

    def add_uid(self, name, comment="", email="", **kwargs):
        prefs = {'sigtype': SignatureType.Positive_Cert,
                 'usage': [],
                 'hashprefs': [],
                 'cipherprefs': [],
                 'compprefs': [],
                 'primary': False}
        prefs.update(kwargs)

        if not self.is_primary:
            raise PGPError("Cannot add UIDs to subkeys!")

        if prefs['sigtype'] not in [SignatureType.Generic_Cert, SignatureType.Persona_Cert, SignatureType.Casual_Cert,
                                    SignatureType.Positive_Cert]:
            raise PGPError("User IDs must be certified")

        uid = PGPUID()
        uid._uid = UserID()
        uid._uid.name = name
        uid._uid.comment = comment
        uid._uid.email = email
        uid._uid.update_hlen()
        uid._parent = self
        uid.add_signature(self.sign(uid, **prefs))

        if not prefs['primary']:
            self._uids.append(uid)
        else:
            self._uids.insert(0, uid)

    def del_uid(self, search):
        uidict = dict( (p, i)
                       for i, u in enumerate(self._uids)
                       for p in filter(lambda i: i is not None, [u.name, u.comment, u.email]) )

        if search not in uidict:
            raise PGPError("uid '{:s}' not found".format(search))

        # self._uids.pop(uidict[search])
        self._uids.rotate(-1 * uidict[search])
        self._uids.popleft()
        self._uids.rotate(uidict[search] - 1)

    def sign(self, subject, **kwargs):
        # default options
        prefs = {'hash': self.hashprefs[0],
                 # inline implies sigtype is SignatureType.CanonicalDocument
                 'inline': False,
                 'sigtype': SignatureType.BinaryDocument,
                 # usage, *prefs, and primary are only meaningful on a self-signature for a User ID or User Attribute
                 'usage': [],
                 'hashprefs': [],
                 'cipherprefs': [],
                 'compprefs': [],
                 'primary': False}
        prefs.update(kwargs)
        _u = KeyFlags.Sign

        ##TODO: clean up this preference precedence deal
        if prefs['inline']:
            # inline signature forces the CanonicalDocument signature type
            prefs['sigtype'] = SignatureType.CanonicalDocument
        if isinstance(subject, PGPUID) and 'sigtype' not in kwargs:
            # if this is a PGPUID, default to Generic_Cert
            prefs['sigtype'] = SignatureType.Generic_Cert

        if prefs['sigtype'] in [SignatureType.Generic_Cert, SignatureType.Persona_Cert, SignatureType.Casual_Cert,
                                SignatureType.Positive_Cert]:
            _u = KeyFlags.Certify

        if prefs['hash'] not in self.hashprefs:
            warnings.warn("Selected hash algorithm not in key preferences", stacklevel=2)

        if self.is_public:
            raise PGPError("Can't sign with a public key")

        if self.is_protected and (not self._key.unlocked):
            raise PGPError("This key is not unlocked")

        if isinstance(subject, PGPKey):
            raise NotImplementedError(repr(subject))

        if _u not in self.usageflags:
            ##TODO: change warning/exception messages to match whether _u is KeyFlag.Sign or KeyFlag.Certify
            for sk in self.subkeys.values():
                if KeyFlags.Sign in sk.usageflags:
                    warnings.warn("This key is not marked for signing, but subkey {:s} is. "
                                  "Using that subkey...".format(sk.fingerprint.keyid),
                                  stacklevel=2)
                    return sk.sign(subject, **kwargs)

            raise PGPError("This key is not marked for signing")

        sig = PGPSignature.new(prefs['sigtype'], self.key_algorithm, prefs['hash'], self.fingerprint.keyid)

        if isinstance(subject, PGPMessage):
            sigdata = sig.hashdata(subject.message)

        elif isinstance(subject, PGPUID):
            if sig.type in [SignatureType.Generic_Cert, SignatureType.Persona_Cert, SignatureType.Casual_Cert,
                            SignatureType.Positive_Cert] and subject._parent is self:
                # flags and preferences
                sig._signature.subpackets.addnew('KeyFlags', hashed=True, flags=prefs['usage'])
                sig._signature.subpackets.addnew('PreferredSymmetricAlgorithms', hashed=True, flags=prefs['cipherprefs'])
                sig._signature.subpackets.addnew('PreferredHashAlgorithms', hashed=True, flags=prefs['hashprefs'])
                sig._signature.subpackets.addnew('PreferredCompressionAlgorithms', hashed=True, flags=prefs['compprefs'])
                # implementation features
                sig._signature.subpackets.addnew('Features', hashed=True, flags=[Features.ModificationDetection])
                sig._signature.subpackets.addnew('KeyServerPreferences', hashed=True, flags=[KeyServerPreferences.NoModify])

                if prefs['primary']:
                    sig._signature.subpackets.addnew('PrimaryUserID', hashed=True, primary=True)

            sigdata = sig.hashdata(subject)

        else:
            sigdata = sig.hashdata(self.load(subject))

        h2 = prefs['hash'].hasher
        h2.update(sigdata)
        sig._signature.hash2 = bytearray(h2.digest()[:2])

        if self.key_algorithm == PubKeyAlgorithm.RSAEncryptOrSign:
            sigopts = (padding.PKCS1v15(), getattr(hashes, prefs['hash'].name)(), default_backend())

        elif self.key_algorithm == PubKeyAlgorithm.DSA:
            sigopts = (getattr(hashes, prefs['hash'].name)(), default_backend())

        else:
            raise NotImplementedError(self.key_algorithm)

        signer = self.__key__.__privkey__().signer(*sigopts)
        signer.update(sigdata)
        sig._signature.signature.from_signer(signer.finalize())
        sig._signature.update_hlen()

        return sig

    def verify(self, subject, signature=None):
        sspairs = []

        # some type checking
        if not isinstance(subject, (type(None), PGPMessage, PGPKey, PGPUID, PGPSignature, six.string_types, bytes, bytearray)):
            raise ValueError("Unexpected subject value: {:s}".format(str(type(subject))))
        if not isinstance(signature, (type(None), PGPSignature)):
            raise ValueError("Unexpected signature value: {:s}".format(str(type(signature))))

        # load the signature subject if necessary
        if isinstance(subject, (six.string_types, bytes, bytearray)):
            subject = self.load(subject)

        # collect signature(s)
        if isinstance(signature, PGPSignature):
            if signature.signer != self.fingerprint.keyid and signature.signer not in self.subkeys:
                raise PGPError("Incorrect key. Expected: {:s}".format(signature.signer))
            sspairs.append((signature, subject))

        if hasattr(subject, '__sig__'):
            def _filter_sigs(sigs):
                _ids = {self.fingerprint.keyid} | set(self.subkeys)
                return [ sig for sig in sigs if sig.signer in _ids ]

            if isinstance(subject, PGPMessage):
                sspairs += [ (sig, subject.message) for sig in _filter_sigs(subject.__sig__) ]

            if isinstance(subject, (PGPUID, PGPKey)):
                sspairs += [ (sig, subject) for sig in _filter_sigs(subject.__sig__) ]

            if isinstance(subject, PGPKey):
                # user ids
                sspairs += [ (sig, uid) for uid in subject.userids for sig in _filter_sigs(uid.__sig__) ]
                # user attributes
                sspairs += [ (sig, ua) for ua in subject.userattributes for sig in _filter_sigs(ua.__sig__) ]
                # subkey/primarykey binding signatures
                sspairs += [ (sig, subkey) for subkey in subject.subkeys.values() for sig in _filter_sigs(subkey.__sig__) ]

        if len(sspairs) == 0:
            raise PGPError("No signatures to verify")

        # finally, start verifying signatures
        sigv = SignatureVerification()
        for sig, subj in sspairs:
            if self.fingerprint.keyid != sig.signer:
                warnings.warn("Signature was signed with this key's subkey: {:s}. "
                              "Verifying with subkey...".format(sig.signer),
                              stacklevel=2)
                sigv &= self.subkeys[sig.signer].verify(subj, sig)

            else:
                if sig.key_algorithm == PubKeyAlgorithm.RSAEncryptOrSign:
                    vargs = ( b'\x00' * (self._key.keymaterial.n.byte_length() - len(sig.__sig__)) + sig.__sig__,
                              padding.PKCS1v15(), getattr(hashes, sig.hash_algorithm.name)(), default_backend() )

                elif sig.key_algorithm == PubKeyAlgorithm.DSA:
                    vargs = (sig.__sig__, getattr(hashes, sig.hash_algorithm.name)(), default_backend())

                else:
                    raise NotImplementedError(sig.key_algorithm)

                sigdata = sig.hashdata(subj)
                verifier = self.__key__.__pubkey__().verifier(*vargs)
                verifier.update(sigdata)
                verified = False

                try:
                    verifier.verify()

                except InvalidSignature:
                    pass

                else:
                    verified = True

                finally:
                    sigv.add_sigsubj(sig, subj, verified)
                    del sigdata, verifier, verified

        return sigv

    def encrypt(self, message, sessionkey=None, **kwargs):
        prefs = {'cipher': self.cipherprefs[0],
                 'hash': self.hashprefs[0]}
        prefs.update(kwargs)

        if KeyFlags.EncryptCommunications not in self.usageflags:
            for sk in self.subkeys.values():
                if KeyFlags.EncryptCommunications in sk.usageflags:
                    warnings.warn("This key is not marked for encrypting communications, but subkey {:s} is. "
                                  "Using that subkey...".format(sk.fingerprint.keyid),
                                  stacklevel=2)
                    return sk.encrypt(message, sessionkey, **kwargs)

            raise PGPError("This key is not marked for encryption")

        if prefs['cipher'] not in self.cipherprefs:
            warnings.warn("Selected symmetric algorithm not in key preferences", stacklevel=2)

        if prefs['hash'] not in self.hashprefs:
            warnings.warn("Selected hash algorithm not in key preferences", stacklevel=2)

        if message.is_compressed and message._contents[0].calg not in self.compprefs:
            warnings.warn("Selected hash algorithm not in key preferences", stacklevel=2)

        if sessionkey is None:
            sessionkey = prefs['cipher'].gen_key()

        # set up a new PKESessionKeyV3
        pkesk = PKESessionKeyV3()
        pkesk.encrypter = bytearray(binascii.unhexlify(self.fingerprint.keyid.encode('latin-1')))
        pkesk.pkalg = self.key_algorithm
        pkesk.encrypt_sk(self.__key__.__pubkey__(), prefs['cipher'], sessionkey)

        if message.is_encrypted:
            _m = message

        else:
            _m = PGPMessage()
            skedata = IntegrityProtectedSKEDataV1()
            skedata.encrypt(sessionkey, prefs['cipher'], message.__bytes__())
            _m._contents = [skedata]

        _m._contents.insert(0, pkesk)

        return _m

    def decrypt(self, message):
        if not isinstance(message, PGPMessage):
            _message = PGPMessage()
            _message.parse(message)
            message = _message
            del _message

        if not message.is_encrypted:
            warnings.warn("This message is not encrypted", stacklevel=2)
            return message

        if self.fingerprint.keyid not in message.issuers:
            sks = set(self.subkeys)
            mis = set(message.issuers)
            if sks & mis:
                skid = list(sks & mis)[0]
                warnings.warn("Message was encrypted with this key's subkey: {:s}. "
                              "Decrypting with that...".format(skid),
                              stacklevel=2)
                return self.subkeys[skid].decrypt(message)

            raise PGPError("Cannot decrypt the provided message with this key")

        for pkesk in [pkt for pkt in message._contents if isinstance(pkt, PKESessionKey)]:
            if pkesk.pkalg == self.key_algorithm and pkesk.encrypter == self.fingerprint.keyid:
                alg, key = pkesk.decrypt_sk(self.__key__.__privkey__())
                break

        # now that we have the symmetric cipher used and the key, we can decrypt the actual message
        decmsg = PGPMessage()
        decmsg.parse(message.message.decrypt(key, alg))

        return decmsg

    def parse(self, packet):
        unarmored = self.ascii_unarmor(self.load(packet))
        data = unarmored['body']

        if unarmored['magic'] is not None and 'KEY' not in unarmored['magic']:
            raise ValueError('Expected: KEY. Got: {}'.format(str(unarmored['magic'])))

        if unarmored['headers'] is not None:
            self.ascii_headers = unarmored['headers']

        # parse packets
        # keys will hold other keys parsed here
        keys = collections.OrderedDict()
        # orphaned will hold all non-opaque orphaned packets
        orphaned = collections.OrderedDict()

        # parsing hints
        # last non-signature placed
        last = None  # last PGP*thing placed
        lns = None   # last non-signature PGP*thing placed
        lpk = None   # last primary key parsed
        lk = None    # last key parsed
        pkt = None   # packet just parsed

        while len(data) > 0:
            pkt = Packet(data)

            # discard opaque packets
            if isinstance(pkt, Opaque):
                warnings.warn("Discarded unsupported packet: {:s}".format(repr(pkt)), stacklevel=2)
                del pkt
                continue

            # load a key packet
            if isinstance(pkt, Key):
                key = self if self._key is None else PGPKey()
                key._key = pkt
                key.ascii_headers = self.ascii_headers

                lk = key
                if key.is_primary:
                    lpk = key
                    keys[key.fingerprint.keyid] = key

                elif (not key.is_primary) and lpk is not None and \
                        (isinstance(lns, PGPUID) or (isinstance(lns, PGPKey)) and not lk.is_primary):
                    key._parent = lpk
                    lpk._children[key.fingerprint.keyid] = key

                else:
                    ##TODO: most other possibilities at this point is an error condition
                    ##TODO: the other possibility is a subkey that has been separated from its primary, on purpose
                    pass

                last = key
                lns = key
                continue

            # don't bother trying to load anything else until we've loaded a key
            # this could be useful in cases where a large block is being loaded and it's led off
            # with key packet versions that we don't understand yet (currently, v2 and v3 key packets)
            if lpk is None:
                continue

            # A user id/attribute was parsed!
            # Discounting signatures, they must follow either a primary key or another user id/attribute
            if isinstance(pkt, (UserID, UserAttribute)) and isinstance(lns, (PGPKey, PGPUID)):
                uid = PGPUID()
                uid._uid = pkt
                uid._parent = lpk
                lpk._uids.append(uid)
                last = uid
                lns = uid
                continue

            # A signature was parsed!
            if isinstance(pkt, Signature):
                sig = PGPSignature.from_sigpkt(pkt)

                # A KeyRevocation signature *must immediately* follow a *primary* key *only*
                if sig.type == SignatureType.KeyRevocation and isinstance(last, PGPKey) and last.is_primary:
                    lk._signatures.append(sig)
                    last = sig
                    continue

                # A signature directly on a key follows the key that is its subject
                if sig.type == SignatureType.DirectlyOnKey and isinstance(lns, PGPKey):
                    lk._signatures.append(sig)
                    last = sig
                    continue

                # A SubkeyRevocation signature comes after a subkey
                if sig.type == SignatureType.SubkeyRevocation and not lk.is_primary:
                    lk._signatures.appendleft(sig)
                    last = sig
                    continue

                # Subkey Binding signatures come after subkeys
                if sig.type == SignatureType.Subkey_Binding and not lk.is_primary:
                    lk._signatures.append(sig)
                    last = sig

                    # extract the Primary Key Binding Signature as well if there is one
                    if 'EmbeddedSignature' in sig._signature.subpackets:
                        _sig = PGPSignature()
                        _sig._signature = next(iter(sig._signature.subpackets['EmbeddedSignature']))
                        _sig.parent = sig
                        lk._signatures.append(_sig)
                        del _sig
                    continue

                # Certification and Certification Revocation signatures *must* follow either a User ID or User Attribute packet,
                # or another Certification signature.
                if sig.type in [SignatureType.Positive_Cert, SignatureType.Persona_Cert, SignatureType.Casual_Cert,
                                SignatureType.Generic_Cert, SignatureType.CertRevocation] and isinstance(lns, (PGPUID)):
                    lns.add_signature(sig)
                    last = sig
                    continue

            # if we get this far, the packet was orphaned! Add it to orphaned and warn.
            warnings.warn("Warning: Orphaned packet detected! {:s}".format(repr(pkt)), stacklevel=2)
            orphaned[(pkt.header.tag, len([k for k, v in orphaned.keys() if k == pkt.header.tag]))] = pkt

        # remove the reference to self from keys
        del keys[self.fingerprint.keyid]
        return {'keys': keys, 'orphaned': orphaned}


class PGPSignature(PGPObject, Exportable):
    @property
    def __sig__(self):
        return self._signature.signature.__sig__()

    @property
    def cipherprefs(self):
        if 'PreferredSymmetricAlgorithms' not in self._signature.subpackets:
            return []
        return next(iter(self._signature.subpackets['h_PreferredSymmetricAlgorithms'])).flags

    @property
    def compprefs(self):
        if 'PreferredCompressionAlgorithms' not in self._signature.subpackets:
            return []
        return next(iter(self._signature.subpackets['h_PreferredCompressionAlgorithms'])).flags

    @property
    def created(self):
        return self._signature.subpackets['h_CreationTime'][-1].created

    @property
    def embedded(self):
        return self.parent is not None

    @property
    def expired(self):
        if 'SignatureExpirationTime' not in self._signature.subpackets:
            return False

        expd = self._signature.subpackets['SignatureExpirationTime'].expires
        if expd.total_seconds() == 0:
            return False

        exp = self.created + expd
        return exp > datetime.utcnow()

    @property
    def exportable(self):
        if 'ExportableCertification' not in self._signature.subpackets:
            return True

        return bool(self._signature.subpackets['ExportableCertification'])

    @property
    def features(self):
        if 'Features' in self._signature.subpackets:
            return self._signature.subpackets['Features'].flags
        return []

    @property
    def hash2(self):
        return self._signature.hash2

    @property
    def hashprefs(self):
        if 'PreferredHashAlgorithms' not in self._signature.subpackets:
            return []
        return next(iter(self._signature.subpackets['h_PreferredHashAlgorithms'])).flags

    @property
    def hash_algorithm(self):
        return self._signature.halg

    @property
    def key_algorithm(self):
        return self._signature.pubalg

    @property
    def key_flags(self):
        if 'KeyFlags' in self._signature.subpackets:
            return next(iter(self._signature.subpackets['h_KeyFlags'])).flags
        return []

    @property
    def keyserver(self):
        if 'PreferredKeyServer' not in self._signature.subpackets:
            return ''
        return self._signature.subpackets['h_KeyServerPreferences'].uri

    @property
    def keyserverprefs(self):
        if 'KeyServerPreferences' not in self._signature.subpackets:
            return []
        return self._signature.subpackets['h_KeyServerPreferences'].flags

    @property
    def magic(self):
        return "SIGNATURE"

    @property
    def notation(self):
        if 'NotationData' in self._signature.subpackets:
            nd = self._signature.subpackets['NotationData']
            return {'flags': nd.flags, 'name': nd.name, 'value': nd.value}
        return {}

    @property
    def revocable(self):
        if 'Revocable' not in self._signature.subpackets:
            return True
        return bool(self._signature.subpackets['Revocable'])

    @property
    def revocation_key(self):
        if 'RevocationKey' not in self._signature.subpackets:
            return None
        raise NotImplementedError()

    @property
    def signer(self):
        return self._signature.signer

    @property
    def target_signature(self):
        raise NotImplementedError()

    @property
    def type(self):
        return self._signature.sigtype

    @classmethod
    def new(cls, sigtype, pkalg, halg, signer):
        sig = PGPSignature()

        sigpkt = SignatureV4()
        sigpkt.header.tag = 2
        sigpkt.header.version = 4
        sigpkt.subpackets.addnew('CreationTime', hashed=True, created=datetime.utcnow())
        sigpkt.subpackets.addnew('Issuer', _issuer=signer)

        sigpkt.sigtype = sigtype
        sigpkt.pubalg = pkalg
        sigpkt.halg = halg

        sig._signature = sigpkt
        return sig

    @classmethod
    def from_sigpkt(cls, sigpkt):
        sig = PGPSignature()
        sig._signature = sigpkt
        return sig

    def __init__(self):
        super(PGPSignature, self).__init__()
        self._signature = None
        self.parent = None

    def __bytes__(self):
        if self._signature is None:
            return b''
        return self._signature.__bytes__()

    def __repr__(self):
        return "<PGPSignature [{:s}] object at 0x{:02x}>".format(self.type.name, id(self))

    def hashdata(self, subject):
        _data = bytearray()

        if isinstance(subject, six.string_types):
            subject = subject.encode('latin-1')

        """
        All signatures are formed by producing a hash over the signature
        data, and then using the resulting hash in the signature algorithm.
        """

        if self.type == SignatureType.BinaryDocument:
            """
            For binary document signatures (type 0x00), the document data is
            hashed directly.
            """
            _s = self.load(subject)
            _data += _s

        if self.type == SignatureType.CanonicalDocument:
            """
            For text document signatures (type 0x01), the
            document is canonicalized by converting line endings to <CR><LF>,
            and the resulting data is hashed.
            """
            _data += re.subn(br'\r{0,1}\n', b'\r\n', subject)[0]

        if self.type in [SignatureType.Generic_Cert, SignatureType.Persona_Cert, SignatureType.Casual_Cert,
                         SignatureType.Positive_Cert, SignatureType.CertRevocation, SignatureType.Subkey_Binding,
                         SignatureType.PrimaryKey_Binding, SignatureType.DirectlyOnKey, SignatureType.KeyRevocation,
                         SignatureType.SubkeyRevocation]:
            """
            When a signature is made over a key, the hash data starts with the
            octet 0x99, followed by a two-octet length of the key, and then body
            of the key packet.  (Note that this is an old-style packet header for
            a key packet with two-octet length.) ...
            Key revocation signatures (types 0x20 and 0x28)
            hash only the key being revoked.
            """
            _s = b''
            if isinstance(subject, PGPUID):
                # _s = subject._parent._key.__bytes__()[len(subject._parent._key.header):]
                _s = subject._parent.hashdata

            elif isinstance(subject, PGPKey) and not subject.is_primary:
                # _s = subject._parent._key.__bytes__()[len(subject._parent._key.header):]
                _s = subject._parent.hashdata

            elif isinstance(subject, PGPKey) and subject.is_primary:
                # _s = subject._key.__bytes__()[len(subject._key.header):]
                _s = subject.hashdata

            if len(_s) > 0:
                _data += b'\x99' + self.int_to_bytes(len(_s), 2) + _s

        if self.type in [SignatureType.Subkey_Binding, SignatureType.PrimaryKey_Binding, SignatureType.SubkeyRevocation]:
            """
            A subkey binding signature
            (type 0x18) or primary key binding signature (type 0x19) then hashes
            the subkey using the same format as the main key (also using 0x99 as
            the first octet).
            """
            # _s = subject._key.__bytes__()[len(subject._key.header):]
            _s = subject.hashdata
            _data += b'\x99' + self.int_to_bytes(len(_s), 2) + _s

        if self.type in [SignatureType.Generic_Cert, SignatureType.Persona_Cert, SignatureType.Casual_Cert,
                         SignatureType.Positive_Cert, SignatureType.CertRevocation]:
            """
            A certification signature (type 0x10 through 0x13) hashes the User
            ID being bound to the key into the hash context after the above
            data.  ...  A V4 certification
            hashes the constant 0xB4 for User ID certifications or the constant
            0xD1 for User Attribute certifications, followed by a four-octet
            number giving the length of the User ID or User Attribute data, and
            then the User ID or User Attribute data.

            ...

            The [certificate revocation] signature
            is computed over the same data as the certificate that it
            revokes, and should have a later creation date than that
            certificate.
            """

            _s = subject.hashdata
            if subject.is_uid:
                _data += b'\xb4' + self.int_to_bytes(len(_s), 4) + _s

            if subject.is_ua:
                _data += b'\xd1' + self.int_to_bytes(len(_s), 4) + _s

        if len(_data) == 0 and self.type is not SignatureType.Timestamp:
            raise NotImplementedError(self.type)

        # if this is a new signature, do update_hlen
        if 0 in list(self._signature.signature):
            self._signature.update_hlen()

        """
        Once the data body is hashed, then a trailer is hashed. (...)
        A V4 signature hashes the packet body
        starting from its first field, the version number, through the end
        of the hashed subpacket data.  Thus, the fields hashed are the
        signature version, the signature type, the public-key algorithm, the
        hash algorithm, the hashed subpacket length, and the hashed
        subpacket body.

        V4 signatures also hash in a final trailer of six octets: the
        version of the Signature packet, i.e., 0x04; 0xFF; and a four-octet,
        big-endian number that is the length of the hashed data from the
        Signature packet (note that this number does not include these final
        six octets).
        """

        hcontext = bytearray()
        hcontext.append(self._signature.header.version if not self.embedded else self._signature._sig.header.version)
        hcontext.append(self.type)
        hcontext.append(self.key_algorithm)
        hcontext.append(self.hash_algorithm)
        hcontext += self._signature.subpackets.__hashbytes__()
        hlen = len(hcontext)
        _data += hcontext
        _data += b'\x04\xff'
        _data += self.int_to_bytes(hlen, 4)
        return bytes(_data)

    def make_onepass(self):
        onepass = OnePassSignatureV3()
        onepass.sigtype = self.type
        onepass.halg = self.hash_algorithm
        onepass.pubalg = self.key_algorithm
        onepass.signer = self.signer
        onepass.update_hlen()
        return onepass

    def parse(self, packet):
        unarmored = self.ascii_unarmor(self.load(packet))
        data = unarmored['body']

        if unarmored['magic'] is not None and unarmored['magic'] != 'SIGNATURE':
            raise ValueError('Expected: SIGNATURE. Got: {}'.format(str(unarmored['magic'])))

        if unarmored['headers'] is not None:
            self.ascii_headers = unarmored['headers']

        # load *one* packet from data
        pkt = Packet(data)
        if pkt.header.tag == PacketTag.Signature and not isinstance(pkt, Opaque):
            self._signature = pkt

        else:
            raise ValueError('Expected: Signature. Got: {:s}'.format(pkt.__class__.__name__))


class PGPUID(object):
    @property
    def __sig__(self):
        return list(self._signatures)

    @property
    def primary(self):
        raise NotImplementedError()

    @property
    def name(self):
        return self._uid.name if isinstance(self._uid, UserID) else ""

    @property
    def comment(self):
        return self._uid.comment if isinstance(self._uid, UserID) else ""

    @property
    def email(self):
        return self._uid.email if isinstance(self._uid, UserID) else ""

    @property
    def image(self):
        return self._uid.image if isinstance(self._uid, UserAttribute) else None

    @property
    def is_uid(self):
        return isinstance(self._uid, UserID)

    @property
    def is_ua(self):
        return isinstance(self._uid, UserAttribute)

    @property
    def selfsig(self):
        if self._parent is not None:
            return next(sig for sig in self._signatures if sig.signer == self._parent.fingerprint.keyid)

    @property
    def signers(self):
        return set(s.signer for s in self.__sig__)

    @property
    def hashdata(self):
        if self.is_uid:
            return self._uid.__bytes__()[len(self._uid.header):]

        if self.is_ua:
            return self._uid.subpackets.__bytes__()

    def __init__(self):
        self._uid = None
        self._signatures = collections.deque()
        self._parent = None

    def add_signature(self, sig):
        # self._signatures should be sorted by creation time, from newest to oldest
        sigind = [s.created for s in self._signatures]
        i = bisect.bisect_left(sigind, sig.created)
        self._signatures.rotate(-1 * i)
        self._signatures.appendleft(sig)
        self._signatures.rotate(i + 1)


class PGPMessage(PGPObject, Exportable):
    @staticmethod
    def dash_unescape(text):
        return re.subn(r'^- -', '-', text, flags=re.MULTILINE)[0]

    @staticmethod
    def dash_escape(text):
        return re.subn(r'^-', '- -', text, flags=re.MULTILINE)[0]

    @property
    def __sig__(self):
        _m = iter(self._contents)
        if self.is_compressed:
            _m = itertools.chain(_m, iter(next(pkt for pkt in self._contents if isinstance(pkt, CompressedData)).packets))
        return [ PGPSignature.from_sigpkt(i) if isinstance(i, Signature) else i for i in _m if isinstance(i, (PGPSignature, Signature))]

    @property
    def encrypters(self):
        return set(m.encrypter for m in self._contents if isinstance(m, PKESessionKey))

    @property
    def is_compressed(self):
        return any(isinstance(pkt, CompressedData) for pkt in self._contents)

    @property
    def is_encrypted(self):
        return self.type == 'encrypted'

    @property
    def is_signed(self):
        return self.type in ['cleartext', 'signed']

    @property
    def issuers(self):
        return self.encrypters | self.signers

    @property
    def magic(self):
        if self.type == 'cleartext':
            return "SIGNATURE"
        return "MESSAGE"

    @property
    def message(self):
        if self.type == 'cleartext':
            return self._contents[0]

        if self.type in ['literal', 'compressed', 'signed']:
            _m = self._contents
            if self.is_compressed:
                _m = next(pkt for pkt in self._contents if isinstance(pkt, CompressedData)).packets
            m = next(pkt for pkt in _m if isinstance(pkt, LiteralData))

            return m.contents

        if self.type == 'encrypted':
            return self._contents[-1]

        raise NotImplementedError(self.type)

    @property
    def signers(self):
        return set(m.signer for m in self._contents if isinstance(m, (Signature, OnePassSignature, PGPSignature)))

    @property
    def type(self):
        ##TODO: it might be better to use an Enum for the output of this
        if isinstance(self._contents[0], six.string_types):
            return 'cleartext'

        if isinstance(self._contents[0], LiteralData):
            return 'literal'

        if isinstance(self._contents[0], CompressedData):
            return 'compressed'

        if isinstance(self._contents[0], (PGPSignature, OnePassSignature)):
            return 'signed'

        if isinstance(self._contents[0], (PKESessionKey, SKESessionKey, SKEData, IntegrityProtectedSKEData)):
            return 'encrypted'

        return 'unknown'

    def __init__(self):
        super(PGPMessage, self).__init__()
        self._contents = []

    def __bytes__(self):
        return b''.join(p.__bytes__() for p in self._contents if hasattr(p, '__bytes__'))

    def __str__(self):
        if self.type == 'cleartext':
            return "-----BEGIN PGP SIGNED MESSAGE-----\n" \
                   "Hash: {hashes:s}\n\n" \
                   "{cleartext:s}\n" \
                   "{signature:s}".format(hashes=','.join(s.hash_algorithm.name for s in self.__sig__),
                                          cleartext=self.dash_escape(self._contents[0]),
                                          signature=super(PGPMessage, self).__str__())

        return super(PGPMessage, self).__str__()

    @classmethod
    def new(cls, message, **kwargs):
        prefs = {'cleartext': False,
                 'sensitive': False,
                 'compression': CompressionAlgorithm.ZIP,
                 'format': 'b'}
        prefs.update(kwargs)

        msg = PGPMessage()

        if prefs['cleartext']:
            msg._contents.append(msg.load(message).decode('latin-1'))

        else:
            # load literal data
            lit = LiteralData()
            lit._contents = msg.load(message)
            lit.format = prefs['format']

            if os.path.isfile(message):
                lit.filename = os.path.basename(message)
                lit.mtime = datetime.utcfromtimestamp(os.stat(message).st_mtime)

            else:
                lit.mtime = datetime.utcnow()

            if prefs['sensitive']:
                lit.filename = '_CONSOLE'

            lit.update_hlen()

            _m = lit
            if prefs['compression'] != CompressionAlgorithm.Uncompressed:
                _m = CompressedData()
                _m.calg = prefs['compression']
                _m.packets.append(lit)
                _m.update_hlen()

            msg._contents.append(_m)

        return msg

    def add_signature(self, sig, onepass=True):
        if self.type == 'cleartext':
            self._contents.append(sig)

        elif isinstance(sig, PGPSignature):
            if onepass:
                _m = self._contents
                if self.is_compressed:
                    _m = next(pkt for pkt in self._contents if isinstance(pkt, CompressedData)).packets

                _m.insert(0, sig.make_onepass())
                if isinstance(_m[1], OnePassSignature):
                    _m[0].nested = True
                _m.append(sig)

            else:
                self._contents.insert(0, sig)

    def encrypt(self, passphrase, sessionkey=None, **kwargs):
        prefs = {'cipher': SymmetricKeyAlgorithm.AES256,
                 'hash': HashAlgorithm.SHA256}
        prefs.update(kwargs)

        # set up a new SKESessionKeyV4
        skesk = SKESessionKeyV4()
        skesk.s2k.usage = 255
        skesk.s2k.specifier = 3
        skesk.s2k.halg = prefs['hash']
        skesk.s2k.encalg = prefs['cipher']
        skesk.s2k.count = skesk.s2k.halg.tuned_count

        if sessionkey is None:
            sessionkey = prefs['cipher'].gen_key()
        skesk.encrypt_sk(passphrase, sessionkey)
        del passphrase

        if not self.is_encrypted:
            # now encrypt pt and place it inside an IntegrityProtectedSKEDataV1
            skedata = IntegrityProtectedSKEDataV1()
            skedata.encrypt(sessionkey, prefs['cipher'], self.__bytes__())

            # now replace self._contents with the newly constructed encrypted message
            self._contents = [skesk, skedata]

        else:
            self._contents.insert(-1, skesk)
        del sessionkey

    def decrypt(self, passphrase):
        if not self.is_encrypted:
            raise PGPError("This message is not encrypted!")

        for skesk in [pkt for pkt in self._contents if isinstance(pkt, SKESessionKey)]:
            try:
                symalg, key = skesk.decrypt_sk(passphrase)

            except ValueError:
                pass

            # else:
            #     del passphrase
            #     break

        # now that we have the session key, we can decrypt the actual message
        decmsg = PGPMessage()
        decmsg.parse(self.message.decrypt(key, symalg))

        return decmsg

    def parse(self, packet):
        unarmored = self.ascii_unarmor(self.load(packet))
        data = unarmored['body']

        if unarmored['magic'] is not None and unarmored['magic'] not in ['MESSAGE', 'SIGNATURE']:
            raise ValueError('Expected: MESSAGE. Got: {}'.format(str(unarmored['magic'])))

        if unarmored['headers'] is not None:
            self.ascii_headers = unarmored['headers']

        # cleartext signature
        if unarmored['magic'] == 'SIGNATURE':
            # the composition for this will be the 'cleartext' as a str,
            # followed by one or more signatures (each one loaded into a PGPSignature)
            self._contents.append(self.dash_unescape(unarmored['cleartext']))
            while len(data) > 0:
                pkt = Packet(data)
                if not isinstance(pkt, Signature):
                    warnings.warn("Discarded unexpected packet: {:s}".format(pkt.__class__.__name__), stacklevel=2)
                self._contents.append(PGPSignature.from_sigpkt(pkt))

        else:
            while len(data) > 0:
                pkt = Packet(data)
                if isinstance(pkt, Signature):
                    self._contents.append(PGPSignature.from_sigpkt(pkt))

                else:
                    self._contents.append(pkt)


class PGPKeyring(collections.Container, collections.Iterable, collections.Sized):
    def __init__(self, *args):
        self._keys = {}
        self._pubkeys = collections.deque()
        self._privkeys = collections.deque()
        self._aliases = collections.deque([{}])
        self.load(*args)

    def __contains__(self, alias):
        aliases = set().union(*self._aliases)

        if isinstance(alias, six.string_types):
            return alias in aliases or alias.replace(' ', '') in aliases

        return alias in aliases

    def __len__(self):
        return len(self._keys)

    def __iter__(self):
        for pgpkey in itertools.chain(self._pubkeys, self._privkeys):
            yield pgpkey

    def _get_key(self, alias):
        for m in self._aliases:
            if alias in m:
                return self._keys[m[alias]]

            if alias.replace(' ', '') in m:
                return self._keys[m[alias.replace(' ', '')]]

        raise KeyError(alias)

    def _get_keys(self, alias):
        return [self._keys[m[alias]] for m in self._aliases if alias in m]

    def _sort_alias(self, alias):
        # remove alias from all levels of _aliases, and sort by created time and key half
        # so the order of _aliases from left to right:
        #  - newer keys come before older ones
        #  - private keys come before public ones
        #
        # this list is sorted in the opposite direction from that, because they will be placed into self._aliases
        # from right to left.
        pkids = sorted(list(set().union(m.pop(alias) for m in self._aliases if alias in m)),
                       key=lambda pkid: (self._keys[pkid].created, self._keys[pkid].is_public))

        # drop the now-sorted aliases into place
        for depth, pkid in enumerate(pkids):
            self._aliases[depth][alias] = pkid

        # finally, remove any empty dicts left over
        while {} in self._aliases:
            self._aliases.remove({})

    def _add_alias(self, alias, pkid):
        # brand new alias never seen before!
        if alias not in self:
            self._aliases[-1][alias] = pkid

        # this is a duplicate alias->key link; ignore it
        elif alias in self and pkid in set(m[alias] for m in self._aliases if alias in m):
            pass

        # this is an alias that already exists, but points to a key that is not already referenced by it
        else:
            adepth = len(self._aliases) - len([None for m in self._aliases if alias in m]) - 1
            # all alias maps have this alias, so increase total depth by 1
            if adepth == -1:
                self._aliases.appendleft({})
                adepth = 0

            self._aliases[adepth][alias] = pkid
            self._sort_alias(alias)

    def _add_key(self, pgpkey):
        pkid = id(pgpkey)
        if pkid not in self._keys:
            self._keys[pkid] = pgpkey

            # add to _{pub,priv}keys if this is either a primary key, or a subkey without one
            if pgpkey.parent is None:
                if pgpkey.is_public:
                    self._pubkeys.append(pkid)

                else:
                    self._privkeys.append(pkid)

            # aliases
            self._add_alias(pgpkey.fingerprint, pkid)
            self._add_alias(pgpkey.fingerprint.keyid, pkid)
            self._add_alias(pgpkey.fingerprint.shortid, pkid)
            for uid in pgpkey.userids:
                self._add_alias(uid.name, pkid)
                self._add_alias(uid.comment, pkid)
                self._add_alias(uid.email, pkid)

            # subkeys
            for subkey in pgpkey.subkeys.values():
                self._add_key(subkey)

    def load(self, *args):
        def _do_load(arg):
            if isinstance(arg, (list, tuple)):
                for item in arg:
                    _do_load(item)

            else:
                _key = PGPKey()
                keys = _key.parse(arg)

                for key in itertools.chain([_key], keys['keys'].values()):
                    self._add_key(key)
                    for fp in [k.fingerprint for k in itertools.chain([key], key.subkeys.values())]:
                        loaded.add(fp)

        loaded = set()
        _do_load(args)
        return list(loaded)

    @contextlib.contextmanager
    def key(self, identifier):
        if isinstance(identifier, PGPMessage):
            for issuer in identifier.issuers:
                if issuer in self:
                    identifier = issuer
                    break

        if isinstance(identifier, PGPSignature):
            identifier = identifier.signer

        if identifier in self:
            pgpkey = self._get_key(identifier)

        else:
            raise KeyError(identifier)

        yield pgpkey

    def fingerprints(self, keyhalf='any', keytype='any'):
        return list({pk.fingerprint for pk in self._keys.values()
                     if pk.is_primary in [True if keytype in ['primary', 'any'] else None,
                                          False if keytype in ['sub', 'any'] else None]
                     if pk.is_public in [True if keyhalf in ['public', 'any'] else None,
                                         False if keyhalf in ['private', 'any'] else None]})

    def unload(self, fp):
        raise NotImplementedError()
