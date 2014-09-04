""" pgp.py

this is where the armorable PGP block objects live
"""
import binascii
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
from .constants import HashAlgorithm
from .constants import KeyFlags
from .constants import PacketTag
from .constants import PubKeyAlgorithm
from .constants import SignatureType

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
from .packet.packets import LiteralData
from .packet.packets import OnePassSignature
from .packet.packets import PKESessionKey
from .packet.packets import Signature
from .packet.packets import SignatureV4
from .packet.packets import SKEData
from .packet.packets import SKESessionKey

from .packet.types import Opaque

from .packet.subpackets.signature import CreationTime
from .packet.subpackets.signature import Issuer

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
    def created(self):
        return self._key.created

    @property
    def cipherprefs(self):
        return self._uids[0]._signatures[0].cipherprefs

    @property
    def compprefs(self):
        return self._uids[0]._signatures[0].compprefs

    @property
    def fingerprint(self):
        return self._key.fingerprint

    @property
    def hashprefs(self):
        return self._uids[0]._signatures[0].hashprefs

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
        return self._signatures

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
        # our signatures
        for sig in self.signatures:
            _bytes += sig.__bytes__()
        # one or more User IDs, followed by their signatures
        for uid in self._uids:
            _bytes += uid._uid.__bytes__()
            _bytes += b''.join([s.__bytes__() for s in uid._signatures])
        # subkeys
        for sk in self._children.values():
            _bytes += sk.__bytes__()

        return bytes(_bytes)

    @classmethod
    def generate(cls):
        raise NotImplementedError()

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

    def sign(self, subject, **kwargs):
        # default options
        prefs = {'hash_alg': HashAlgorithm.SHA512,
                 # inline implies sigtype is SignatureType.CanonicalDocument
                 'inline': False,
                 'sigtype': SignatureType.BinaryDocument,
                 # usage and *prefs are only meaningful on a self-signature
                 'usage': [],
                 'hashprefs': [],
                 'cipherprefs': [],
                 'compprefs': []}
        prefs.update(kwargs)

        ##TODO: roll this into above, if possible
        if prefs['inline']:
            prefs['sigtype'] = SignatureType.CanonicalDocument

        if self.is_public:
            raise PGPError("Can't sign with a public key")

        if self.is_protected and (not self._key.unlocked):
            raise PGPError("This key is not unlocked")

        if isinstance(subject, PGPKey) or (isinstance(subject, PGPMessage) and subject.type != 'cleartext'):
            raise NotImplementedError(repr(subject))

        if KeyFlags.Sign not in self.usageflags:
            for sk in self.subkeys.values():
                if KeyFlags.Sign in sk.usageflags:
                    warnings.warn("This key is not marked for signing, but subkey {:s} is. "
                                  "Using that subkey...".format(sk.fingerprint.keyid))
                    return sk.sign(subject, **kwargs)

            raise PGPError("This key is not marked for signing")

        sig = PGPSignature.new(prefs['sigtype'], self.key_algorithm, prefs['hash_alg'], self.fingerprint.keyid)

        if prefs['inline']:
            if not isinstance(subject, PGPMessage):
                msg = PGPMessage()
                msg._contents.append(self.load(subject).decode('latin-1'))

            else:
                msg = subject

            msg._contents.append(sig)

            sigdata = sig.hashdata(msg.message)

        else:
            sigdata = sig.hashdata(self.load(subject))

        h2 = prefs['hash_alg'].hasher
        h2.update(sigdata)
        sig._signature.hash2 = bytearray(h2.digest()[:2])

        if self.key_algorithm == PubKeyAlgorithm.RSAEncryptOrSign:
            sigopts = (padding.PKCS1v15(), getattr(hashes, prefs['hash_alg'].name)(), default_backend())

        elif self.key_algorithm == PubKeyAlgorithm.DSA:
            sigopts = (getattr(hashes, prefs['hash_alg'].name)(), default_backend())

        else:
            raise NotImplementedError(self.key_algorithm)

        signer = self.__key__.__privkey__().signer(*sigopts)
        signer.update(sigdata)
        sig._signature.signature.from_signer(signer.finalize())
        sig._signature.update_hlen()

        if prefs['inline']:
            return msg

        return sig

    def verify(self, subject, signature=None, **kwargs):
        sig = None

        # load the signature subject if necessary
        if not isinstance(subject, (PGPMessage, PGPKey)):
            subj = self.load(subject)

        # figure out what kind of signature we have
        #  - error case
        if not isinstance(signature, (type(None), PGPSignature)):
            raise ValueError("Unexpected signature value - should be None or a PGPSignature")

        #  - detached PGPSignature
        if isinstance(signature, PGPSignature):
            sig = signature

        #  - cleartext message with inline signature
        if isinstance(subject, PGPMessage) and subject.type == 'cleartext':
            subj = subject.message

            # signed by us?
            if self.fingerprint.keyid in subject.issuers:
                sig = [s for s in subject.__sig__ if s.signer == self.fingerprint.keyid][0]

            # signed by a subkey?
            elif set(self.subkeys) & subject.issuers:
                skid = list(set(self.subkeys) & subject.issuers)[0]
                sig = [sig for sig in subject.__sig__ if sig.signer == skid][0]

        if sig is None:
            raise NotImplementedError(repr(subject))

        if self.fingerprint.keyid != sig.signer and sig.signer not in self.subkeys:
            raise PGPError("Incorrect key. Expected: {:s}".format(sig.signer))

        if self.fingerprint.keyid != sig.signer and sig.signer in self.subkeys:
            warnings.warn("Signature was signed with this key's subkey: {:s}. "
                          "Verifying with that...".format(sig.signer))
            return self.subkeys[sig.signer].verify(subject, sig)

        ##TODO: check this key's usage flags

        if sig.key_algorithm == PubKeyAlgorithm.RSAEncryptOrSign:
            verifier = self.__key__.__pubkey__().verifier(sig.__sig__, padding.PKCS1v15(), getattr(hashes, sig.hash_algorithm.name)(), default_backend())

        elif sig.key_algorithm == PubKeyAlgorithm.DSA:
            verifier = self.__key__.__pubkey__().verifier(sig.__sig__, getattr(hashes, sig.hash_algorithm.name)(), default_backend())

        else:
            ##TODO: raise a different exception if the key algorithm is something that can't/shouldn't be used for signing, like ElGamal
            raise NotImplementedError(sig.key_algorithm)

        sigv = SignatureVerification()
        sigv.signature = sig
        sigv.subject = subj

        sigdata = sig.hashdata(subj)

        verifier.update(sigdata)

        sigv = SignatureVerification()
        try:
            verifier.verify()

        except InvalidSignature:
            pass

        else:
            sigv._verified = True

        return sigv

    def encrypt(self, message):
        raise NotImplementedError()

    def decrypt(self, message):
        if not isinstance(message, PGPMessage):
            _message = PGPMessage()
            _message.parse(message)
            message = _message
            del _message

        if not message.is_encrypted:
            warnings.warn("This message is not encrypted")
            return message

        if self.fingerprint.keyid not in message.issuers:
            sks = set(self.subkeys)
            mis = set(message.issuers)
            if sks & mis:
                skid = list(sks & mis)[0]
                warnings.warn("Message was encrypted with this key's subkey: {:s}. "
                              "Decrypting with that...".format(skid))
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
                sig = PGPSignature()
                sig._signature = pkt

                # A KeyRevocation signature *must immediately* follow a *primary* key *only*
                if sig.type == SignatureType.KeyRevocation and isinstance(last, PGPKey) and last.is_primary:
                    lk._signatures.append(sig)
                    last = sig
                    continue

                # A signature directly on a key follows the key that is its subject, but comes after a revocation signature
                # or subkey binding signature if the last key is a subkey
                if sig.type == SignatureType.DirectlyOnKey and isinstance(lns, PGPKey):
                    ahead = [SignatureType.KeyRevocation, SignatureType.SubkeyRevocation, SignatureType.Subkey_Binding]
                    rots = len(list(itertools.groupby(lk._signatures, key=lambda s: s.type in ahead)[0][1]))
                    lk._signatures.rotate(-1 * rots)
                    lk._signatures.appendleft(sig)
                    lk._signatures.rotate(1 * rots)

                # A SubkeyRevocation signature *must immediately* follow the Subkey Binding Signature that
                # immediately follows a Subkey
                if sig.type == SignatureType.SubkeyRevocation and isinstance(last, PGPSignature) and isinstance(lk, PGPKey) and not lk.is_primary:
                    lk._signatures.appendleft(sig)
                    last = sig
                    continue

                # Certification signatures *must* follow either a User ID or User Attribute packet,
                # or another Certification signature.
                if sig.type in [SignatureType.Positive_Cert, SignatureType.Persona_Cert, SignatureType.Casual_Cert,
                                SignatureType.Generic_Cert] and isinstance(lns, (PGPUID)):
                    lns._signatures.append(sig)
                    last = sig
                    continue

                # Subkey Binding signatures *must immediately* follow a Subkey
                if isinstance(last, PGPKey) and not last.is_primary:
                    last._signatures.appendleft(sig)
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
        return self._signature.subpackets['h_PreferredSymmetricAlgorithms'][0].flags

    @property
    def compprefs(self):
        if 'PreferredCompressionAlgorithms' not in self._signature.subpackets:
            return []
        return self._signature.subpackets['h_PreferredCompressionAlgorithms'][0].flags

    @property
    def created(self):
        return self._signature.subpackets['h_CreationTime'][-1].created

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
        return self._signature.subpackets['h_PreferredHashAlgorithms'][0].flags

    @property
    def hash_algorithm(self):
        return self._signature.halg

    @property
    def key_algorithm(self):
        return self._signature.pubalg

    @property
    def key_flags(self):
        if 'KeyFlags' in self._signature.subpackets:
            return self._signature.subpackets['h_KeyFlags'][0].flags
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

        csp = CreationTime()
        csp.created = datetime.utcnow()
        sigpkt.subpackets['h_CreationTime'] = csp

        isp = Issuer()
        isp.issuer = bytearray(binascii.unhexlify(six.b(signer)))
        sigpkt.subpackets['Issuer'] = isp

        sigpkt.sigtype = sigtype
        sigpkt.pubalg = pkalg
        sigpkt.halg = halg

        sig._signature = sigpkt
        return sig

    def __init__(self):
        super(PGPSignature, self).__init__()
        self._signature = None

    def __bytes__(self):
        if self._signature is None:
            return b''
        return self._signature.__bytes__()

    def hashdata(self, subject):
        _data = bytearray()
        """
        All signatures are formed by producing a hash over the signature
        data, and then using the resulting hash in the signature algorithm.
        """

        if self.type == SignatureType.BinaryDocument:
            """
            For binary document signatures (type 0x00), the document data is
            hashed directly.
            """
            s = self.load(subject)
            _data += s

        if self.type == SignatureType.CanonicalDocument:
            """
            For text document signatures (type 0x01), the
            document is canonicalized by converting line endings to <CR><LF>,
            and the resulting data is hashed.
            """
            _data += re.subn(br'\r{0,1}\n', b'\r\n', subject.encode('latin-1'))[0]

        if len(_data) == 0:
            raise NotImplementedError(self.type)

        # update our signature packet lengths before proceeding, in case they are wrong
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
        hcontext.append(self._signature.header.version)
        hcontext.append(self.type)
        hcontext.append(self.key_algorithm)
        hcontext.append(self.hash_algorithm)
        hcontext += self._signature.subpackets.__hashbytes__()
        hlen = len(hcontext)
        _data += hcontext
        _data += b'\x04\xff'
        _data += self.int_to_bytes(hlen, 4)
        return bytes(_data)

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
    def primary(self):
        raise NotImplementedError()

    @property
    def name(self):
        return self._uid.name

    @property
    def comment(self):
        return self._uid.comment

    @property
    def email(self):
        return self._uid.email

    def __init__(self):
        self._uid = None
        self._signatures = collections.deque()
        self._parent = None


class PGPMessage(PGPObject, Exportable):
    @staticmethod
    def dash_unescape(text):
        return re.subn(r'^- -', '-', text, flags=re.MULTILINE)[0]

    @staticmethod
    def dash_escape(text):
        return re.subn(r'^-', '- -', text, flags=re.MULTILINE)[0]

    @property
    def __sig__(self):
        return [pkt for pkt in self._contents if isinstance(pkt, PGPSignature)]

    @property
    def is_encrypted(self):
        return self.type == 'encrypted'

    @property
    def is_signed(self):
        return self.type in ['cleartext', 'signed']

    @property
    def issuers(self):
        return set().union(*[[pkt.encrypter for pkt in self._contents if isinstance(pkt, PKESessionKey)],
                             [pkt.signer for pkt in self._contents if isinstance(pkt, (Signature, OnePassSignature, PGPSignature))]
                             ])

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
            m = [pkt for pkt in self._contents if isinstance(pkt, (CompressedData, LiteralData))][0]

            if isinstance(m, CompressedData):
                return m.packets[0].contents

            return m.contents

        if self.type == 'encrypted':
            return self._contents[-1]

        raise NotImplementedError(self.type)

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
        ##TODO: this can be gleaned from any signatures in the message. It might not be worth even storing this here,
        #       since it will need to be computed for constructed messages, anyway
        self._halgs = []

    def __bytes__(self):
        return b''.join([ p.__bytes__() for p in self._contents if isinstance(p, (Packet, PGPMessage, PGPSignature)) ])

    def __str__(self):
        if self.type == 'cleartext':
            return "-----BEGIN PGP SIGNED MESSAGE-----\n" \
                   "Hash: {hashes:s}\n\n" \
                   "{cleartext:s}\n" \
                   "{signature:s}".format(hashes=','.join([s.hash_algorithm.name for s in self.__sig__]),
                                          cleartext=self.dash_escape(self._contents[0]),
                                          signature=super(PGPMessage, self).__str__())

        return super(PGPMessage, self).__str__()

    @classmethod
    def new(cls, message, **kwargs):
        prefs = {'sensitive': False,
                 'compress': True,
                 'compalg': CompressionAlgorithm.ZIP,
                 'format': 'b'}
        prefs.update(kwargs)

        msg = PGPMessage()

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
        if prefs['compress']:
            _m = CompressedData()
            _m.calg = prefs['compalg']
            _m.packets.append(lit)
            _m.update_hlen()

        msg._contents.append(_m)

        return msg

    def encrypt(self, passphrase):
        raise NotImplementedError()

    def decrypt(self, passphrase):
        if not self.is_encrypted:
            raise PGPError("This message is not encrypted!")

        for skesk in [pkt for pkt in self._contents if isinstance(pkt, SKESessionKey)]:
            symalg, key = skesk.decrypt_sk(passphrase)
            del passphrase
            break

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
            self._halgs = unarmored['hashes'] if unarmored['hashes'] is not None else ['MD5']
            while len(data) > 0:
                pkt = Packet(data)
                if not isinstance(pkt, Signature):
                    warnings.warn("Discarded unexpected packet: {:s}".format(pkt.__class__.__name__))
                sig = PGPSignature()
                sig._signature = pkt
                self._contents.append(sig)

        else:
            while len(data) > 0:
                self._contents.append(Packet(data))


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
        pkids = sorted(list(set().union([m.pop(alias) for m in self._aliases if alias in m])),
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
