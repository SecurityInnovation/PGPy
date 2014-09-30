""" pgp.py

this is where the armorable PGP block objects live
"""
import binascii
import bisect
import collections
import contextlib
import functools
import itertools
import operator
import os
import re
import warnings

import six

from datetime import datetime
from datetime import timedelta

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from .errors import PGPDecryptionError
from .errors import PGPError

from .constants import CompressionAlgorithm
from .constants import Features
from .constants import HashAlgorithm
from .constants import ImageEncoding
from .constants import KeyFlags
from .constants import PacketTag
from .constants import PubKeyAlgorithm
from .constants import RevocationReason
from .constants import SignatureType
from .constants import SymmetricKeyAlgorithm

from .decorators import KeyAction

from .packet import Key
from .packet import MDC
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

from .types import Armorable
from .types import PGPObject
from .types import SignatureVerification


def _deque_insort(seq, item):
    i = bisect.bisect_left(seq, item)
    seqlen = len(seq)

    # go left if i is in the first half of the list
    if i < (seqlen // 2):
        seq.rotate(- i)
        seq.appendleft(item)
        seq.rotate(i)

    # go right if i is in the second half
    else:
        i = (seqlen - i)
        seq.rotate(i)
        seq.append(item)
        seq.rotate(- i)


def _deque_popat(seq, i):
    seq.rotate(- i)
    item = seq.popleft()
    seq.rotate(i)

    return item


def _deque_resort(seq, item):
    # find where item is
    i = bisect.bisect_left(seq, item)
    if i != len(seq) and seq[i] == item:
        _deque_insort(seq, _deque_popat(seq, i))
        return
    raise ValueError


class PGPSignature(PGPObject, Armorable):
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
    def key_expiration(self):
        return next(iter(self._signature.subpackets.get('KeyExpirationTime', None)), None)

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

    def __lt__(self, other):
        return self.created < other.created

    def __add__(self, other):
        if isinstance(other, Signature):
            if self._signature is None:
                self._signature = other
                return self

        ##TODO: this is not a great way to do this
        if other.__class__.__name__ == 'EmbeddedSignature':
            self._signature = other
            return self

        raise TypeError

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
            _data += bytearray(subject)

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
                _s = subject._parent.hashdata

            elif isinstance(subject, PGPKey) and not subject.is_primary:
                _s = subject._parent.hashdata

            elif isinstance(subject, PGPKey) and subject.is_primary:
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
        unarmored = self.ascii_unarmor(packet)
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
    def is_primary(self):
        return bool(next(iter(self.selfsig._signature.subpackets['h_PrimaryUserID']), False))

    @property
    def is_uid(self):
        return isinstance(self._uid, UserID)

    @property
    def is_ua(self):
        return isinstance(self._uid, UserAttribute)

    @property
    def selfsig(self):
        if self._parent is not None:
            return next((sig for sig in reversed(self._signatures) if sig.signer == self._parent.fingerprint.keyid), None)

    @property
    def signers(self):
        return set(s.signer for s in self.__sig__)

    @property
    def hashdata(self):
        if self.is_uid:
            return self._uid.__bytes__()[len(self._uid.header):]

        if self.is_ua:
            return self._uid.subpackets.__bytes__()

    @classmethod
    def new(cls, photo=None, name=None, comment="", email="", **kwargs):
        uid = PGPUID()
        if photo is not None:
            uid._uid = UserAttribute()
            uid._uid.image.image = bytearray(photo)
            uid._uid.image.iencoding = ImageEncoding.encodingof(photo)
            uid._uid.update_hlen()

        if name is not None:
            uid._uid = UserID()
            uid._uid.name = name
            uid._uid.comment = comment
            uid._uid.email = email
            uid._uid.update_hlen()

        if uid._uid is None:
            raise ValueError()

        return uid

    def __init__(self):
        super(PGPUID, self).__init__()
        self._uid = None
        self._signatures = collections.deque()
        self._parent = None

    def __repr__(self):
        return "<PGPUID [{:s}][{}] at 0x{:02X}>".format(self._uid.__class__.__name__, self.selfsig.created, id(self))

    def __lt__(self, other):
        if self.is_uid == other.is_uid:
            if self.is_primary == other.is_primary:
                return self.selfsig > other.selfsig

            if self.is_primary:
                return True

            return False

        if self.is_uid and other.is_ua:
            return True

        if self.is_ua and other.is_uid:
            return False

    def __add__(self, other):
        if isinstance(other, PGPSignature):
            _deque_insort(self._signatures, other)

            # is this a new self-signature?
            if self._parent is not None and self in self._parent and other is self.selfsig and len(self._signatures) > 1:
                _deque_resort(self._parent._uids, self)

            return self

        if isinstance(other, UserID) and self._uid is None:
            self._uid = other
            return self

        if isinstance(other, UserAttribute) and self._uid is None:
            self._uid = other
            return self

        raise TypeError("unsupported operand type(s) for +=: '{:s}' and '{:s}'"
                        "".format(self.__class__.__name__, other.__class__.__name__))


class PGPMessage(PGPObject, Armorable):
    @staticmethod
    def dash_unescape(text):
        return re.subn(r'^- -', '-', text, flags=re.MULTILINE)[0]

    @staticmethod
    def dash_escape(text):
        return re.subn(r'^-', '- -', text, flags=re.MULTILINE)[0]

    @property
    def encrypters(self):
        return set(m.encrypter for m in self._sessionkeys if isinstance(m, PKESessionKey))

    @property
    def is_compressed(self):
        return self._compression != CompressionAlgorithm.Uncompressed

    @property
    def is_encrypted(self):
        return isinstance(self._message, (SKEData, IntegrityProtectedSKEData))

    @property
    def is_signed(self):
        return len(self._signatures) > 0

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
        if self.type in ['cleartext', 'encrypted']:
            return self._message

        if self.type == 'literal':
            return self._message.contents

    @property
    def signatures(self):
        return list(self._signatures)

    @property
    def signers(self):
        return set(m.signer for m in self._signatures)

    @property
    def type(self):
        ##TODO: it might be better to use an Enum for the output of this
        if isinstance(self._message, six.string_types):
            return 'cleartext'

        if isinstance(self._message, LiteralData):
            return 'literal'

        if isinstance(self._message, (SKEData, IntegrityProtectedSKEData)):
            return 'encrypted'

        return 'unknown'

    def __init__(self):
        super(PGPMessage, self).__init__()
        self._compression = CompressionAlgorithm.Uncompressed
        self._message = None
        self._mdc = None
        self._signatures = collections.deque()
        self._sessionkeys = []

    def __bytes__(self):
        if self.is_compressed:
            comp = CompressedData()
            comp.calg = self._compression
            comp.packets = [pkt for pkt in self]
            comp.update_hlen()
            return comp.__bytes__()

        return b''.join(pkt.__bytes__() for pkt in self)

    def __str__(self):
        if self.type == 'cleartext':
            return "-----BEGIN PGP SIGNED MESSAGE-----\n" \
                   "Hash: {hashes:s}\n\n" \
                   "{cleartext:s}\n" \
                   "{signature:s}".format(hashes=','.join(s.hash_algorithm.name for s in self.signatures),
                                          cleartext=self.dash_escape(self._message),
                                          signature=super(PGPMessage, self).__str__())

        return super(PGPMessage, self).__str__()

    def __iter__(self):
        if self.type == 'cleartext':
            for sig in self._signatures:
                yield sig

        elif self.is_encrypted:
            for pkt in self._sessionkeys:
                yield pkt
            yield self.message

        else:
            ##TODO: is it worth coming up with a way of disabling one-pass signing?
            for sig in self._signatures:
                ops = sig.make_onepass()
                if sig is not self._signatures[-1]:
                    ops.nested = True
                yield ops

            yield self._message
            if self._mdc is not None:
                yield self._mdc

            for sig in self._signatures:
                yield sig

    def __add__(self, other):
        if isinstance(other, CompressedData):
            self._compression = CompressedData.calg
            for pkt in other.packets:
                self += pkt
            return self

        if isinstance(other, (six.string_types, LiteralData, SKEData, IntegrityProtectedSKEData)):
            if self._message is None:
                self._message = other
                return self

        if isinstance(other, MDC):
            if self._mdc is None:
                self._mdc = other
                return self

        if isinstance(other, OnePassSignature):
            # these are "generated" on the fly during composition
            return self

        if isinstance(other, Signature):
            other = PGPSignature() + other

        if isinstance(other, PGPSignature):
            _deque_insort(self._signatures, other)
            return self

        if isinstance(other, (PKESessionKey, SKESessionKey)):
            self._sessionkeys.append(other)
            return self

        if isinstance(other, PGPMessage):
            self._message = other._message
            self._mdc = other._mdc
            self._compression = other._compression
            self._sessionkeys += other._sessionkeys
            self._signatures += other._signatures
            return self

        raise NotImplementedError(str(type(other)))

    @classmethod
    def new(cls, message, **kwargs):
        prefs = {'cleartext': False,
                 'sensitive': False,
                 'compression': CompressionAlgorithm.ZIP,
                 'format': 'b'}
        prefs.update(kwargs)

        if prefs['cleartext']:
            _m = message

        else:
            # load literal data
            lit = LiteralData()
            lit._contents = bytearray(six.b(message))
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

        msg = PGPMessage() + _m
        msg._compression = prefs['compression']

        return msg

    def encrypt(self, passphrase, sessionkey=None, **prefs):
        cipher_algo = prefs.pop('cipher', SymmetricKeyAlgorithm.AES256)
        hash_algo = prefs.pop('hash', HashAlgorithm.SHA256)

        # set up a new SKESessionKeyV4
        skesk = SKESessionKeyV4()
        skesk.s2k.usage = 255
        skesk.s2k.specifier = 3
        skesk.s2k.halg = hash_algo
        skesk.s2k.encalg = cipher_algo
        skesk.s2k.count = skesk.s2k.halg.tuned_count

        if sessionkey is None:
            sessionkey = cipher_algo.gen_key()
        skesk.encrypt_sk(passphrase, sessionkey)
        del passphrase

        msg = PGPMessage() + skesk

        if not self.is_encrypted:
            skedata = IntegrityProtectedSKEDataV1()
            skedata.encrypt(sessionkey, cipher_algo, self.__bytes__())
            msg += skedata

        else:
            msg += self

        return msg

    def decrypt(self, passphrase):
        if not self.is_encrypted:
            raise PGPError("This message is not encrypted!")

        for skesk in iter(sk for sk in self._sessionkeys if isinstance(sk, SKESessionKey)):
            try:
                symalg, key = skesk.decrypt_sk(passphrase)
                decmsg = PGPMessage()
                decmsg.parse(self.message.decrypt(key, symalg))

            except (TypeError, ValueError, NotImplementedError, PGPDecryptionError):
                continue

            else:
                del passphrase
                break

        else:
            raise PGPDecryptionError("Decryption failed")

        return decmsg

    def parse(self, packet):
        unarmored = self.ascii_unarmor(packet)
        data = unarmored['body']

        if unarmored['magic'] is not None and unarmored['magic'] not in ['MESSAGE', 'SIGNATURE']:
            raise ValueError('Expected: MESSAGE. Got: {}'.format(str(unarmored['magic'])))

        if unarmored['headers'] is not None:
            self.ascii_headers = unarmored['headers']

        # cleartext signature
        if unarmored['magic'] == 'SIGNATURE':
            # the composition for this will be the 'cleartext' as a str,
            # followed by one or more signatures (each one loaded into a PGPSignature)
            self += self.dash_unescape(unarmored['cleartext'])
            while len(data) > 0:
                pkt = Packet(data)
                if not isinstance(pkt, Signature):
                    warnings.warn("Discarded unexpected packet: {:s}".format(pkt.__class__.__name__), stacklevel=2)
                    continue
                self += PGPSignature() + pkt

        else:
            while len(data) > 0:
                self += Packet(data)


class PGPKey(PGPObject, Armorable):
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

        else:  # pragma: no cover
            raise PGPError("Incomplete key")

    @property
    def compprefs(self):
        if self.is_primary or len(self._uids) > 0:
            return self._uids[0].selfsig.compprefs

        elif self.parent is not None:
            return self.parent.compprefs

        else:  # pragma: no cover
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

        else:  # pragma: no cover
            raise PGPError("Incomplete key")

    @property
    def is_expired(self):
        try:
            expires = min(sig.key_expiration.expires for sig in self.self_signatures if sig.key_expiration is not None)

        except ValueError:
            return False

        else:
            return datetime.utcnow() <= (self.created + expires)

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

        if not self.is_protected:
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
    def self_signatures(self):
        for sig in self._signatures:
            if sig.signer == self.fingerprint.keyid:
                yield sig

        if self.is_primary:
            for sig in iter(u.selfsig for u in self.userids):
                yield sig

        else:
            for sig in self.parent.self_signatures:
                yield sig

    @property
    def signatures(self):
        return list(self._signatures)

    @property
    def signers(self):
        return {sig.signer for sig in self.__sig__}

    @property
    def subkeys(self):
        return self._children

    @property
    def usageflags(self):
        if self.is_primary:
            return set(self._uids[0].selfsig.key_flags)

        else:
            return set(self._signatures[0].key_flags)

    @property
    def userids(self):
        return [u for u in self._uids if u.is_uid]

    @property
    def userattributes(self):
        return [u for u in self._uids if u.is_ua]

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
        for sig in [ s for s in self.signatures if not s.embedded and s.exportable ]:
            _bytes += sig.__bytes__()
        # one or more User IDs, followed by their signatures
        for uid in self._uids:
            _bytes += uid._uid.__bytes__()
            _bytes += b''.join(s.__bytes__() for s in uid._signatures if s.exportable)
        # subkeys
        for sk in self._children.values():
            _bytes += sk.__bytes__()

        return bytes(_bytes)

    def __repr__(self):
        return "<PGPKey [{:s}][0x{:s}] at 0x{:02X}>" \
               "".format(self._key.__class__.__name__, self.fingerprint.keyid, id(self))

    def __contains__(self, item):
        if isinstance(item, PGPKey):
            return item.fingerprint.keyid in self._children

        if isinstance(item, PGPUID):
            return item in self._uids

        if isinstance(item, PGPSignature):
            return item in self._signatures

        raise TypeError

    def __add__(self, other):
        if isinstance(other, Key) and self._key is None:
            self._key = other
            return self

        if isinstance(other, PGPKey) and not other.is_primary and other.is_public == self.is_public:
            other._parent = self
            self._children[other.fingerprint.keyid] = other
            return self

        if isinstance(other, PGPSignature):
            _deque_insort(self._signatures, other)
            return self

        if isinstance(other, PGPUID):
            other._parent = self
            _deque_insort(self._uids, other)
            return self

        raise TypeError("unsupported operand type(s) for +=: '{:s}' and '{:s}'"
                        "".format(self.__class__.__name__, other.__class__.__name__))

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

    def add_uid(self, uid, selfsign=True, **kwargs):
        prefs = {'sigtype': SignatureType.Positive_Cert,
                 'usage': [],
                 'hashprefs': [],
                 'cipherprefs': [],
                 'compprefs': [],
                 'primary': False}
        prefs.update(kwargs)

        uid._parent = self
        if selfsign:
            uid += self.sign(uid, **prefs)

        self += uid

    def del_uid(self, search):
        i = next( (i for i, u in enumerate(self._uids)
                   if search in filter(lambda a: a is not None, (u.name, u.comment, u.email))),
                  None)

        if i is None:
            raise PGPError("uid '{:s}' not found".format(search))

        _deque_popat(self._uids, i)

    @KeyAction(KeyFlags.Sign, KeyFlags.Certify, is_unlocked=True, is_public=False)
    def sign(self, subject, **prefs):
        hash_algo = prefs.pop('hash', next(iter(self.hashprefs)))
        default_types = [(PGPUID, [], SignatureType.Generic_Cert),
                         (PGPMessage, [getattr(subject, 'type', None) == 'cleartext'], SignatureType.CanonicalDocument)]
        default_type = next(iter(dt for c, c_, dt in default_types if isinstance(subject, c) and all(c_)), SignatureType.BinaryDocument)
        sig_type = prefs.pop('sigtype', default_type)

        sig = PGPSignature.new(sig_type, self.key_algorithm, hash_algo, self.fingerprint.keyid)

        ##TODO: I'm still not completely satisfied with this giant mess, but it's at least a little cleaner than before
        legal = collections.namedtuple('legal', ['id', 'types', 'criteria', 'sigtypes'])
        allowed_combos = [legal(id=None, types=type(None), criteria=[], sigtypes={SignatureType.Timestamp}),
                          legal(id='load', types=six.string_types, criteria=[], sigtypes={SignatureType.BinaryDocument}),
                          legal(id='msg', types=PGPMessage, criteria=[getattr(subject, 'type', None) == 'cleartext'],
                                sigtypes={SignatureType.CanonicalDocument}),
                          legal(id='msg', types=PGPMessage, criteria=[getattr(subject, 'type', None) != 'cleartext'],
                                sigtypes={SignatureType.BinaryDocument}),
                          legal(id='revoke', types=PGPUID, criteria=[], sigtypes={SignatureType.CertRevocation}),
                          legal(id='revoke', types=PGPKey, criteria=[getattr(subject, 'is_primary', False)],
                                sigtypes={SignatureType.KeyRevocation}),
                          legal(id='revoke', types=PGPKey, criteria=[getattr(subject, 'is_primary', None) is False],
                                sigtypes={SignatureType.SubkeyRevocation}),
                          legal(id='selfcertify', types=(PGPUID, PGPKey),
                                criteria=[ (getattr(subject, 'fingerprint', None) if isinstance(subject, PGPKey) else
                                            getattr(getattr(subject, '_parent', None), 'fingerprint', None)) == self.fingerprint],
                                sigtypes=SignatureType.certifications ^ {SignatureType.CertRevocation}),
                          legal(id='bind_sub', types=PGPKey,
                                criteria=[getattr(subject, 'is_primary', None) is False,
                                          getattr(getattr(subject, '_parent', None), 'fingerprint', None) == self.fingerprint],
                                sigtypes={SignatureType.Subkey_Binding}),
                          legal(id='bind_pri', types=PGPKey,
                                criteria=[getattr(subject, 'is_primary', None) is True,
                                          getattr(self, '_parent', None) is not None,
                                          getattr(subject, 'fingerprint', None) == getattr(self._parent, 'fingerprint', False)],
                                sigtypes={SignatureType.PrimaryKey_Binding}),
                          legal(id='certify', types=PGPUID, criteria=[],
                                sigtypes=SignatureType.certifications ^ {SignatureType.CertRevocation}),
                          legal(id='directkey', types=PGPKey, criteria=[], sigtypes={SignatureType.DirectlyOnKey})]

        combo = next((c for c in allowed_combos
                      if isinstance(subject, c.types) and all(c.criteria) and sig.type in c.sigtypes), None)

        if combo is None:
            raise PGPError('SignatureType.{:s} not supported on subject type {}'.format(sig.type.name, str(type(subject))))

        if combo.id == 'msg':
            subject = subject.message

        if combo.id == 'revoke':
            reason = prefs.pop('reason', RevocationReason.NotSpecified)
            comment = prefs.pop('comment', '')
            sig._signature.subpackets.addnew('ReasonForRevocation', hashed=True, code=reason, string=comment)

        if combo.id in ['selfcertify', 'directkey', 'bind_sub']:
            usage_flags = prefs.pop('usage', [])
            sig._signature.subpackets.addnew('KeyFlags', hashed=True, flags=usage_flags)

        if combo.id == 'bind_sub' and subject.key_algorithm.can_sign:
            esig = self.subkeys[subject.fingerprint.keyid].sign(self, ignore_usage=True, sigtype=SignatureType.PrimaryKey_Binding)
            sig._signature.subpackets.addnew('EmbeddedSignature', hashed=False, _sig=esig._signature)

        if combo.id in ['selfcertify', 'directkey']:
            flag_opts = [ ('cipherprefs', 'PreferredSymmetricAlgorithms'),
                          ('hashprefs', 'PreferredHashAlgorithms'),
                          ('compprefs', 'PreferredCompressionAlgorithms'), ]
            for flags, sp in iter((prefs.pop(f, []), sp) for f, sp in flag_opts):
                sig._signature.subpackets.addnew(sp, hashed=True, flags=flags)

        if combo.id in ['selfcertify', 'certify', 'directkey']:
            revocable = prefs.pop('revocable', None)
            if revocable is not None:
                sig._signature.subpackets.addnew('Revocable', hashed=True, bflag=revocable)

            exportable = prefs.pop('exportable', None)
            if exportable is not None:
                sig._signature.subpackets.addnew('Exportable', hashed=True, bflag=exportable)

        if combo.id == 'selfcertify' and isinstance(subject, PGPUID):
            sig._signature.subpackets.addnew('Features', hashed=True, flags=[Features.ModificationDetection])

            primary = prefs.pop('primary', None)
            if primary is not None:
                sig._signature.subpackets.addnew('PrimaryUserID', hashed=True, primary=primary)

        if combo.id == 'directkey':
            revoker = prefs.pop('revoker', None)
            if revoker is not None:
                sig._signature.subpackets.addnew('RevocationKey', hashed=True, fingerprint=revoker)

        sigdata = sig.hashdata(subject)
        h2 = hash_algo.hasher
        h2.update(sigdata)
        sig._signature.hash2 = bytearray(h2.digest()[:2])

        if self.key_algorithm == PubKeyAlgorithm.RSAEncryptOrSign:
            sigopts = (padding.PKCS1v15(), getattr(hashes, hash_algo.name)(), default_backend())

        elif self.key_algorithm == PubKeyAlgorithm.DSA:
            sigopts = (getattr(hashes, hash_algo.name)(), default_backend())

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

        def _filter_sigs(sigs):
            _ids = {self.fingerprint.keyid} | set(self.subkeys)
            return [ sig for sig in sigs if sig.signer in _ids ]

        # collect signature(s)
        if isinstance(signature, PGPSignature):
            if signature.signer != self.fingerprint.keyid and signature.signer not in self.subkeys:
                raise PGPError("Incorrect key. Expected: {:s}".format(signature.signer))
            sspairs.append((signature, subject))

        if isinstance(subject, PGPMessage):
            sspairs += [ (sig, subject.message) for sig in _filter_sigs(subject.signatures) ]

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

                # temporary testing
                def _hash2(sd):
                    _h = sig.hash_algorithm.hasher
                    _h.update(sd)
                    return _h.digest()[:2]

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

    @KeyAction(KeyFlags.EncryptCommunications, is_public=True)
    def encrypt(self, message, sessionkey=None, **prefs):
        cipher_algo = prefs.pop('cipher', next(iter(self.cipherprefs)))
        hash_algo = prefs.pop('hash', next(iter(self.hashprefs)))

        if cipher_algo not in self.cipherprefs:
            warnings.warn("Selected symmetric algorithm not in key preferences", stacklevel=3)

        if hash_algo not in self.hashprefs:
            warnings.warn("Selected hash algorithm not in key preferences", stacklevel=3)

        if message.is_compressed and message._compression not in self.compprefs:
            warnings.warn("Selected compression algorithm not in key preferences", stacklevel=3)

        if sessionkey is None:
            sessionkey = cipher_algo.gen_key()

        # set up a new PKESessionKeyV3
        pkesk = PKESessionKeyV3()
        pkesk.encrypter = bytearray(binascii.unhexlify(self.fingerprint.keyid.encode('latin-1')))
        pkesk.pkalg = self.key_algorithm
        pkesk.encrypt_sk(self.__key__.__pubkey__(), cipher_algo, sessionkey)

        if message.is_encrypted:
            _m = message

        else:
            _m = PGPMessage()
            skedata = IntegrityProtectedSKEDataV1()
            skedata.encrypt(sessionkey, cipher_algo, message.__bytes__())
            _m += skedata

        _m += pkesk

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

        pkesk = next(pk for pk in message._sessionkeys if pk.pkalg == self.key_algorithm and pk.encrypter == self.fingerprint.keyid)
        alg, key = pkesk.decrypt_sk(self.__key__.__privkey__())

        # now that we have the symmetric cipher used and the key, we can decrypt the actual message
        decmsg = PGPMessage()
        decmsg.parse(message.message.decrypt(key, alg))

        return decmsg

    def parse(self, data):
        unarmored = self.ascii_unarmor(data)
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
        # last holds the last non-signature thing processed

        getpkt = lambda d: Packet(d) if len(d) > 0 else None
        getpkt = iter(functools.partial(getpkt, data), None)

        class pktgrouper(object):
            def __init__(self):
                self.last = None

            def __call__(self, pkt):
                if pkt.header.tag != PacketTag.Signature:
                    self.last = '{:02X}_{:s}'.format(id(pkt), pkt.__class__.__name__)
                return self.last

        while True:
            for group in iter(group for _, group in itertools.groupby(getpkt, key=pktgrouper()) if not _.endswith('Opaque')):
                pkt = next(group)

                # deal with pkt first
                if isinstance(pkt, Key):
                    pgpobj = (self if self._key is None else PGPKey()) + pkt

                elif isinstance(pkt, (UserID, UserAttribute)):
                    pgpobj = PGPUID() + pkt

                else:
                    break

                # add signatures to whatever we got
                [ operator.iadd(pgpobj, PGPSignature() + sig) for sig in group if not isinstance(sig, Opaque) ]

                # and file away pgpobj
                if isinstance(pgpobj, PGPKey) and pgpobj.is_primary:
                    keys[(pgpobj.fingerprint.keyid, pgpobj.is_public)] = pgpobj

                elif isinstance(pgpobj, PGPKey) and not pgpobj.is_primary:
                    # parent is likely the most recently parsed primary key
                    keys[next(reversed(keys))] += pgpobj

                    bsigs = [ pkb for skb in pgpobj._signatures if skb.type == SignatureType.Subkey_Binding
                              for pkb in skb._signature.subpackets['EmbeddedSignature'] ]
                    for es in bsigs:
                        esig = PGPSignature() + es
                        esig.parent = es
                        pgpobj += esig

                elif isinstance(pgpobj, PGPUID):
                    # parent is likely the most recently parsed primary key
                    keys[next(reversed(keys))] += pgpobj

                else:
                    break
            else:
                # finished normally
                break

            # this will only be reached called if the inner loop hit a break
            warnings.warn("Warning: Orphaned packet detected! {:s}".format(repr(pkt)), stacklevel=2)
            orphaned[(pkt.header.tag, len([k for k, v in orphaned.keys() if k == pkt.header.tag]))] = pkt
            for pkt in group:
                orphaned[(pkt.header.tag, len([k for k, v in orphaned.keys() if k == pkt.header.tag]))] = pkt

        # remove the reference to self from keys
        [ keys.pop((getattr(self, 'fingerprint.keyid', '~'), None), t) for t in (True, False) ]
        return {'keys': keys, 'orphaned': orphaned}


class PGPKeyring(collections.Container, collections.Iterable, collections.Sized):
    def __init__(self, *args):
        super(PGPKeyring, self).__init__()
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
        def _preiter(first, iterable):
            yield first
            for item in iterable:
                yield item

        loaded = set()
        for key in [ item for ilist in iter(ilist if isinstance(ilist, (tuple, list)) else [ilist] for ilist in args)
                     for item in ilist ]:
            _key = PGPKey()
            keys = _key.parse(key)

            for ik in _preiter(_key, keys['keys'].values()):
                self._add_key(ik)
                loaded |= {ik.fingerprint} | {isk.fingerprint for isk in ik.subkeys.values()}

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
