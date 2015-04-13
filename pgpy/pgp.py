""" pgp.py

this is where the armorable PGP block objects live
"""
import binascii
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

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from .constants import CompressionAlgorithm
from .constants import Features
from .constants import HashAlgorithm
from .constants import ImageEncoding
from .constants import KeyFlags
from .constants import NotationDataFlags
from .constants import PacketTag
from .constants import PubKeyAlgorithm
from .constants import RevocationKeyClass
from .constants import RevocationReason
from .constants import SignatureType
from .constants import SymmetricKeyAlgorithm

from .decorators import KeyAction

from .errors import PGPDecryptionError
from .errors import PGPError

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
from .types import Fingerprint
from .types import PGPObject
from .types import SignatureVerification
from .types import SorteDeque


class PGPSignature(PGPObject, Armorable):
    @property
    def __sig__(self):
        return self._signature.signature.__sig__()

    @property
    def cipherprefs(self):
        """
        A ``list`` of preferred symmetric algorithms specified in this signature, if any. Otherwise, an empty ``list``.
        """
        if 'PreferredSymmetricAlgorithms' in self._signature.subpackets:
            return next(iter(self._signature.subpackets['h_PreferredSymmetricAlgorithms'])).flags
        return []

    @property
    def compprefs(self):
        """
        A ``list`` of preferred compression algorithms specified in this signature, if any. Otherwise, an empty ``list``.
        """
        if 'PreferredCompressionAlgorithms' in self._signature.subpackets:
            return next(iter(self._signature.subpackets['h_PreferredCompressionAlgorithms'])).flags
        return []

    @property
    def created(self):
        """
        A :py:obj:`~datetime.datetime` of when this signature was created.
        """
        return self._signature.subpackets['h_CreationTime'][-1].created

    @property
    def embedded(self):
        return self.parent is not None

    @property
    def expires_at(self):
        """
        A :py:obj:`~datetime.datetime` of when this signature expires, if a signature expiration date is specified.
        Otherwise, ``False``
        """
        if 'SignatureExpirationTime' in self._signature.subpackets:
            expd = next(iter(self._signature.subpackets['SignatureExpirationTime'])).expires
            return self.created + expd
        return False

    @property
    def exportable(self):
        """
        ``False`` if this signature is marked as being not exportable. Otherwise, ``True``.
        """
        if 'ExportableCertification' in self._signature.subpackets:
            return bool(next(iter(self._signature.subpackets['ExportableCertification'])))

        return True

    @property
    def features(self):
        """
        A ``set`` of implementation features specified in this signature, if any. Otherwise, an empty ``set``.
        """
        if 'Features' in self._signature.subpackets:
            return next(iter(self._signature.subpackets['Features'])).flags
        return set()

    @property
    def hash2(self):
        return self._signature.hash2

    @property
    def hashprefs(self):
        """
        A ``list`` of preferred hash algorithms specified in this signature, if any. Otherwise, an empty ``list``.
        """
        if 'PreferredHashAlgorithms' in self._signature.subpackets:
            return next(iter(self._signature.subpackets['h_PreferredHashAlgorithms'])).flags
        return []

    @property
    def hash_algorithm(self):
        """
        The :py:obj:`~constants.HashAlgorithm` used when computing this signature.
        """
        return self._signature.halg

    @property
    def is_expired(self):
        """
        ``True`` if the signature has an expiration date, and is expired. Otherwise, ``False``
        """
        expires_at = self.expires_at
        if expires_at is not False and expires_at != self.created:
            return expires_at < datetime.utcnow()

        return False

    @property
    def key_algorithm(self):
        """
        The :py:obj:`~constants.PubKeyAlgorithm` of the key that generated this signature.
        """
        return self._signature.pubalg

    @property
    def key_expiration(self):
        if 'KeyExpirationTime' in self._signature.subpackets:
            return next(iter(self._signature.subpackets['KeyExpirationTime'])).expires
        return None

    @property
    def key_flags(self):
        """
        A ``set`` of :py:obj:`~constants.KeyFlags` specified in this signature, if any. Otherwise, an empty ``set``.
        """
        if 'KeyFlags' in self._signature.subpackets:
            return next(iter(self._signature.subpackets['h_KeyFlags'])).flags
        return set()

    @property
    def keyserver(self):
        """
        The preferred key server specified in this signature, if any. Otherwise, an empty ``str``.
        """
        if 'PreferredKeyServer' in self._signature.subpackets:
            return next(iter(self._signature.subpackets['h_PreferredKeyServer'])).uri
        return ''

    @property
    def keyserverprefs(self):
        """
        A ``list`` of :py:obj:`~constants.KeyServerPreferences` in this signature, if any. Otherwise, an empty ``list``.
        """
        if 'KeyServerPreferences' in self._signature.subpackets:
            return next(iter(self._signature.subpackets['h_KeyServerPreferences'])).flags
        return []

    @property
    def magic(self):
        return "SIGNATURE"

    @property
    def notation(self):
        """
        A ``dict`` of notation data in this signature, if any. Otherwise, an empty ``dict``.
        """
        return dict((nd.name, nd.value) for nd in self._signature.subpackets['NotationData'])

    @property
    def policy_uri(self):
        """
        The policy URI specified in this signature, if any. Otherwise, an empty ``str``.
        """
        if 'Policy' in self._signature.subpackets:
            return next(iter(self._signature.subpackets['Policy'])).uri
        return ''

    @property
    def revocable(self):
        """
        ``False`` if this signature is marked as being not revocable. Otherwise, ``True``.
        """
        if 'Revocable' in self._signature.subpackets:
            return bool(next(iter(self._signature.subpackets['Revocable'])))
        return True

    @property
    def revocation_key(self):
        if 'RevocationKey' in self._signature.subpackets:
            raise NotImplementedError()
        return None

    @property
    def signer(self):
        """
        The 16-character Key ID of the key that generated this signature.
        """
        return self._signature.signer

    @property
    def target_signature(self):
        raise NotImplementedError()

    @property
    def type(self):
        """
        The :py:obj:`~constants.SignatureType` of this signature.
        """
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

        if halg is not None:
            sigpkt.halg = halg

        sig._signature = sigpkt
        return sig

    def __init__(self):
        """
        PGPSignature objects represent OpenPGP compliant signatures.

        PGPSignature implements the ``__str__`` method, the output of which will be the signature object in
        OpenPGP-compliant ASCII-armored format.

        PGPSignature implements the ``__bytes__`` method, the output of which will be the signature object in
        OpenPGP-compliant binary format.
        """
        super(PGPSignature, self).__init__()
        self._signature = None
        self.parent = None

    def __bytes__(self):
        return b''.join(s.__bytes__() for s in [self._signature] if s is not None)

    def __repr__(self):
        return "<PGPSignature [{:s}] object at 0x{:02x}>".format(self.type.name, id(self))

    def __lt__(self, other):
        return self.created < other.created

    def __or__(self, other):
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
            _data += re.subn(br'\r?\n', b'\r\n', subject)[0]

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
            if subject.is_primary:
                _s = subject.subkeys[self.signer].hashdata

            else:
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
        """If this is a User ID, the stored name. If this is not a User ID, this will be an empty string."""
        return self._uid.name if isinstance(self._uid, UserID) else ""

    @property
    def comment(self):
        """
        If this is a User ID, this will be the stored comment. If this is not a User ID, or there is no stored comment,
        this will be an empty string.,
        """

        return self._uid.comment if isinstance(self._uid, UserID) else ""

    @property
    def email(self):
        """
        If this is a User ID, this will be the stored email address. If this is not a User ID, or there is no stored
        email address, this will be an empty string.
        """
        return self._uid.email if isinstance(self._uid, UserID) else ""

    @property
    def image(self):
        """
        If this is a User Attribute, this will be the stored image. If this is not a User Attribute, this will be ``None``.
        """
        return self._uid.image.image if isinstance(self._uid, UserAttribute) else None

    @property
    def is_primary(self):
        """
        If the most recent, valid self-signature specifies this as being primary, this will be True. Otherwise, Faqlse.
        """
        return bool(next(iter(self.selfsig._signature.subpackets['h_PrimaryUserID']), False))

    @property
    def is_uid(self):
        """
        ``True`` if this is a User ID, otherwise False.
        """
        return isinstance(self._uid, UserID)

    @property
    def is_ua(self):
        """
        ``True`` if this is a User Attribute, otherwise False.
        """
        return isinstance(self._uid, UserAttribute)

    @property
    def selfsig(self):
        """
        This will be the most recent, self-signature of this User ID or Attribute. If there isn't one, this will be ``None``.
        """
        if self._parent is not None:
            return next((sig for sig in reversed(self._signatures) if sig.signer == self._parent.fingerprint.keyid), None)

    @property
    def signers(self):
        """
        This will be a set of all of the key ids which have signed this User ID or Attribute.
        """
        return set(s.signer for s in self.__sig__)

    @property
    def hashdata(self):
        if self.is_uid:
            return self._uid.__bytes__()[len(self._uid.header):]

        if self.is_ua:
            return self._uid.subpackets.__bytes__()

    @classmethod
    def new(cls, pn, comment="", email=""):
        """
        Create a new User ID or photo.

        :param pn: User ID name, or photo. If this is a ``bytearray``, it will be loaded as a photo.
                   Otherwise, it will be used as the name field for a User ID.
        :type pn: ``bytearray``, ``str``, ``unicode``
        :param comment: The comment field for a User ID. Ignored if this is a photo.
        :type comment: ``str``, ``unicode``
        :param email: The email address field for a User ID. Ignored if this is a photo.
        :type email: ``str``, ``unicode``
        :returns: :py:obj:`PGPUID`
        """
        uid = PGPUID()
        if isinstance(pn, bytearray):
            uid._uid = UserAttribute()
            uid._uid.image.image = pn
            uid._uid.image.iencoding = ImageEncoding.encodingof(pn)
            uid._uid.update_hlen()

        else:
            uid._uid = UserID()
            uid._uid.name = pn
            uid._uid.comment = comment
            uid._uid.email = email
            uid._uid.update_hlen()

        if uid._uid is None:
            raise ValueError()

        return uid

    def __init__(self):
        """
        PGPUID objects represent User IDs and User Attributes for keys.

        PGPUID implements the ``__format__`` method for User IDs, returning a string in the format
        'name (comment) <email>', leaving out any comment or email fields that are not present.
        """
        super(PGPUID, self).__init__()
        self._uid = None
        self._signatures = SorteDeque()
        self._parent = None

    def __repr__(self):
        return "<PGPUID [{:s}][{}] at 0x{:02X}>".format(self._uid.__class__.__name__, self.selfsig.created, id(self))

    def __lt__(self, other):  # pragma: no cover
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

    def __or__(self, other):
        if isinstance(other, PGPSignature):
            self._signatures.insort(other)
            if self._parent is not None and self in self._parent._uids:
                self._parent._uids.resort(self)

            return self

        if isinstance(other, UserID) and self._uid is None:
            self._uid = other
            return self

        if isinstance(other, UserAttribute) and self._uid is None:
            self._uid = other
            return self

        raise TypeError("unsupported operand type(s) for |: '{:s}' and '{:s}'"
                        "".format(self.__class__.__name__, other.__class__.__name__))

    def __format__(self, format_spec):
        if self.is_uid:
            comment = six.u("") if self.comment == "" else six.u(" ({:s})").format(self.comment)
            email = six.u("") if self.email == "" else six.u(" <{:s}>").format(self.email)
            return six.u("{:s}{:s}{:s}").format(self.name, comment, email)

        raise NotImplementedError


class PGPMessage(PGPObject, Armorable):
    @staticmethod
    def dash_unescape(text):
        return re.subn(r'^- -', '-', text, flags=re.MULTILINE)[0]

    @staticmethod
    def dash_escape(text):
        return re.subn(r'^-', '- -', text, flags=re.MULTILINE)[0]

    @property
    def encrypters(self):
        """A ``set`` containing all key ids (if any) to which this message was encrypted."""
        return set(m.encrypter for m in self._sessionkeys if isinstance(m, PKESessionKey))

    @property
    def filename(self):
        if self.type == 'literal':
            return self._message.filename
        return ''

    @property
    def is_compressed(self):
        """``True`` if this message will be compressed when exported"""
        return self._compression != CompressionAlgorithm.Uncompressed

    @property
    def is_encrypted(self):
        """``True`` if this message is encrypted; otherwise, ``False``"""
        return isinstance(self._message, (SKEData, IntegrityProtectedSKEData))

    @property
    def is_sensitive(self):
        return self.type == 'literal' and self._message.filename == '_CONSOLE'

    @property
    def is_signed(self):
        """
        ``True`` if this message is signed; otherwise, ``False``.
        Should always be ``False`` if the message is encrypted.
        """
        return len(self._signatures) > 0

    @property
    def issuers(self):
        """A ``set`` containing all key ids (if any) which have signed or encrypted this message."""
        return self.encrypters | self.signers

    @property
    def magic(self):
        if self.type == 'cleartext':
            return "SIGNATURE"
        return "MESSAGE"

    @property
    def message(self):
        """The message contents"""
        if self.type in ['cleartext', 'encrypted']:
            return self._message

        if self.type == 'literal':
            return self._message.contents

    @property
    def signatures(self):
        """A ``set`` containing all key ids (if any) which have signed this message."""
        return list(self._signatures)

    @property
    def signers(self):
        """A ``set`` containing all key ids (if any) which have signed this message."""
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

        raise NotImplementedError

    def __init__(self):
        """
        PGPMessage objects represent OpenPGP message compositions.

        PGPMessage implements the `__str__` method, the output of which will be the message composition in
        OpenPGP-compliant ASCII-armored format.

        PGPMessage implements the `__bytes__` method, the output of which will be the message composition in
        OpenPGP-compliant binary format.

        Any signatures within the PGPMessage that are marked as being non-exportable will not be included in the output
        of either of those methods.
        """
        super(PGPMessage, self).__init__()
        self._compression = CompressionAlgorithm.Uncompressed
        self._message = None
        self._mdc = None
        self._signatures = SorteDeque()
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
            if self._mdc is not None:  # pragma: no cover
                yield self._mdc

            for sig in self._signatures:
                yield sig

    def __or__(self, other):
        if isinstance(other, CompressedData):
            self._compression = CompressedData.calg
            for pkt in other.packets:
                self |= pkt
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
            other = PGPSignature() | other

        if isinstance(other, PGPSignature):
            self._signatures.insort(other)
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
        """
        Create a new PGPMessage object.

        :param message: The message to be stored.
        :type message: ``str``, ``unicode``, ``bytes``, ``bytearray``
        :returns: :py:obj:`PGPMessage`

        The following optional keyword arguments can be used with :py:meth:`PGPMessage.new`:

        :keyword file: if True, ``message`` should be a path to a file. The contents of that file will be read and used
                       as the contents of the message.
        :type file: ``bool``
        :keyword cleartext: if True, the message will be cleartext with inline signatures.
        :type cleartext: ``bool``
        :keyword sensitive: if True, the filename will be set to '_CONSOLE' to signal other OpenPGP clients to treat
                            this message as being 'for your eyes only'. Ignored if cleartext is True.
        :type sensitive: ``bool``
        :keyword compression: Set the compression algorithm for the new message.
                              Defaults to :py:obj:`CompressionAlgorithm.ZIP`. Ignored if cleartext is True.
        """
        cleartext = kwargs.pop('cleartext', False)
        sensitive = kwargs.pop('sensitive', False)
        compression = kwargs.pop('compression', CompressionAlgorithm.ZIP)
        file = kwargs.pop('file', False)

        filename = ''
        mtime = datetime.utcnow()

        msg = PGPMessage()

        if file and os.path.isfile(message):
            filename = message
            message = bytearray(os.path.getsize(filename))
            mtime = datetime.utcfromtimestamp(os.path.getmtime(filename))

            with open(filename, 'rb') as mf:
                mf.readinto(message)

        if cleartext:
            # cleartext message
            msg |= message

        else:
            # load literal data
            lit = LiteralData()
            lit._contents = bytearray(cls.text_to_bytes(message))
            lit.filename = '_CONSOLE' if sensitive else os.path.basename(filename)
            lit.mtime = mtime
            lit.format = 'b'

            if cls.is_ascii(message):
                lit.format = 't'

            lit.update_hlen()

            msg |= lit
            msg._compression = compression

        return msg

    def encrypt(self, passphrase, sessionkey=None, **prefs):
        """
        Encrypt the contents of this message using a passphrase.
        :param passphrase: The passphrase to use for encrypting this message.
        :type passphrase: ``str``, ``unicode``, ``bytes``

        :optional param sessionkey: Provide a session key to use when encrypting something. Default is ``None``.
                                    If ``None``, a session key of the appropriate length will be generated randomly.

                                    .. warning::

                                        Care should be taken when making use of this option! Session keys *absolutely need*
                                        to be unpredictable! Use the ``gen_key()`` method on the desired
                                        :py:obj:`~constants.SymmetricKeyAlgorithm` to generate the session key!

        :type sessionkey: ``bytes``, ``str``
        :raises: :py:exc:`~errors.PGPEncryptionError`
        :returns: A new :py:obj:`PGPMessage` containing the encrypted contents of this message.
        """
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

        msg = PGPMessage() | skesk

        if not self.is_encrypted:
            skedata = IntegrityProtectedSKEDataV1()
            skedata.encrypt(sessionkey, cipher_algo, self.__bytes__())
            msg |= skedata

        else:
            msg |= self

        return msg

    def decrypt(self, passphrase):
        """
        Attempt to decrypt this message using a passphrase.

        :param passphrase: The passphrase to use to attempt to decrypt this message.
        :type passphrase: ``str``, ``unicode``, ``bytes``
        :raises: :py:exc:`~errors.PGPDecryptionError` if decryption failed for any reason.
        :returns: A new :py:obj:`PGPMessage` containing the decrypted contents of this message
        """
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
            self |= self.dash_unescape(unarmored['cleartext'])
            while len(data) > 0:
                pkt = Packet(data)
                if not isinstance(pkt, Signature):  # pragma: no cover
                    warnings.warn("Discarded unexpected packet: {:s}".format(pkt.__class__.__name__), stacklevel=2)
                    continue
                self |= PGPSignature() | pkt

        else:
            while len(data) > 0:
                self |= Packet(data)


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
        return list(self._signatures)

    @property
    def created(self):
        """A :py:obj:`~datetime.datetime` object of the creation date and time of the key, in UTC."""
        return self._key.created

    @property
    def expires_at(self):
        """A :py:obj:`~datetime.datetime` object of when this key is to be considered expired, if any. Otherwise, ``None``"""
        try:
            expires = min(sig.key_expiration for sig in itertools.chain(iter(uid.selfsig for uid in self.userids), self.self_signatures)
                          if sig.key_expiration is not None)

        except ValueError:
            return None

        else:
            return (self.created + expires)

    @property
    def fingerprint(self):
        """The fingerprint of this key, as a :py:obj:`~pgpy.types.Fingerprint` object."""
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
    def is_expired(self):
        """``True`` if this key is expired, otherwise ``False``"""
        expires = self.expires_at
        if expires is not None:
            return datetime.utcnow() <= expires

        return False

    @property
    def is_primary(self):
        """``True`` if this is a primary key; ``False`` if this is a subkey"""
        return isinstance(self._key, Primary) and not isinstance(self._key, Sub)

    @property
    def is_protected(self):
        """``True`` if this is a private key that is protected with a passphrase, otherwise ``False``"""
        if self.is_public:
            return False

        return self._key.protected

    @property
    def is_public(self):
        """``True`` if this is a public key, otherwise ``False``"""
        return isinstance(self._key, Public) and not isinstance(self._key, Private)

    @property
    def is_unlocked(self):
        """``False`` if this is a private key that is protected with a passphrase and has not yet been unlocked, otherwise ``True``"""
        if self.is_public:
            return True

        if not self.is_protected:
            return True

        return self._key.unlocked

    @property
    def key_algorithm(self):
        """The :py:obj:`constants.PubKeyAlgorithm` pertaining to this key"""
        return self._key.pkalg

    @property
    def magic(self):
        return '{:s} KEY BLOCK'.format('PUBLIC' if (isinstance(self._key, Public) and not isinstance(self._key, Private)) else
                                       'PRIVATE' if isinstance(self._key, Private) else '')

    @property
    def parent(self):
        """The :py:obj:`PGPKey` object of this subkey's parent primary key, if applicable, otherwise ``None``"""
        if self.is_primary:
            return None
        return self._parent

    @property
    def self_signatures(self):
        keyid, keytype = (self.fingerprint.keyid, SignatureType.DirectlyOnKey) if self.is_primary \
            else (self.parent.fingerprint.keyid, SignatureType.Subkey_Binding)

        ##TODO: filter out revoked signatures as well
        for sig in iter(sig for sig in self._signatures
                        if all([sig.type == keytype, sig.signer == keyid, not sig.is_expired])):
            yield sig

    @property
    def signers(self):
        return {sig.signer for sig in self.__sig__}

    @property
    def subkeys(self):
        """An :py:obj:`~collections.OrderedDict` of subkeys bound to this primary key, if applicable,
        selected by 16-character keyid."""
        return self._children

    @property
    def userids(self):
        """A ``list`` of :py:obj:`PGPUID` objects containing User ID information about this key"""
        return [ u for u in self._uids if u.is_uid ]

    @property
    def userattributes(self):
        """A ``list`` of :py:obj:`PGPUID` objects containing one or more images associated with this key"""
        return [u for u in self._uids if u.is_ua]

    @classmethod
    def new(cls, key_algorithm, **kwargs):
        raise NotImplementedError

    def __init__(self):
        """
        PGPKey objects represent OpenPGP compliant keys along with all of their associated data.

        PGPKey implements the `__str__` method, the output of which will be the key composition in
        OpenPGP-compliant ASCII-armored format.

        PGPKey implements the `__bytes__` method, the output of which will be the key composition in
        OpenPGP-compliant binary format.

        Any signatures within the PGPKey that are marked as being non-exportable will not be included in the output
        of either of those methods.
        """
        super(PGPKey, self).__init__()
        self._key = None
        self._children = collections.OrderedDict()
        self._parent = None
        self._signatures = SorteDeque()
        self._uids = SorteDeque()

    def __bytes__(self):
        _bytes = bytearray()
        # us
        _bytes += self._key.__bytes__()
        # our signatures; ignore embedded signatures
        for sig in iter(s for s in self._signatures if not s.embedded and s.exportable):
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
        if isinstance(item, PGPKey):  # pragma: no cover
            return item.fingerprint.keyid in self.subkeys

        if isinstance(item, Fingerprint):  # pragma: no cover
            return item.keyid in self.subkeys

        if isinstance(item, PGPUID):
            return item in self._uids

        if isinstance(item, PGPSignature):
            return item in self._signatures

        raise TypeError

    def __or__(self, other):
        if isinstance(other, Key) and self._key is None:
            self._key = other
            return self

        if isinstance(other, PGPKey) and not other.is_primary and other.is_public == self.is_public:
            other._parent = self
            self._children[other.fingerprint.keyid] = other
            return self

        if isinstance(other, PGPSignature):
            self._signatures.insort(other)

            # if this is a subkey binding signature that has embedded primary key binding signatures, add them to parent
            if other.type == SignatureType.Subkey_Binding:
                for es in iter(pkb for pkb in other._signature.subpackets['EmbeddedSignature']):
                    esig = PGPSignature() | es
                    esig.parent = other
                    self._signatures.insort(esig)

            return self

        if isinstance(other, PGPUID):
            other._parent = self
            self._uids.insort(other)
            return self

        raise TypeError("unsupported operand type(s) for |: '{:s}' and '{:s}'"
                        "".format(self.__class__.__name__, other.__class__.__name__))

    def protect(self):
        raise NotImplementedError()

    @contextlib.contextmanager
    def unlock(self, passphrase):
        """
        Context manager method for unlocking passphrase-protected private keys. Has no effect if the key is not both
        private and passphrase-protected.

        When the context managed block is exited, the unprotected private key material is removed.

        Example::

            privkey = PGPKey()
            privkey.parse(keytext)

            assert privkey.is_protected
            assert privkey.is_unlocked is False
            # privkey.sign("some text") <- this would raise an exception

            with privkey.unlock("TheCorrectPassphrase"):
                # privkey is now unlocked
                assert privkey.is_unlocked
                # so you can do things with it
                sig = privkey.sign("some text")

            # privkey is no longer unlocked
            assert privkey.is_unlocked is False

        Emits a :py:obj:`~warnings.UserWarning` if the key is public or not passphrase protected.

        :param str passphrase: The passphrase to be used to unlock this key.
        :raises: :py:exc:`~pgpy.errors.PGPDecryptionError` if the passphrase is incorrect
        """
        if self.is_public:
            # we can't unprotect public keys because only private key material is ever protected
            warnings.warn("Public keys cannot be passphrase-protected", stacklevel=3)
            yield self
            return

        if not self.is_protected:
            # we can't unprotect private keys that are not protected, because there is no ciphertext to decrypt
            warnings.warn("This key is not protected with a passphrase", stacklevel=3)
            yield self
            return

        try:
            for sk in itertools.chain([self], self.subkeys.values()):
                sk._key.unprotect(passphrase)
            del passphrase
            yield self

        finally:
            # clean up here by deleting the previously decrypted secret key material
            for sk in itertools.chain([self], self.subkeys.values()):
                sk._key.keymaterial.clear()

    def add_uid(self, uid, selfsign=True, **prefs):
        uid._parent = self
        if selfsign:
            uid |= self.certify(uid, SignatureType.Positive_Cert, **prefs)

        self |= uid

    def get_uid(self, search):
        if self.is_primary:
            return next((u for u in self._uids if search in filter(lambda a: a is not None, (u.name, u.comment, u.email))), None)
        return self.parent.get_uid(search)

    def del_uid(self, search):
        u = self.get_uid(search)

        if u is None:
            raise KeyError("uid '{:s}' not found".format(search))

        u._parent = None
        self._uids.remove(u)

    def _get_key_flags(self, user=None):
        if self.is_primary:
            if user is not None:
                user = self.get_uid(user)

            else:
                user = next(iter(self.userids))

            return user.selfsig.key_flags

        return next(self.self_signatures).key_flags

    def _sign(self, subject, sig, **prefs):
        """
        The actual signing magic happens here.
        :param subject: The subject to sign
        :param sig: The :py:obj:`PGPSignature` object the new signature is to be encapsulated within
        :returns: ``sig``, after the signature is added to it.
        """
        user = prefs.pop('user', None)
        uid = None
        if user is not None:
            uid = self.get_uid(user)
        else:
            uid = next(iter(self.userids), None)
            if uid is None and self.parent is not None:
                uid = next(iter(self.parent.userids), None)

        if sig.hash_algorithm is None:
            sig._signature.halg = uid.selfsig.hashprefs[0]

        if self.key_algorithm == PubKeyAlgorithm.RSAEncryptOrSign:
            sigopts = (padding.PKCS1v15(), getattr(hashes, sig.hash_algorithm.name)(),)

        elif self.key_algorithm == PubKeyAlgorithm.DSA:
            sigopts = (getattr(hashes, sig.hash_algorithm.name)(),)

        else:
            raise NotImplementedError(self.key_algorithm)

        if sig.hash_algorithm not in uid.selfsig.hashprefs:
            warnings.warn("Selected hash algorithm not in key preferences", stacklevel=4)

        # signature options that can be applied at any level
        expires = prefs.pop('expires', None)
        notation = prefs.pop('notation', None)
        revocable = prefs.pop('revocable', True)
        policy_uri = prefs.pop('policy_uri', None)

        if expires is not None:
            # expires should be a timedelta, so if it's a datetime, turn it into a timedelta
            if isinstance(expires, datetime):
                expires = expires - self.created

            sig._signature.subpackets.addnew('SignatureExpirationTime', hashed=True, expires=expires)

        if revocable is False:
            sig._signature.subpackets.addnew('Revocable', hashed=True, bflag=revocable)

        if notation is not None:
            for name, value in notation.items():
                # mark all notations as human readable unless value is a bytearray
                flags = NotationDataFlags.HumanReadable
                if isinstance(value, bytearray):
                    flags = 0x00

                sig._signature.subpackets.addnew('NotationData', hashed=True, flags=flags, name=name, value=value)

        if policy_uri is not None:
            sig._signature.subpackets.addnew('Policy', hashed=True, uri=policy_uri)

        if user is not None and uid is not None:
            signers_uid = "{:s}".format(uid)
            sig._signature.subpackets.addnew('SignersUserID', hashed=True, userid=signers_uid)

        # handle an edge case for timestamp signatures vs standalone signatures
        if sig.type == SignatureType.Timestamp and len(sig._signature.subpackets._hashed_sp) > 1:
            sig._signature.sigtype = SignatureType.Standalone

        sigdata = sig.hashdata(subject)
        h2 = sig.hash_algorithm.hasher
        h2.update(sigdata)
        sig._signature.hash2 = bytearray(h2.digest()[:2])

        signer = self.__key__.__privkey__().signer(*sigopts)
        signer.update(sigdata)
        sig._signature.signature.from_signer(signer.finalize())
        sig._signature.update_hlen()

        return sig

    @KeyAction(KeyFlags.Sign, is_unlocked=True, is_public=False)
    def sign(self, subject, **prefs):
        """
        Sign text, a message, or a timestamp using this key.

        :param subject: The text to be signed
        :type subject: ``str``, :py:obj:`~pgpy.PGPMessage`, ``None``
        :raises: :py:exc:`~pgpy.errors.PGPError` if the key is passphrase-protected and has not been unlocked
        :raises: :py:exc:`~pgpy.errors.PGPError` if the key is public
        :returns: :py:obj:`PGPSignature`

        The following optional keyword arguments can be used with :py:meth:`PGPKey.sign`, as well as
        :py:meth:`PGPKey.certify`,  :py:meth:`PGPKey.revoke`, and :py:meth:`PGPKey.bind`:

        :keyword expires: Set an expiration date for this signature
        :type expires: :py:obj:`~datetime.datetime`, :py:obj:`~datetime.timedelta`
        :keyword notation: Add arbitrary notation data to this signature.
        :type notation: ``dict``
        :keyword policy_uri: Add a URI to the signature that should describe the policy under which the signature
                             was issued.
        :type policy_uri: ``str``
        :keyword revocable: If ``False``, this signature will be marked non-revocable
        :type revocable: ``bool``
        :keyword user: Specify which User ID to use when creating this signature. Also adds a "Signer's User ID"
                       to the signature.
        :type user: ``str``
        """
        sig_type = SignatureType.BinaryDocument
        hash_algo = prefs.pop('hash', None)

        if subject is None:
            sig_type = SignatureType.Timestamp

        if isinstance(subject, PGPMessage):
            if subject.type == 'cleartext':
                sig_type = SignatureType.CanonicalDocument

            subject = subject.message

        sig = PGPSignature.new(sig_type, self.key_algorithm, hash_algo, self.fingerprint.keyid)

        return self._sign(subject, sig, **prefs)

    @KeyAction(KeyFlags.Certify, is_unlocked=True, is_public=False)
    def certify(self, subject, level=SignatureType.Generic_Cert, **prefs):
        """
        Sign a key or a user id within a key.

        :param subject: The user id or key to be certified.
        :type subject: :py:obj:`PGPKey`, :py:obj:`PGPUID`
        :param level: :py:obj:`~constants.SignatureType.Generic_Cert`, :py:obj:`~constants.SignatureType.Persona_Cert`,
                      :py:obj:`~constants.SignatureType.Casual_Cert`, or :py:obj:`~constants.SignatureType.Positive_Cert`.
                      Only used if subject is a :py:obj:`PGPUID`; otherwise, it is ignored.
        :raises: :py:exc:`~pgpy.errors.PGPError` if the key is passphrase-protected and has not been unlocked
        :raises: :py:exc:`~pgpy.errors.PGPError` if the key is public
        :returns: :py:obj:`PGPSignature`

        In addition to the optional keyword arguments accepted by :py:meth:`PGPKey.sign`, the following optional
        keyword arguments can be used with :py:meth:`PGPKey.certify`.

        These optional keywords only make sense, and thus only have an effect, when self-signing a key or User ID:

        :keyword ciphers: A list of preferred symmetric ciphers, as :py:obj:`~constants.SymmetricKeyAlgorithm`.
                          This keyword is ignored for non-self-certifications.
        :type ciphers: ``list``
        :keyword hashes: A list of preferred hash algorithms, as :py:obj:`~constants.HashAlgorithm`.
                         This keyword is ignored for non-self-certifications.
        :type hashes: ``list``
        :keyword compression: A list of preferred compression algorithms, as :py:obj:`~constants.CompressionAlgorithm`.
                              This keyword is ignored for non-self-certifications.
        :type compression: ``list``
        :keyword key_expires: Specify a key expiration date for when this key should expire, or a
                              :py:obj:`~datetime.timedelta` of how long after the key was created it should expire.
                              This keyword is ignored for non-self-certifications.
        :type key_expires: :py:obj:`datetime.datetime`, :py:obj:`datetime.timedelta`
        :keyword keyserver: Specify the URI of the preferred key server of the user.
                            This keyword is ignored for non-self-certifications.
        :type keyserver: ``str``, ``unicode``, ``bytes``
        :keyword primary: Whether or not to consider the certified User ID as the primary one.
                          This keyword is ignored for non-self-certifications, and any certifications directly on keys.
        :type primary: ``bool``

        These optional keywords only make sense, and thus only have an effect, when signing another key or User ID:

        :keyword trust: Specify the level and amount of trust to assert when certifying a public key. Should be a tuple
                        of two ``int`` s, specifying the trust level and trust amount. See
                        `RFC 4880 Section 5.2.3.13. Trust Signature <http://tools.ietf.org/html/rfc4880#section-5.2.3.13>`_
                        for more on what these values mean.
        :type trust: ``tuple`` of two ``int`` s
        :keyword regex: Specify a regular expression to constrain the specified trust signature in the resulting signature.
                        Symbolically signifies that the specified trust signature only applies to User IDs which match
                        this regular expression.
                        This is meaningless without also specifying trust level and amount.
        :type regex: ``str``
        """
        hash_algo = prefs.pop('hash', None)
        sig_type = level
        if isinstance(subject, PGPKey):
            sig_type = SignatureType.DirectlyOnKey

        sig = PGPSignature.new(sig_type, self.key_algorithm, hash_algo, self.fingerprint.keyid)

        # signature options that only make sense in certifications
        usage = prefs.pop('usage', None)
        exportable = prefs.pop('exportable', None)

        if usage is not None:
            sig._signature.subpackets.addnew('KeyFlags', hashed=True, flags=usage)

        if exportable is not None:
            sig._signature.subpackets.addnew('ExportableCertification', hashed=True, bflag=exportable)

        keyfp = self.fingerprint
        if isinstance(subject, PGPKey):
            keyfp = subject.fingerprint
        if isinstance(subject, PGPUID) and subject._parent is not None:
            keyfp = subject._parent.fingerprint

        if keyfp == self.fingerprint:
            # signature options that only make sense in self-certifications
            cipher_prefs = prefs.pop('ciphers', None)
            hash_prefs = prefs.pop('hashes', None)
            compression_prefs = prefs.pop('compression', None)
            key_expires = prefs.pop('key_expiration', None)
            keyserver_flags = prefs.pop('keyserver_flags', None)
            keyserver = prefs.pop('keyserver', None)
            primary_uid = prefs.pop('primary', None)

            if key_expires is not None:
                # key expires should be a timedelta, so if it's a datetime, turn it into a timedelta
                if isinstance(key_expires, datetime):
                    key_expires = key_expires - self.created

                sig._signature.subpackets.addnew('KeyExpirationTime', hashed=True, expires=key_expires)

            if cipher_prefs is not None:
                sig._signature.subpackets.addnew('PreferredSymmetricAlgorithms', hashed=True, flags=cipher_prefs)

            if hash_prefs is not None:
                sig._signature.subpackets.addnew('PreferredHashAlgorithms', hashed=True, flags=hash_prefs)

            if compression_prefs is not None:
                sig._signature.subpackets.addnew('PreferredCompressionAlgorithms', hashed=True, flags=compression_prefs)

            if keyserver_flags is not None:
                sig._signature.subpackets.addnew('KeyServerPreferences', hashed=True, flags=keyserver_flags)

            if keyserver is not None:
                sig._signature.subpackets.addnew('PreferredKeyServer', hashed=True, uri=keyserver)

            if primary_uid is not None:
                sig._signature.subpackets.addnew('PrimaryUserID', hashed=True, primary=primary_uid)

            # Features is always set on self-signatures
            sig._signature.subpackets.addnew('Features', hashed=True, flags=Features.pgpy_features)

        else:
            # signature options that only make sense in non-self-certifications
            trust = prefs.pop('trust', None)
            regex = prefs.pop('regex', None)

            if trust is not None:
                sig._signature.subpackets.addnew('TrustSignature', hashed=True, level=trust[0], amount=trust[1])

                if regex is not None:
                    sig._signature.subpackets.addnew('RegularExpression', hashed=True, regex=regex)

        return self._sign(subject, sig, **prefs)

    @KeyAction(KeyFlags.Certify, is_unlocked=True, is_public=False)
    def revoke(self, target, **prefs):
        """
        Revoke a key, a subkey, or all current certification signatures of a User ID that were generated by this key so far.

        :param target: The key to revoke
        :type target: :py:obj:`PGPKey`, :py:obj:`PGPUID`
        :raises: :py:exc:`~pgpy.errors.PGPError` if the key is passphrase-protected and has not been unlocked
        :raises: :py:exc:`~pgpy.errors.PGPError` if the key is public
        :returns: :py:obj:`PGPSignature`

        In addition to the optional keyword arguments accepted by :py:meth:`PGPKey.sign`, the following optional
        keyword arguments can be used with :py:meth:`PGPKey.revoke`.

        :keyword reason: Defaults to :py:obj:`constants.RevocationReason.NotSpecified`
        :type reason: One of :py:obj:`constants.RevocationReason`.
        :keyword comment: Defaults to an empty string.
        :type comment: ``str``
        """
        hash_algo = prefs.pop('hash', None)
        if isinstance(target, PGPUID):
            sig_type = SignatureType.CertRevocation

        elif isinstance(target, PGPKey):
            ##TODO: check to make sure that the key that is being revoked:
            #        - is this key
            #        - is one of this key's subkeys
            #        - specifies this key as its revocation key
            if target.is_primary:
                sig_type = SignatureType.KeyRevocation

            else:
                sig_type = SignatureType.SubkeyRevocation

        else:  # pragma: no cover
            raise TypeError

        sig = PGPSignature.new(sig_type, self.key_algorithm, hash_algo, self.fingerprint.keyid)

        # signature options that only make sense when revoking
        reason = prefs.pop('reason', RevocationReason.NotSpecified)
        comment = prefs.pop('comment', "")
        sig._signature.subpackets.addnew('ReasonForRevocation', hashed=True, code=reason, string=comment)

        return self._sign(target, sig, **prefs)

    @KeyAction(is_unlocked=True, is_public=False)
    def revoker(self, revoker, **prefs):
        """
        Generate a signature that specifies another key as being valid for revoking this key.

        :param revoker: The :py:obj:`PGPKey` to specify as a valid revocation key.
        :type revoker: :py:obj:`PGPKey`
        :raises: :py:exc:`~pgpy.errors.PGPError` if the key is passphrase-protected and has not been unlocked
        :raises: :py:exc:`~pgpy.errors.PGPError` if the key is public
        :returns: :py:obj:`PGPSignature`

        In addition to the optional keyword arguments accepted by :py:meth:`PGPKey.sign`, the following optional
        keyword arguments can be used with :py:meth:`PGPKey.revoker`.

        :keyword sensitive: If ``True``, this sets the sensitive flag on the RevocationKey subpacket. Currently,
                            this has no other effect.
        :type sensitive: ``bool``
        """
        hash_algo = prefs.pop('hash', None)

        sig = PGPSignature.new(SignatureType.DirectlyOnKey, self.key_algorithm, hash_algo, self.fingerprint.keyid)

        # signature options that only make sense when adding a revocation key
        sensitive = prefs.pop('sensitive', False)
        keyclass = RevocationKeyClass.Normal | (RevocationKeyClass.Sensitive if sensitive else 0x00)

        sig._signature.subpackets.addnew('RevocationKey',
                                         hashed=True,
                                         algorithm=revoker.key_algorithm,
                                         fingerprint=revoker.fingerprint,
                                         keyclass=keyclass)

        # revocation keys should really not be revocable themselves
        prefs['revocable'] = False
        return self._sign(self, sig, **prefs)

    @KeyAction(is_unlocked=True, is_public=False)
    def bind(self, key, **prefs):
        """
        Bind a subkey to this key.

        Valid optional keyword arguments are identical to those of self-signatures for :py:meth:`PGPkey.certify`
        """
        hash_algo = prefs.pop('hash', None)

        if self.is_primary and not key.is_primary:
            sig_type = SignatureType.Subkey_Binding

        elif key.is_primary and not self.is_primary:
            sig_type = SignatureType.PrimaryKey_Binding

        else:  # pragma: no cover
            raise PGPError

        sig = PGPSignature.new(sig_type, self.key_algorithm, hash_algo, self.fingerprint.keyid)

        if sig_type == SignatureType.Subkey_Binding:
            # signature options that only make sense in subkey binding signatures
            usage = prefs.pop('usage', None)

            if usage is not None:
                sig._signature.subpackets.addnew('KeyFlags', hashed=True, flags=usage)

            # if possible, have the subkey create a primary key binding signature
            if key.key_algorithm.can_sign:
                subkeyid = key.fingerprint.keyid
                esig = None

                if not key.is_public:  # pragma: no cover
                    esig = key.bind(self)

                elif subkeyid in self.subkeys:
                    esig = self.subkeys[subkeyid].bind(self)

                if esig is not None:
                    sig._signature.subpackets.addnew('EmbeddedSignature', hashed=False, _sig=esig._signature)

        return self._sign(key, sig, **prefs)

    def verify(self, subject, signature=None):
        """
        Verify a subject with a signature using this key.

        :param subject: The subject to verify
        :type subject: ``str``, ``unicode``, ``None``, :py:obj:`PGPMessage`, :py:obj:`PGPKey`, :py:obj:`PGPUID`
        :param signature: If the signature is detached, it should be specified here.
        :type signature: :py:obj:`PGPSignature`
        :returns: :py:obj:`~pgpy.types.SignatureVerification`
        """
        sspairs = []

        # some type checking
        if not isinstance(subject, (type(None), PGPMessage, PGPKey, PGPUID, PGPSignature, six.string_types, bytes, bytearray)):
            raise TypeError("Unexpected subject value: {:s}".format(str(type(subject))))
        if not isinstance(signature, (type(None), PGPSignature)):
            raise TypeError("Unexpected signature value: {:s}".format(str(type(signature))))

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
            # subkey binding signatures
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
                              padding.PKCS1v15(), getattr(hashes, sig.hash_algorithm.name)(),)

                elif sig.key_algorithm == PubKeyAlgorithm.DSA:
                    vargs = (sig.__sig__, getattr(hashes, sig.hash_algorithm.name)(),)

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
                    sigv.add_sigsubj(sig, self.fingerprint.keyid, subj, verified)
                    del sigdata, verifier, verified

        return sigv

    @KeyAction(KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage, is_public=True)
    def encrypt(self, message, sessionkey=None, **prefs):
        """
        Encrypt a PGPMessage using this key.

        :param message: The message to encrypt.
        :type message: :py:obj:`PGPMessage`
        :optional param sessionkey: Provide a session key to use when encrypting something. Default is ``None``.
                                    If ``None``, a session key of the appropriate length will be generated randomly.

                                    .. warning::

                                        Care should be taken when making use of this option! Session keys *absolutely need*
                                        to be unpredictable! Use the ``gen_key()`` method on the desired
                                        :py:obj:`~constants.SymmetricKeyAlgorithm` to generate the session key!
        :type sessionkey: ``bytes``, ``str``

        :raises: :py:exc:`~errors.PGPEncryptionError` if encryption failed for any reason.
        :returns: A new :py:obj:`PGPMessage` with the encrypted contents of ``message``

        The following optional keyword arguments can be used with :py:meth:`PGPKey.encrypt`:

        :keyword cipher: Specifies the symmetric block cipher to use when encrypting the message.
        :type cipher: :py:obj:`~constants.SymmetricKeyAlgorithm`
        :keyword user: Specifies the User ID to use as the recipient for this encryption operation, for the purposes of
                       preference defaults and selection validation.
        :type user: ``str``, ``unicode``
        """
        user = prefs.pop('user', None)
        uid = None
        if user is not None:
            uid = self.get_uid(user)
        else:
            uid = next(iter(self.userids), None)
            if uid is None and self.parent is not None:
                uid = next(iter(self.parent.userids), None)
        cipher_algo = prefs.pop('cipher', uid.selfsig.cipherprefs[0])

        if cipher_algo not in uid.selfsig.cipherprefs:
            warnings.warn("Selected symmetric algorithm not in key preferences", stacklevel=3)

        if message.is_compressed and message._compression not in uid.selfsig.compprefs:
            warnings.warn("Selected compression algorithm not in key preferences", stacklevel=3)

        if sessionkey is None:
            sessionkey = cipher_algo.gen_key()

        # set up a new PKESessionKeyV3
        pkesk = PKESessionKeyV3()
        pkesk.encrypter = bytearray(binascii.unhexlify(self.fingerprint.keyid.encode('latin-1')))
        pkesk.pkalg = self.key_algorithm
        pkesk.encrypt_sk(self.__key__.__pubkey__(), cipher_algo, sessionkey)

        if message.is_encrypted:  # pragma: no cover
            _m = message

        else:
            _m = PGPMessage()
            skedata = IntegrityProtectedSKEDataV1()
            skedata.encrypt(sessionkey, cipher_algo, message.__bytes__())
            _m |= skedata

        _m |= pkesk

        return _m

    def decrypt(self, message):
        """
        Decrypt a PGPMessage using this key.

        :param message: An encrypted :py:obj:`PGPMessage`
        :returns: A new :py:obj:`PGPMessage` with the decrypted contents of ``message``
        """
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
        orphaned = []
        # last holds the last non-signature thing processed

        getpkt = lambda d: Packet(d) if len(d) > 0 else None
        getpkt = iter(functools.partial(getpkt, data), None)

        def pktgrouper():
            class PktGrouper(object):
                def __init__(self):
                    self.last = None

                def __call__(self, pkt):
                    if pkt.header.tag != PacketTag.Signature:
                        self.last = '{:02X}_{:s}'.format(id(pkt), pkt.__class__.__name__)
                    return self.last
            return PktGrouper()

        while True:
            for group in iter(group for _, group in itertools.groupby(getpkt, key=pktgrouper()) if not _.endswith('Opaque')):
                pkt = next(group)

                # deal with pkt first
                if isinstance(pkt, Key):
                    pgpobj = (self if self._key is None else PGPKey()) | pkt

                elif isinstance(pkt, (UserID, UserAttribute)):
                    pgpobj = PGPUID() | pkt

                else:  # pragma: no cover
                    break

                # add signatures to whatever we got
                [ operator.ior(pgpobj, PGPSignature() | sig) for sig in group if not isinstance(sig, Opaque) ]

                # and file away pgpobj
                if isinstance(pgpobj, PGPKey):
                    if pgpobj.is_primary:
                        keys[(pgpobj.fingerprint.keyid, pgpobj.is_public)] = pgpobj

                    else:
                        keys[next(reversed(keys))] |= pgpobj

                elif isinstance(pgpobj, PGPUID):
                    # parent is likely the most recently parsed primary key
                    keys[next(reversed(keys))] |= pgpobj

                else:  # pragma: no cover
                    break
            else:
                # finished normally
                break

            # this will only be reached called if the inner loop hit a break
            warnings.warn("Warning: Orphaned packet detected! {:s}".format(repr(pkt)), stacklevel=2)  # pragma: no cover
            orphaned.append(pkt)  # pragma: no cover
            for pkt in group:  # pragma: no cover
                orphaned.append(pkt)

        # remove the reference to self from keys
        [ keys.pop((getattr(self, 'fingerprint.keyid', '~'), None), t) for t in (True, False) ]
        # return {'keys': keys, 'orphaned': orphaned}
        return keys


class PGPKeyring(collections.Container, collections.Iterable, collections.Sized):
    def __init__(self, *args):
        """
        PGPKeyring objects represent in-memory keyrings that can contain any combination of supported private and public
        keys. It can not currently be conveniently exported to a format that can be understood by GnuPG.
        """
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

    def __iter__(self):  # pragma: no cover
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
        while {} in self._aliases:  # pragma: no cover
            self._aliases.remove({})

    def _add_alias(self, alias, pkid):
        # brand new alias never seen before!
        if alias not in self:
            self._aliases[-1][alias] = pkid

        # this is a duplicate alias->key link; ignore it
        elif alias in self and pkid in set(m[alias] for m in self._aliases if alias in m):
            pass  # pragma: no cover

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
        """
        Load all keys provided into this keyring object.

        :param \*args: Each arg in ``args`` can be any of the formats supported by :py:meth:`PGPKey.from_path` and
                      :py:meth:`PGPKey.from_blob`, or a ``list`` or ``tuple`` of these.
        :type \*args: ``list``, ``tuple``, ``str``, ``unicode``, ``bytes``, ``bytearray``
        :returns: a ``set`` containing the unique fingerprints of all of the keys that were loaded during this operation.
        """
        def _preiter(first, iterable):
            yield first
            for item in iterable:
                yield item

        loaded = set()
        for key in iter(item for ilist in iter(ilist if isinstance(ilist, (tuple, list)) else [ilist] for ilist in args)
                        for item in ilist):
            if os.path.isfile(key):
                _key, keys = PGPKey.from_file(key)

            else:
                _key, keys = PGPKey.from_blob(key)

            for ik in _preiter(_key, keys.values()):
                self._add_key(ik)
                loaded |= {ik.fingerprint} | {isk.fingerprint for isk in ik.subkeys.values()}

        return list(loaded)

    @contextlib.contextmanager
    def key(self, identifier):
        """
        A context-manager method. Yields the first :py:obj:`PGPKey` object that matches the provided identifier.

        :param identifier: The identifier to use to select a loaded key.
        :type identifier: :py:exc:`PGPMessage`, :py:exc:`PGPSignature`, ``str``
        :raises: :py:exc:`KeyError` if there is no loaded key that satisfies the identifier.
        """
        if isinstance(identifier, PGPMessage):
            for issuer in identifier.issuers:
                if issuer in self:
                    identifier = issuer
                    break

        if isinstance(identifier, PGPSignature):
            identifier = identifier.signer

        yield self._get_key(identifier)

    def fingerprints(self, keyhalf='any', keytype='any'):
        """
        List loaded fingerprints with some optional filtering.

        :param str keyhalf: Can be 'any', 'public', or 'private'. If 'public', or 'private', the fingerprints of keys of the
                            the other type will not be included in the results.
        :param str keytype: Can be 'any', 'primary', or 'sub'. If 'primary' or 'sub', the fingerprints of keys of the
                            the other type will not be included in the results.
        :returns: a ``set`` of fingerprints of keys matching the filters specified.
        """
        return {pk.fingerprint for pk in self._keys.values()
                if pk.is_primary in [True if keytype in ['primary', 'any'] else None,
                                     False if keytype in ['sub', 'any'] else None]
                if pk.is_public in [True if keyhalf in ['public', 'any'] else None,
                                    False if keyhalf in ['private', 'any'] else None]}

    def unload(self, key):
        """
        Unload a loaded key and its subkeys.

        The easiest way to do this is to select a key using :py:meth:`PGPKeyring.key` first::

            with keyring.key("DSA von TestKey") as key:
                keyring.unload(key)

        :param key: The key to unload.
        :type key: :py:obj:`PGPKey`
        """
        assert isinstance(key, PGPKey)
        pkid = id(key)
        if pkid in self._keys:
            # remove references
            [ kd.remove(pkid) for kd in [self._pubkeys, self._privkeys] if pkid in kd ]
            # remove the key
            self._keys.pop(pkid)

            # remove aliases
            for m, a in [ (m, a) for m in self._aliases for a, p in m.items() if p == pkid ]:
                m.pop(a)
                # do a re-sort of this alias if it was not unique
                if a in self:
                    self._sort_alias(a)

            # if key is a primary key, unload its subkeys as well
            if key.is_primary:
                [ self.unload(sk) for sk in key.subkeys.values() ]
