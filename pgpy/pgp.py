""" pgp.py

this is where the armorable PGP block objects live
"""

from collections import OrderedDict
from datetime import datetime

from .constants import PacketTag
from .constants import SignatureType

from .packet import Key
from .packet import Packet
from .packet import Primary
from .packet import Private
from .packet import Public
from .packet import Sub
from .packet import UserID
from .packet import UserAttribute
from .packet.packets import Signature
from .packet.types import Opaque

from .types import Exportable
from .types import PGPObject


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
    def cipherprefs(self):
        return self._uids[0]._sigs[(self.fingerprint.keyid, 0)].cipherprefs

    @property
    def compprefs(self):
        return self._uids[0]._sigs[(self.fingerprint.keyid, 0)].compprefs

    @property
    def fingerprint(self):
        return self._key.fingerprint

    @property
    def hashprefs(self):
        return self._uids[0]._sigs[(self.fingerprint.keyid, 0)].hashprefs

    @property
    def is_primary(self):
        return isinstance(self._key, Primary) and not isinstance(self._key, Sub)

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
            return self._uids[0]._sigs[(self.fingerprint.keyid, 0)].key_flags

        else:
            return self._signatures[list(self._signatures.keys())[0]].key_flags

    @property
    def userids(self):
        return [u for u in self._uids if isinstance(u._uid, UserID)]

    @property
    def userattributes(self):
        return [u for u in self._uids if isinstance(u._uid, UserAttribute)]

    def __init__(self):
        super(PGPKey, self).__init__()
        self._key = None                # :type: PubKeyV4 | PrivKeyV4 | PubSubKeyV4 | PrivSubKeyV4
        self._children = OrderedDict()  # :type: dict of PGPKey
        self._parent = None             # :type: PGPKey
        self._signatures = {}           # :type: dict of PGPSignature
        self._uids = []                 # :type: list of PGPUID

    def __bytes__(self):
        _bytes = bytearray()
        # us
        _bytes += self._key.__bytes__()
        # our signatures
        for sig in self.signatures.values():
            _bytes += sig.__bytes__()
        # one or more User IDs, followed by their signatures
        for uid in self._uids:
            _bytes += uid._uid.__bytes__()
            _bytes += b''.join([s.__bytes__() for s in uid._sigs.values()])
        # subkeys
        for sk in self._children.values():
            _bytes += sk.__bytes__()

        return bytes(_bytes)

    @classmethod
    def generate(cls):
        raise NotImplementedError()

    def protect(self):
        raise NotImplementedError()

    def unprotect(self):
        raise NotImplementedError()

    def sign(self, subject, **kwargs):
        # prefs = {'inline': False}
        raise NotImplementedError()

    def verify(self, subject, signature=None, **kwargs):
        raise NotImplementedError()

    def encrypt(self):
        raise NotImplementedError()

    def decrypt(self):
        raise NotImplementedError()

    def parse(self, packet):
        data = bytearray()
        unarmored = None

        try:
            unarmored = self.ascii_unarmor(packet)

        except ValueError:
            data = packet

        finally:
            if unarmored is not None:
                if 'KEY' not in unarmored['magic']:
                    raise ValueError('Expected: Signature. Got: {}'.format(str(unarmored['magic'])))

                data = unarmored['body']
                self.ascii_headers = unarmored['headers']

        if not isinstance(data, bytearray):
            data = bytearray(data)

        # parse packets
        # keys will hold other keys parsed here
        keys = OrderedDict()
        # uids will hold user ids and user attributes parsed here
        uids = OrderedDict()
        # orphaned will hold all non-opaque orphaned packets
        orphaned = OrderedDict()

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
                ##TODO: warn if Opaque
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
                    lk.signatures[sig.type] = sig
                    last = sig
                    continue

                # A SubkeyRevocation signature *must immediately* follow the Subkey Binding Signature that
                # immediately follows a Subkey
                if sig.type == SignatureType.SubkeyRevocation and isinstance(last, PGPSignature) and isinstance(lk, PGPKey) and not lk.is_primary:
                    lk.signatures[sig.type] = sig
                    last = sig
                    continue

                # Certification signatures *must* follow either a User ID or User Attribute packet,
                # or another Certification signature.
                if isinstance(lns, (PGPUID)):
                    scount = len([k for k in lns._sigs.keys() if k[0] == sig.signer])
                    lns._sigs[(sig.signer, scount)] = sig
                    last = sig
                    continue

                # Subkey Binding signatures *must immediately* follow a Subkey
                if isinstance(last, PGPKey) and not last.is_primary:
                    last._signatures[(sig.signer, 0)] = sig
                    last = sig
                    continue

                ##TODO: where do direct-key signatures go?


            # if we get this far, the packet was orphaned! Add it to orphaned.
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
        if not 'SignatureExpirationTime' in self._signature.subpackets:
            return False

        expd = self._signature.subpackets['SignatureExpirationTime'].expires
        if expd.total_seconds() == 0:
            return False

        exp = self.created + expd
        return exp > datetime.utcnow()

    @property
    def exportable(self):
        if not 'ExportableCertification' in self._signature.subpackets:
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
        if not 'Revocable' in self._signature.subpackets:
            return True
        return bool(self._signature.subpackets['Revocable'])

    @property
    def revocation_key(self):
        if not 'RevocationKey' in self._signature.subpackets:
            return None
        raise NotImplementedError()

    @property
    def signer(self):
        return self._signature.subpackets['Issuer'][-1].issuer

    @property
    def target_signature(self):
        raise NotImplementedError()

    @property
    def type(self):
        return self._signature.sigtype

    def __init__(self):
        super(PGPSignature, self).__init__()
        self._signature = None

    def __bytes__(self):
        if self._signature is None:
            return b''
        return self._signature.__bytes__()

    def parse(self, packet):
        data = bytearray()
        unarmored = None

        try:
            unarmored = self.ascii_unarmor(packet)

        except ValueError:
            data = packet

        finally:
            if unarmored is not None:
                if unarmored['magic'] != 'SIGNATURE':
                    raise ValueError('Expected: Signature. Got: {}'.format(str(unarmored['magic'])))

                data = unarmored['body']
                self.ascii_headers = unarmored['headers']

        if not isinstance(data, bytearray):
            data = bytearray(data)

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

    def __init__(self):
        self._uid = None
        self._sigs = OrderedDict()
        self._parent = None


# class PGPKey(PGPObject):
#     # @property
#     # def keypkts(self):
#     #     return [ packet for packet in self.packets if isinstance(packet, KeyPacket) ]
#
#     # @property
#     # def primarykey(self):
#     #     """
#     #     Reference to the primary key if this is a subkey
#     #     ?? if this is already a primary key
#     #     """
#     #     # return [ packet for packet in self.packets if type(packet) in [PubKey, PrivKey] ][0]
#     #     raise NotImplementedError()
#
#     @property
#     def primary(self):
#         """
#         True if this is a primary key
#         False if this is a subkey
#         """
#         return isinstance(self._keypkt, Primary)
#
#     @property
#     def sub(self):
#         """
#         True if this is a subkey
#         False if this is a primary key
#         """
#         return isinstance(self._keypkt, Sub)
#
#     @property
#     def public(self):
#         """
#         True if this is a public key
#         False if this is a private key
#         """
#         return isinstance(self._keypkt, Public)
#
#     @property
#     def private(self):
#         """
#         True if this is a private key
#         False if this is a public key
#         """
#         return isinstance(self._keypkt, Private)
#
#     @property
#     def magic(self):
#         return "{} KEY BLOCK".format("PRIVATE" if self.private else \
#                                      "PUBLIC" if self.public else "?")
#
#     @classmethod
#     def new(cls):
#         ##TODO: generate a new key
#         raise NotImplementedError()
#
#     def __init__(self):
#         super(PGPKey, self).__init__()
#
#         self._keypkt = None
#         self._userids = []
#         self._attrs = []
#         self._keysigs = []
#
#     def parse(self, data):
#         ##TODO: load the next key in data and return the leftovers
#         raise NotImplementedError()
#
#     def __bytes__(self):
#         raise NotImplementedError()
#
#     def __pgpdump__(self):
#         raise NotImplementedError()
#
#     def lock(self, passphrase, s2k=None):
#         """
#         Encrypt the secret key material if it is not already encrypted.
#         """
#         ##TODO: this should fail if this PGPKey is not a private key
#         ##TODO: this should fail if the secret key material is already encrypted
#         ##TODO: s2k should default to the strongest method available (which is currently Iterated)
#         raise NotImplementedError()
#
#     def unlock(self, passphrase):
#         """
#         Decrypt the secret key material if it is encrypted
#         """
#         raise NotImplementedError()
#
#     def sign(self, subject, hash=None, inline=False, sigtype=None):
#         """
#         Sign a subject with this key.
#         """
#         ##TODO: if hash is None, default to using the strongest hash in this key's preference flags
#         ##TODO: implement inline signing
#         ##TODO: implement signing things other than binary documents
#         ##TODO: sigtype should default to the binary signature type specifier rather than None
#         raise NotImplementedError()
#
#     def verify(self, subject, signature):
#         """
#         Verify a subject using this key.
#         """
#         if not isinstance(signature, PGPSignature):
#             signature = pgpload(signature)[0]
#
#         if not isinstance(signature, PGPSignature):
#             raise ValueError("signature must be a signature!")
#
#     def encrypt(self):
#         """
#         Encrypt something
#         """
#         raise NotImplementedError()
#
#     def decrypt(self):
#         """
#         Decrypt something
#         """
#         raise NotImplementedError()
