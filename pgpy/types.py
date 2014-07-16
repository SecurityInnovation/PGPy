""" types.py
"""
import collections
import re

from .packet.packets import PrivKey
from .packet.packets import PubKey
from .packet.packets import UserID
from .pgp import PGPKey


class SignatureVerification(object):
    """
    Returned by :py:meth:`pgpy.PGPKeyring.verify`

    Can be compared directly as a boolean to determine whether or not the specified signature verified.
    """
    def __init__(self):
        self._verified = False

        self.signature = None
        """
        The :py:class:`~pgpy.pgp.PGPSignature` that was used in the verification that returned this
        """
        self.key = None
        """
        The :py:class:`~pgpy.pgp.PGPKey` (if available) that was used to verify the signature
        """
        self.subject = None
        """
        The subject of the verification
        """

    # Python 2
    def __nonzero__(self):
        return self._verified

    # Python 3
    def __bool__(self):
        return self._verified

    def __repr__(self):  # pragma: no cover
        return "SignatureVerification({key}, {verified})".format(verified=str(bool(self)), key=self.key.keyid)


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
                raise ValueError("Expected: String of 40 hex digits")

            # store in the format: "AAAA BBBB CCCC DDDD EEEE  FFFF 0000 1111 2222 3333"
            content = ''.join([ j for i in zip([ content[x:(x + 4)] for x in range(0, 40, 4) ],
                                               [' '] * 4 + ['  '] + [' '] * 5) for j in i ][:-1])
            return str.__new__(cls, content)

        def __eq__(self, other):
            other = str(other).replace(' ', '')

            if self.replace(' ', '') == other:
                return True

            if self.keyid == other:
                return True

            if self.shortid == other:
                return True

            return False

        def __hash__(self):
            return hash(str(self))

    class _KeyID(str):
        def __new__(cls, content):
            # validate input before continuing: this should be a string of 16 hex digits
            content = content.upper().replace(' ', '')
            if len(content) != 16 or (not bool(re.match(r'^[A-Z0-9]+$', content))):
                raise ValueError("Expected: String of 16 hex digits")

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
                raise ValueError("Expected: String of 8 hex digits")

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
        # return collections.ValuesView({ k: self._keys[k].pubkey for k in self if self._keys[k].pubkey is not None })
        return collections.ValuesView(self._pubkeys)

    @property
    def __privkeys__(self):
        """
        :return: a ValuesView of private keys
        """
        # return collections.ValuesView({ k: self._keys[k].privkey for k in self if self._keys[k].privkey is not None })
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
                uidm = re.match(r'^(?P<name>[^\(<]*)(?: \((?P<comment>.*)\))?(?: <(?P<email>.*)>)$', uid.data.decode()).groupdict()

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
        pass

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
