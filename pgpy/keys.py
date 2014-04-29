""" key.py

"""
import collections
import contextlib

from .pgp import PGPLoad
from .errors import PGPError


def managed(func):
    def inner(self, *args, **kwargs):
        if not self.ctx:
            raise PGPError("Invalid usage - this method must be invoked from a context managed state!")

        return func(self, *args, **kwargs)
    return inner


class PGPKeyring(object):
    def __init__(self, keys=None):
        self.pubkeys = collections.OrderedDict()
        self.seckeys = collections.OrderedDict()

        self.using = None
        self.ctx = False

        if keys is not None:
            self.load(keys)

    def __getattr__(self, item):
        if item == "packets" and self.using is None:
            return [ pkt for keys in list(self.pubkeys.values()) + list(self.seckeys.values()) for pkt in keys.packets ]

        if item == "keys" and self.using is None:
            return list(self.pubkeys.values()) + list(self.seckeys.values())

        raise AttributeError(item)

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
        # from the Computing Signatures section of RFC 4880 (http://tools.ietf.org/html/rfc4880#section-5.2.4)
        #
        # All signatures are formed by producing a hash over the signature
        # data, and then using the resulting hash in the signature algorithm.
        #
        # For binary document signatures (type 0x00), the document data is
        # hashed directly.  For text document signatures (type 0x01), the
        # document is canonicalized by converting line endings to <CR><LF>,
        # and the resulting data is hashed.
        #
        # ...
        #
        # ...
        #
        # ...
        #
        # Once the data body is hashed, then a trailer is hashed.
        # (...) A V4 signature hashes the packet body
        # starting from its first field, the version number, through the end
        # of the hashed subpacket data.  Thus, the fields hashed are the
        # signature version, the signature type, the public-key algorithm, the
        # hash algorithm, the hashed subpacket length, and the hashed
        # subpacket body.
        #
        # V4 signatures also hash in a final trailer of six octets: the
        # version of the Signature packet, i.e., 0x04; 0xFF; and a four-octet,
        # big-endian number that is the length of the hashed data from the
        # Signature packet (note that this number does not include these final
        # six octets).
        #
        # After all this has been hashed in a single hash context, the
        # resulting hash field is used in the signature algorithm and placed
        # at the end of the Signature packet.

        ##TODO: create PGPSignature object
        pass

    @managed
    def verify(self, subject):
        ##TODO: verify existing PGPSignature object
        pass