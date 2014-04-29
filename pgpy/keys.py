""" key.py

"""
import collections

from .pgp import PGPLoad


class PGPKeyring(object):
    def __init__(self, keys=None):
        self.pubkeys = collections.OrderedDict()
        self.seckeys = collections.OrderedDict()

        if keys is not None:
            self.load(keys)

    ##TODO: context management magic
    def __enter__(self):
        return self

    def __exit__(self, type, value, tb):
        pass

    def __getattr__(self, item):
        if item == "packets":
            return [ pkt for keys in list(self.pubkeys.values()) + list(self.seckeys.values()) for pkt in keys.packets]

        if item == "keys":
            return list(self.pubkeys.values()) + list(self.seckeys.values())

    def __bytes__(self):
        return b''.join(k.__bytes__() for k in list(self.pubkeys.values()) + list(self.seckeys.values()))

    def load(self, keys):
        ##TODO: type-check keys
        # create one or more PGPKey objects in self.keys
        if type(keys) is not list:
            keys = [keys]

        ##TODO: load ASCII armored keys
        ##TODO: load binary keys
        ##TODO: load GPG keyrings
        ##TODO: load from GPG agent
        for key in keys:
            # load the key into a PGPBlock object first
            kb = PGPLoad(key)

            for k in kb:
                if k.secret:
                    self.seckeys[k.keyid] = k

                else:
                    self.pubkeys[k.keyid] = k

    def sign(self, subject, keyid, inline=False):
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

    def verify(self, signature, subject):
        ##TODO: verify existing PGPSignature object
        pass

    def list_pubkeys(self):
        ##TODO: list loaded public key ids
        pass

    def list_privkeys(self):
        ##TODO: list loaded private key ids
        pass