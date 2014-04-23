""" key.py

"""
import collections

from .fileloader import FileLoader

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


class PGPKey(object):
    pass


class PGPKeyLoader(FileLoader):
    pubkey_magic = "PUBLIC KEY BLOCK"
    privkey_magic = "PRIVATE KEY BLOCK"

    def __init__(self, key):
        self.keys = collections.OrderedDict()

        super(PGPKeyLoader, self).__init__(key)

    def parse(self):
        ##TODO: load/parse PGP key(s) from ASCII armored files
        ##TODO: load/parse PGP key(s) from binary files
        ##TODO: load/parse PGP key(s) from GPG keyrings
        ##TODO: load/parse PGP key(s) from GPG agent
        pass


class PGPKeyCollection(object):
    def __init__(self):
        ##TODO: create one or more PGPKey objects
        pass

    ##TODO: context management magic
    def __enter__(self):
        pass

    def __exit__(self):
        pass

    def sign(self, subject, keyid):
        ##TODO: create PGPSignature object
        pass

    def verify(self, signature, subject):
        ##TODO: verify existing PGPSignature object
        pass

    def list_pubkeys(self):
        ##TODO: list loaded public keys
        pass

    def list_privkeys(self):
        ##TODO: list loaded private keys
        pass