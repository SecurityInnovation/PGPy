""" pgp.py

"""
import re
import collections
import base64
import hashlib
import calendar

from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from .fileloader import FileLoader
from .reg import *
from .util import bytes_to_int, int_to_bytes
from .packet import PGPPacket, SymmetricKeyAlgo, PubKeyAlgo, HashAlgo
from .packet.packets import Signature
from .packet.fields import Header
from .errors import PGPError, PGPKeyDecryptionError
from ._author import __version__


def PGPLoad(pgpbytes):
    # load pgpbytes regardless of type, first
    f = FileLoader(pgpbytes)

    b = []

    # now, are there any ASCII PGP blocks at all?
    if f.is_ascii:
        # decode/parse ASCII PGP blocks
        nascii = list(re.finditer(ASCII_BLOCK, f.bytes.decode(), flags=re.MULTILINE | re.DOTALL))

        if len(nascii) == 0:
            raise PGPError("No PGP blocks to read!")  # pragma: no cover

        for block in nascii:
            if block.group(1)[-9:] == "KEY BLOCK":
                c = PGPKey

            if block.group(1) == "SIGNATURE":
                c = PGPSignature

            p = c(block.group(0).encode())
            b.append(p)

    # try to load binary instead
    else:
        block = PGPBlock(pgpbytes)

        # is this a signature?
        if block.packets[0].header.tag == Header.Tag.Signature:
            b.append(PGPSignature(pgpbytes))
            block.packets = []

        # now go through block and split out any keys, if possible
        bpos = 0
        for i, pkt in enumerate(block.packets):
            # if this is the last packet, we need to instantiate whatever type is at block.packets[bpos]
            if i == len(block.packets) - 1:
                pktblock = block.packets[bpos:]

                if pktblock[0].header.tag in [Header.Tag.PubKey, Header.Tag.PrivKey]:
                    bl = PGPKey(None)

                bl.packets = pktblock
                b.append(bl)
                bpos = i
                continue

            # a public or private key (not subkey) indicates the start of a new block,
            # so load the previous block into a new object
            if i != bpos and pkt.header.tag in [Header.Tag.PubKey, Header.Tag.PrivKey]:
                pktblock = block.packets[bpos:i]
                bl = PGPKey(None)
                bl.packets = pktblock
                b.append(bl)
                bpos = i
                continue

    ##TODO: load from a GPG agent

    # return loaded blocks
    return b


class PGPBlock(FileLoader):
    crc24_init = 0xB704CE
    crc24_poly = 0x1864CFB

    ASCII_FORMAT = \
        "-----BEGIN PGP {block_type}-----\n"\
        "{headers}\n"\
        "{packet}\n"\
        "={crc}\n"\
        "-----END PGP {block_type}-----\n"

    def __init__(self, data, btype=None, all=False):
        # options
        self.type = btype
        self.all = all

        # data fields
        self.ascii_headers = collections.OrderedDict()
        self.data = b''
        self.crc = 0
        self.packets = []

        super(PGPBlock, self).__init__(data)

    def __str__(self):
        headers = ""
        for key, val in self.ascii_headers.items():
            headers += "{key}: {val}\n".format(key=key, val=val)

        # base64-encode our bytes, then insert a newline every 64th character
        payload = b''
        for pkt in self.packets:
            payload += pkt.__bytes__()
        payload = base64.b64encode(payload).decode()
        payload = '\n'.join(payload[i:i + 64] for i in range(0, len(payload), 64))

        # figure out block type magic
        t = ""
        if self.type is not None:
            t = str(self.type)

        return self.ASCII_FORMAT.format(
            block_type=t,
            headers=headers,
            packet=payload,
            crc=base64.b64encode(int_to_bytes(self.crc24(), 3)).decode(),
        )

    def __bytes__(self):
        _bytes = b''
        for pkt in self.packets:
            _bytes += pkt.__bytes__()

        return _bytes

    def parse(self):
        ##TODO: load multiple keys from a single block

        # try to extract the PGP block(s)
        self.extract_pgp_ascii_block()

        if self.bytes != b'':
            # parsing/decoding using the RFC 4880 section on "Forming ASCII Armor"
            # https://tools.ietf.org/html/rfc4880#section-6.2
            k = re.split(ASCII_BLOCK, self.bytes.decode(), flags=re.MULTILINE | re.DOTALL)[1:-1]

            # parse header field(s)
            h = [ h for h in re.split(r'^([^:]*): (.*)$\n?', k[1], flags=re.MULTILINE) if h != '' ]
            for key, val in [ (h[i], h[i + 1]) for i in range(0, len(h), 2) ]:
                self.ascii_headers[key] = val

            self.data = base64.b64decode(k[2].replace('\n', '').encode())
            self.crc = bytes_to_int(base64.b64decode(k[3].encode()))

            # verify CRC
            if self.crc != self.crc24():
                raise Exception("Bad CRC")  # pragma: no cover

        # dump fields in all contained packets per RFC 4880, without using pgpdump
        if self.data != b'':
            pos = 0
            while pos < len(self.data):
                self.packets.append(PGPPacket(self.data[pos:]))
                pos += len(self.packets[-1].__bytes__())

    def crc24(self):
        # CRC24 computation, as described in the RFC 4880 section on Radix-64 Conversions
        #
        # The checksum is a 24-bit Cyclic Redundancy Check (CRC) converted to
        # four characters of radix-64 encoding by the same MIME base64
        # transformation, preceded by an equal sign (=).  The CRC is computed
        # by using the generator 0x864CFB and an initialization of 0xB704CE.
        # The accumulation is done on the data before it is converted to
        # radix-64, rather than on the converted data.
        ##TODO: if self.data == b'', work on the output of self.__bytes__() instead
        if self.data == b'':
            return None  # pragma: no cover

        crc = self.crc24_init
        sig = [ ord(i) for i in self.data ] if type(self.data) is str else self.data

        for loc in range(0, len(self.data)):
            crc ^= sig[loc] << 16

            for i in range(0, 8):
                crc <<= 1
                if crc & 0x1000000:
                    crc ^= self.crc24_poly

        return crc & 0xFFFFFF

    def extract_pgp_ascii_block(self):
        data = self.bytes

        # if type is bytes, try to decode so re doesn't choke
        if self.is_ascii:
            data = data.decode()

        # this is binary data; skip extracting the block and move on
        else:
            self.bytes = b''
            self.data = data
            return

        # are there any ASCII armored PGP blocks present? if not, we may be dealing with binary data instead
        if self.type is None and re.search(r'-----BEGIN PGP ([A-Z ]*)-----', data,
                                           flags=re.MULTILINE | re.DOTALL) is None:
            self.bytes = b''
            self.data = data.encode()
            return

        # find all ASCII armored PGP blocks
        pgpiter = list(re.finditer(ASCII_BLOCK, data, flags=re.MULTILINE | re.DOTALL))

        # return all blocks
        if self.type is None and all:
            # try to determine block type
            if len(pgpiter) == 1:
                for m in Magic.__members__.values():
                    if re.search(m.value, data, flags=re.MULTILINE | re.DOTALL):
                        self.type = m
                        break

            _bytes = b''

            for m in pgpiter:
                _bytes += data[m.start():m.end()].encode()

            self.bytes = _bytes
            return

        # return the first block only
        if self.type is None and not all:
            m = pgpiter[0]

            # try to determine block type
            for _m in Magic.__members__.values():
                if re.search(m.value, data, flags=re.MULTILINE | re.DOTALL):
                    self.type = _m
                    break

            self.bytes = data[m.start():m.end()].encode()
            return

        # return the block type that was requested
        for m in pgpiter:
            block = data[m.start():m.end()]

            # specific type
            if re.match(Magic(self.type).value, block):
                self.bytes = block.encode()
                return

        # no ASCII blocks found :(
        self.bytes = b''
        self.data = data.encode()


class PGPSignature(PGPBlock):
    @property
    def sigpkt(self):
        return self.packets[0]

    @classmethod
    def new(cls, keyid,
            sigtype=Signature.Type.BinaryDocument,
            alg=PubKeyAlgo.RSAEncryptOrSign,
            hashalg=HashAlgo.SHA512):
        # create a new signature
        newsig = PGPSignature(None)

        # create new ASCII headers
        newsig.ascii_headers['Version'] = 'PGPy v' + __version__

        # create a new header
        ##TODO: this should be moved to Packet, probably
        newheader = Header()
        newheader.always_1 = 1
        newheader.tag = Header.Tag.Signature

        # create a new signature packet
        newsig.packets = [Signature(None)]
        newsig.sigpkt.header = newheader
        newsig.sigpkt.version = Signature.Version.v4
        newsig.sigpkt.type = sigtype
        newsig.sigpkt.key_algorithm = alg
        newsig.sigpkt.hash_algorithm = hashalg

        # add hashed subpacket - signature creation time
        ##TODO: maybe use the subpacket type instead of \x02
        ##TODO: implement subpacket creation in SubPackets
        hspacket = b'\x00\x06\x05\x02' + int_to_bytes(calendar.timegm(datetime.utcnow().timetuple()), 4)
        newsig.sigpkt.hashed_subpackets.parse(hspacket)

        # add unhashed subpacket - issuer key ID
        ##TODO: maybe use the subpacket type instead of \x10
        ##TODO: implement subpacket creation in SubPackets
        spacket = b'\x09\x10' + int_to_bytes(int(keyid, 16), 8)
        spacket = int_to_bytes(len(spacket), 2) + spacket
        newsig.sigpkt.unhashed_subpackets.parse(spacket)

        return newsig

    def __init__(self, sigf):
        super(PGPSignature, self).__init__(sigf, Magic.Signature)

    def hashdata(self, subject):
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
        _data = b''
        # h = hashlib.new(spkt.hash_algorithm.name)

        # if spkt.hash_algorithm == HashAlgo.SHA1:
        #     h = SHA.new()
        #
        # elif spkt.hash_algorithm == HashAlgo.SHA256:
        #     h = SHA256.new()
        #
        # else:
        #     raise NotImplementedError()

        s = FileLoader(subject)

        if self.sigpkt.type == Signature.Type.BinaryDocument:
            _data += s.bytes

        else:
            ##TODO: sign other types of things
            raise NotImplementedError(self.sigpkt.type)  # pragma: no cover

        # add the signature trailer to the hash context
        _data += self.sigpkt.version.__bytes__()
        _data += self.sigpkt.type.__bytes__()
        _data += self.sigpkt.key_algorithm.__bytes__()
        _data += self.sigpkt.hash_algorithm.__bytes__()
        _data += self.sigpkt.hashed_subpackets.__bytes__()

        # finally, hash the final six-octet trailer and return
        hlen = 4 + len(self.sigpkt.hashed_subpackets.__bytes__())
        _data += b'\x04\xff'
        _data += int_to_bytes(hlen, 4)

        return _data


class PGPKey(PGPBlock):
    @property
    def keypkt(self):
        return self.packets[0]

    @property
    def keypkts(self):
        return [ packet for packet in self.packets if
                 hasattr(packet, "key_material") or
                 hasattr(packet, "seckey_material") ]

    @property
    def secret(self):
        return self.keypkt.secret

    @property
    def encrypted(self):
        return False if self.keypkt.stokey.id == 0 else True

    @property
    def fp(self):
        return self.keypkt.fp

    @fp.setter
    def fp(self, value):
        self.keypkt.fp = value

    @property
    def fingerprint(self):
        if self.fp is None:
            # We have not yet computed the fingerprint, so we'll have to do that now.
            # Here is the RFC 4880 section on computing v4 fingerprints:
            #
            # A V4 fingerprint is the 160-bit SHA-1 hash of the octet 0x99,
            # followed by the two-octet packet length, followed by the entire
            # Public-Key packet starting with the version field.  The Key ID is the
            # low-order 64 bits of the fingerprint.
            sha1 = hashlib.sha1()
            kmpis = self.keypkt.key_material.__bytes__()
            bcde_len = int_to_bytes(6 + len(kmpis), 2)

            # a.1) 0x99 (1 octet)
            sha1.update(b'\x99')
            # a.2 high-order length octet
            sha1.update(bcde_len[:1])
            # a.3 low-order length octet
            sha1.update(bcde_len[-1:])
            # b) version number = 4 (1 octet);
            sha1.update(b'\x04')
            # c) timestamp of key creation (4 octets);
            sha1.update(int_to_bytes(calendar.timegm(self.keypkt.key_creation.timetuple()), 4))
            # d) algorithm (1 octet): 17 = DSA (example);
            sha1.update(self.keypkt.key_algorithm.__bytes__())
            # e) Algorithm-specific fields.
            sha1.update(kmpis)

            # now store the digest
            self.fp = sha1.hexdigest().upper()

        return self.fp

    @property
    def keyid(self):
        return self.fingerprint[-16:]

    def __init__(self, keyb):
        super(PGPKey, self).__init__(keyb)

    def decrypt_keymaterial(self, passphrase):
        if not self.encrypted:
            return  # pragma: no cover

        # Encryption/decryption of the secret data is done in CFB mode using
        # the key created from the passphrase and the Initial Vector from the
        # packet.  A different mode is used with V3 keys (which are only RSA)
        # than with other key formats.  (...)
        #
        # With V4 keys, a simpler method is used.  All secret MPI values are
        # encrypted in CFB mode, including the MPI bitcount prefix.

        for pkt in self.keypkts:
            # derive a key from our passphrase. If the passphrase is correct, this will be the right one...
            sessionkey = pkt.stokey.derive_key(passphrase)

            # instantiate the correct algorithm with the correct keylength
            if pkt.stokey.alg == SymmetricKeyAlgo.CAST5:
                alg = algorithms.CAST5(sessionkey)

            # attempt to decrypt this packet!
            cipher = Cipher(alg, modes.CFB(pkt.stokey.iv), backend=default_backend())
            decryptor = cipher.decryptor()

            pt = decryptor.update(pkt.enc_seckey_material) + decryptor.finalize()

            # check the hash to see if we decrypted successfully or not
            if pkt.stokey.id == 254:
                if not pt[-20:] == hashlib.new('sha1', pt[:-20]).digest():
                    raise PGPKeyDecryptionError("Passphrase was incorrect!")

                # parse decrypted key material into pkt.seckey_material
                pkt.seckey_material.parse(pt[:-20], pkt.header.tag, pkt.key_algorithm, sec=True)
                pkt.checksum = pt[-20:]

    def undecrypt_keymaterial(self):
        for pkt in self.keypkts:
            pkt.seckey_material.reset()

    ##TODO: encrypt secret key material that is not yet encrypted
    ##TODO: generate String2Key specifier for newly encrypted data
