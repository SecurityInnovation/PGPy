""" pgp.py

"""
import re
import collections
import base64
import hashlib
import calendar
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from .fileloader import FileLoader
from .reg import *
from .util import bytes_to_int, int_to_bytes
from .packet import PGPPacket
from .packet.fields import Header, SymmetricKeyAlgo
from .packet.keyfields import MPIFields
from .errors import PGPError

def PGPLoad(pgpbytes):
    # load pgpbytes regardless of type, first
    f = FileLoader(pgpbytes)

    b = []

    # now, are there any ASCII PGP blocks at all?
    if f.is_ascii():
        # decode/parse ASCII PGP blocks
        nascii = list(re.finditer(ASCII_BLOCK, f.bytes.decode(), flags=re.MULTILINE | re.DOTALL))

        if len(nascii) == 0:
            raise PGPError("No PGP blocks to read!")

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
        payload = '\n'.join(payload[i:i+64] for i in range(0, len(payload), 64))

        # figure out block type magic
        t = ""
        if self.type is not None:
            t = str(self.type)

        return self.ASCII_FORMAT.format(
                block_type=t,
                headers=headers,
                packet=payload,
                crc=base64.b64encode(int_to_bytes(self.crc, 3)).decode(),
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
            for key, val in [ (h[i], h[i+1]) for i in range(0, len(h), 2) ]:
                self.ascii_headers[key] = val

            self.data = base64.b64decode(k[2].replace('\n', '').encode())
            self.crc = bytes_to_int(base64.b64decode(k[3].encode()))

            # verify CRC
            if self.crc != self.crc24():
                raise Exception("Bad CRC")

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
        if self.data == b'':
            return None

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
        if self.is_ascii():
            data = data.decode()

        # this is binary data; skip extracting the block and move on
        else:
            self.bytes = b''
            self.data = data
            return

        # are there any ASCII armored PGP blocks present? if not, we may be dealing with binary data instead
        if self.type is None and re.search(r'-----BEGIN PGP ([A-Z ]*)-----', data, flags=re.MULTILINE | re.DOTALL) is None:
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
                self.bytes =  block.encode()
                return

        # no ASCII blocks found :(
        self.bytes = b''
        self.data = data.encode()


class PGPSignature(PGPBlock):
    def __init__(self, sigf):
        super(PGPSignature, self).__init__(sigf, Magic.Signature)
        ##TODO: handle creating a new signature


class PGPKey(PGPBlock):
    def __init__(self, keyb):
        super(PGPKey, self).__init__(keyb)

    def __getattr__(self, item):
        if item == "secret":
            return self.packets[0].secret

        if item in ["fingerprint", "keyid"] and self.fp is None:
            # We have not yet computed the fingerprint, so we'll have to do that now.
            # Here is the RFC 4880 section on computing v4 fingerprints:
            #
            # A V4 fingerprint is the 160-bit SHA-1 hash of the octet 0x99,
            # followed by the two-octet packet length, followed by the entire
            # Public-Key packet starting with the version field.  The Key ID is the
            # low-order 64 bits of the fingerprint.
            sha1 = hashlib.sha1()

            # kmpis = b''
            # for mpi in self.packets[0].key_material.fields.values():
            #     kmpis += mpi['bytes']
            kmpis = self.packets[0].key_material.__bytes__()

            bcde_len = int_to_bytes(6 + len(kmpis), 2)

            # a.1) 0x99 (1 octet)
            sha1.update(b'\x99')
            # a.2 high-order length octet
            # sha1.update(int_to_bytes(self.packets[0].header.length)[0:1])
            sha1.update(bcde_len[:1])
            # a.3 low-order length octet
            # sha1.update(int_to_bytes(self.packets[0].header.length)[-1:])
            sha1.update(bcde_len[-1:])
            # b) version number = 4 (1 octet);
            sha1.update(b'\x04') # this is a v4 fingerprint
            # c) timestamp of key creation (4 octets);
            sha1.update(int_to_bytes(calendar.timegm(self.packets[0].key_creation.timetuple()), 4))
            # d) algorithm (1 octet): 17 = DSA (example);
            sha1.update(self.packets[0].key_algorithm.__bytes__())
            # e) Algorithm-specific fields.
            sha1.update(kmpis)

            # now store the digest
            self.fp = sha1.hexdigest().upper()

        if item == "fingerprint":
            return self.fp

        if item == "keyid":
            # ... The Key ID is the low-order 64-bits of the fingerprint.
            return self.fp[-16:]

        if item == "encrypted":
            if self.packets[0].stokey.id != 0:
                return True

            return False

    def decrypt_keymaterial(self, passphrase):
        if not self.encrypted:
            return

        # Encryption/decryption of the secret data is done in CFB mode using
        # the key created from the passphrase and the Initial Vector from the
        # packet.  A different mode is used with V3 keys (which are only RSA)
        # than with other key formats.  (...)
        #
        # With V4 keys, a simpler method is used.  All secret MPI values are
        # encrypted in CFB mode, including the MPI bitcount prefix.

        for i, pkt in [ (i, pkt) for i, pkt in enumerate(self.packets)
                     if pkt.header.tag in [Header.Tag.PrivKey, Header.Tag.PrivSubKey]
                     and pkt.stokey.id != 0 ]:
            # derive a key from our passphrase. If the passphrase is correct, this will be the right one...
            sessionkey = pkt.stokey.derive_key(passphrase)

            # instantiate the correct algorithm with the correct keylength
            if pkt.stokey.alg == SymmetricKeyAlgo.CAST5:
                alg = algorithms.CAST5(sessionkey)
                # alg = algorithms.CAST5(sessionkey[-16:])

            # attempt to decrypt this packet!
            cipher = Cipher(alg, modes.CFB(pkt.stokey.iv), backend=default_backend())
            decryptor = cipher.decryptor()

            ct = decryptor.update(pkt.enc_seckey_material) + decryptor.finalize()

            # check the hash to see if we decrypted successfully or not
            if pkt.stokey.id == 254:
                if not ct[-20:] == hashlib.new('sha1', ct[:-20]).digest():
                    raise PGPError("Passphrase was incorrect!")

                # parse decrypted key material into pkt.seckey_material
                # self.packets[i]
                pkt.seckey_material.parse(ct[:-20], pkt.header.tag, pkt.key_algorithm, sec=True)
                pkt.checksum = ct[-20:]

    ##TODO: encrypt secret key material that is not yet encrypted
    ##TODO: generate String2Key specifier for newly encrypted data