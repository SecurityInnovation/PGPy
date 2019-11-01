""" test field parsing
"""
import pytest

import itertools

from pgpy.constants import HashAlgorithm
from pgpy.constants import String2KeyType
from pgpy.constants import SymmetricKeyAlgorithm
from pgpy.constants import S2KGNUExtension
from pgpy.packet.fields import String2Key
from pgpy.packet.types import Header
from pgpy.packet.subpackets import Signature
from pgpy.packet.subpackets import UserAttribute
from pgpy.packet.subpackets.types import Header as HeaderSP
from pgpy.packet.subpackets.types import Opaque as OpaqueSP


_trailer = b'\xde\xca\xff\xba\xdd'
_tag = bytearray(b'\xc2')
pkt_headers = [
    # new format
    # 1 byte length - 191
    _tag + b'\xbf' +                 (b'\x00' * 191)   + _trailer,
    # 2 byte length - 192
    _tag + b'\xc0\x00' +             (b'\x00' * 192)   + _trailer,
    # 2 byte length - 8383
    _tag + b'\xdf\xff' +             (b'\x00' * 8383)  + _trailer,
    # 5 byte length - 8384
    _tag + b'\xff\x00\x00 \xc0' +    (b'\x00' * 8384)  + _trailer,
    # old format
    # 1 byte length - 255
    bytearray(b'\x88') + b'\xff' +                 (b'\x00' * 255)   + _trailer,
    # 2 byte length - 256
    bytearray(b'\x89') + b'\x01\x00' +             (b'\x00' * 256)   + _trailer,
    # 4 byte length - 65536
    bytearray(b'\x8a') + b'\x00\x01\x00\x00' +     (b'\x00' * 65536) + _trailer,
    ]

subpkt_headers = [
    # 1 byte length - 191
    bytearray(b'\xbf'                 + b'\x00' + (b'\x00' * 190)),
    # 2 byte length - 192
    bytearray(b'\xc0\x00'             + b'\x00' + (b'\x00' * 191)),
    # 2 byte length - 8383
    bytearray(b'\xdf\xff'             + b'\x00' + (b'\x00' * 8382)),
    # 5 byte length - 8384
    bytearray(b'\xff\x00\x00 \xc0'    + b'\x00' + (b'\x00' * 0x8383)),
    # 5 byte length - 65535
    bytearray(b'\xff\x00\x00\xff\xff' + b'\x00' + (b'\x00' * 65534)),
    ]


class TestHeaders(object):
    @pytest.mark.parametrize('pheader', pkt_headers)
    def test_packet_header(self, pheader):
        b = pheader[:]
        h = Header()
        h.parse(pheader)

        assert h.tag == 0x02
        assert h.length == len(pheader) - len(_trailer)
        assert pheader[h.length:] == _trailer
        assert len(h) == len(b) - len(pheader)
        assert h.__bytes__() == b[:len(h)]

    @pytest.mark.parametrize('spheader', subpkt_headers)
    def test_subpacket_header(self, spheader):
        h = HeaderSP()
        h.parse(spheader)

        assert 65537 > h.length > 1
        assert len(h) == len(h.__bytes__())


_sspclasses = {
    # 0x00: 'Opaque',
    # 0x01: 'Opaque',
    0x02: 'CreationTime',
    0x03: 'SignatureExpirationTime',
    0x04: 'ExportableCertification',
    0x05: 'TrustSignature',
    0x06: 'RegularExpression',
    0x07: 'Revocable',
    # 0x08: 'Opaque',
    0x09: 'KeyExpirationTime',
    # 0x0a: 'AdditionalDecryptionKey',  ##TODO: parse this, then uncomment
    0x0b: 'PreferredSymmetricAlgorithms',
    0x0c: 'RevocationKey',
    # 0x0d: 'Opaque',
    # 0x0e: 'Opaque',
    # 0x0f: 'Opaque',
    0x10: 'Issuer',
    # 0x11: 'Opaque',
    0x12: 'Opaque',  # reserved
    # 0x13: 'Opaque',
    0x14: 'NotationData',
    0x15: 'PreferredHashAlgorithms',
    0x16: 'PreferredCompressionAlgorithms',
    0x17: 'KeyServerPreferences',
    0x18: 'PreferredKeyServer',
    0x19: 'PrimaryUserID',
    0x1a: 'Policy',
    0x1b: 'KeyFlags',
    0x1c: 'SignersUserID',
    0x1d: 'ReasonForRevocation',
    0x1e: 'Features',
    # 0x1f: 'Target',  ##TODO: obtain one of these ##TODO: parse this, then uncomment
    0x20: 'EmbeddedSignature',
    0x21: 'IssuerFingerprint',
    0x23: 'IntendedRecipient',
    0x25: 'AttestedCertifications',
    # 0x64-0x6e: Private or Experimental
    0x64: 'Opaque',
    0x65: 'Opaque',
    0x66: 'Opaque',
    0x67: 'Opaque',
    0x68: 'Opaque',
    0x69: 'Opaque',
    0x6a: 'Opaque',
    0x6b: 'Opaque',
    0x6c: 'Opaque',
    0x6d: 'Opaque',
    0x6e: 'Opaque',
}

_uaspclasses = {
    0x01: 'Image'
}

_ssps = [
    # 0x02 - creation time
    b'\x05\x02?z\xf7\x13',
    # 0x03 - expiration time
    b'\x05\x03\x00\x12u\x00',
    # 0x04 - exportable certification
    b'\x02\x04\x00',
    # 0x05
    b'\x03\x05\x01x',
    # 0x06
    b'\x1d\x06<[^>]+[@.]liebenzell\\.org>$\x00',
    # 0x07
    b'\x02\x07\x00',
    # 0x08
    # 0x09
    b'\x05\t\x01\xe13\x80',
    # 0x0a
    b'\x17\n\x00\x11M,\x9e,\xee~&\rK\xbd\x9b[\x1b`\xbcu\x0c\xefW\x06',
    # 0x0b
    b'\x05\x0b\x07\n\x03\x04',
    # 0x0c
    b'\x17\x0c\x80\x119\x06\xf8\xf6\x98d\x9e\xbePG\xd0\xba\x11\xed\xa7\xd0!<\xa1\x1b',
    # 0x10
    b"\t\x10\n'Z\xb6\xb4\xbc\xa5\xd7",
    # 0x12
    b'\x05\x12R/\xe2d',
    # 0x14
    b'\x87\x14\x80\x00\x00\x00\x00\x10\x00nsignotes@grep.be"http://www.grep.be/gpg/CF62318D5BBE'
    b'D48F33ACD5431B0006256FB29164/0138DA92EDFFB27DD270F86DB475E207BAB58229.asc"',
    # 0x15
    b'\x03\x15\x03\x02',
    # 0x16
    b'\x03\x16\x02\x01',
    # 0x17
    b'\x02\x17\x80',
    # 0x18
    b'\x19\x18hkp://fakekey.server.tld',
    # 0x19
    b'\x02\x19\x01',
    # 0x1a
    b'\x15\x1ahttp://www.blaap.org',
    # 0x1b
    b'\x02\x1b#',
    # 0x1c
    b' \x1cSander Temme <sander@temme.net>',
    # 0x1d
    b'\x02\x1d\x00',
    # 0x1e
    b'\x02\x1e\x01',
    # 0x20
    b"\xc0] \x04\x19\x01\n\x00\x06\x05\x02S\x9a6\x06\x00\n\t\x10\x19q\xf7\xb8\x80g\xdd\x07\xd20"
    b"\x07\xfd\x19\xbb\xea;6|\xdb1\xf3\xbc\xfbZ\x1d\xb6\xcfY\xe6&\xe9\xed\xf1O\xdc\x84\xdd\xe1"
    b"\x88\xff\xb9\xba\x1a\xe9\x8d\x16K\xd2\xb4\xf49\x7f(\xc9\xe8/\xf6\x87\x0f\xef\xb7*\xf9'r{E"
    b"\xf3\x07?\xcb\xffm\x87\x86&H\xee\xc4\xbc\xf1L\x177\x92\xdb\xf9I\x16Q\xf6\x9ei\xf56z\x0f\xff"
    b"^\x92\x88Kh\xbd; \x86\xa5\xbaL\xa2\xda\x93\xae\x10\xd1Y\xa5\xa7\xb4)*\xf6\xa1,]\xd1\xe3\\"
    b"\xc3l3\xecA\xec&\x145\xe1\xc4\xd0\x15y\xb2\xf8\x0c\x0e\xd3_[\x1f\x0fM\x98\xa8J\xb3\xd9?\xa4"
    b"\xb3\x16\xee8\xad/\x07\xea\x7f\xad\x1a\x0f\xbe\x06\x94\xa51\xf6@\xae\xcdy\x92B\x1c\xd5\x04z"
    b"\xbf\xe9\xbc\x9c\xac\x99W6\x81\xad\xe0\x81\xb4\x89n\xd0_\x1c\x92\xbe\xf6\x1cmn\xe92_\x86\xcf"
    b"\xb0v\x1f\x9dk%\xbd<\x0c\x1e\x91\x0c\xec\\\xdc\x8cCu\xd8N\xf2\x82E\x00\xc8rnSY\x1b\xa0%\x13"
    b"\xc0$Q+\xd3\xd0\xd8 \x0c\xe9\xafI5&\xe5\xc1!\xaf",
    # 0x21
    b'\x16!\x04\xeb\xc8\x8a\x94\xac\xb1\x10\xf1\xbe?\xe3\xc1+GK\xb0 \x84\xc7\x12',
    # 0x65
    b'\x07eGPG\x00\x01\x01',
    ]

sig_subpkts = [bytearray(sp) + _trailer for sp in _ssps]


class TestSignatureSubPackets(object):
    @pytest.mark.parametrize('sigsubpacket', sig_subpkts)
    def test_load(self, sigsubpacket):
            spb = sigsubpacket[:]
            sp = Signature(spb)

            assert spb == _trailer
            assert len(sp) == len(sigsubpacket) - len(_trailer)
            assert len(sp) == len(sp.__bytes__())
            assert sp.__bytes__() == bytes(sigsubpacket[:-len(_trailer)])

            if sp.header.typeid in _sspclasses:
                assert sp.__class__.__name__ == _sspclasses[sp.header.typeid]

            else:
                assert isinstance(sp, OpaqueSP)


_uassps = [
    # 0x01
    b'\xc3\xfd\x01\x10\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xd8\xff'
    b'\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xdb\x00\x84\x00\xff\xff\xff'
    b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
    b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
    b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01\xff\xff\xff\xff'
    b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
    b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
    b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xc0\x00\x11\x08\x00x'
    b'\x00x\x03\x01\x11\x00\x02\x11\x01\x03\x11\x01\xff\xc4\x01\xa2\x00\x00\x01\x05\x01\x01\x01'
    b'\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x10'
    b'\x00\x02\x01\x03\x03\x02\x04\x03\x05\x05\x04\x04\x00\x00\x01}\x01\x02\x03\x00\x04\x11\x05'
    b'\x12!1A\x06\x13Qa\x07"q\x142\x81\x91\xa1\x08#B\xb1\xc1\x15R\xd1\xf0$3br\x82\t\n\x16\x17'
    b'\x18\x19\x1a%&\'()*456789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz\x83\x84\x85\x86\x87\x88\x89\x8a'
    b'\x92\x93\x94\x95\x96\x97\x98\x99\x9a\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xb2\xb3\xb4\xb5'
    b'\xb6\xb7\xb8\xb9\xba\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9'
    b'\xda\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\x01'
    b'\x00\x03\x01\x01\x01\x01\x01\x01\x01\x01\x01\x00\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05'
    b'\x06\x07\x08\t\n\x0b\x11\x00\x02\x01\x02\x04\x04\x03\x04\x07\x05\x04\x04\x00\x01\x02w\x00'
    b'\x01\x02\x03\x11\x04\x05!1\x06\x12AQ\x07aq\x13"2\x81\x08\x14B\x91\xa1\xb1\xc1\t#3R\xf0\x15'
    b'br\xd1\n\x16$4\xe1%\xf1\x17\x18\x19\x1a&\'()*56789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz\x82'
    b'\x83\x84\x85\x86\x87\x88\x89\x8a\x92\x93\x94\x95\x96\x97\x98\x99\x9a\xa2\xa3\xa4\xa5\xa6'
    b'\xa7\xa8\xa9\xaa\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca'
    b'\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xf2\xf3\xf4\xf5'
    b'\xf6\xf7\xf8\xf9\xfa\xff\xda\x00\x0c\x03\x01\x00\x02\x11\x03\x11\x00?\x00\x92\x80\n\x00('
    b'\x00\xa0\x02\x80\n\x00(\x00\xa0\x02\x80\n\x00(\x00\xa0\x02\x80\n\x00(\x00\xa0\x02\x80\n'
    b'\x00(\x00\xa0\x02\x80\n\x00(\x00\xa0\x02\x80\n\x00(\x00\xa0\x02\x80\n\x00(\x00\xa0\x02\x80'
    b'\n\x00(\x00\xa0\x02\x80\n\x00(\x00\xa0\x02\x80\n\x00(\x00\xa0\x02\x80\n\x00(\x00\xa0\x02'
    b'\x80\n\x00(\x00\xa0\x02\x80\n\x00(\x00\xa0\x02\x80\n\x00(\x00\xa0\x02\x80\n\x00(\x00\xa0'
    b'\x02\x80\n\x00(\x00\xa0\x02\x80\n\x00(\x00\xa0\x02\x80\n\x00(\x00\xa0\x04\xc8\x1dH\xa0\x03'
    b'#\xd4~t\x00\xb4\x00P\x02d\x0e\xa6\x80\x0c\x83\xd0\x8a\x00Z\x00:P\x02dz\x8f\xccP\x02\xd0'
    b'\x01@\x05\x00\x14\x00P\x01@\x11cs\x1c\xfb\xd0\x03\xb6\x0fS@\r\x19V\xc7j\x00{\x1c\x0f~\xd4'
    b'\x00\xc0\xb9\xe4\x9e\xb4\x00\xa5;\x8c\xd0\x02\xa1\xc8\xe7\xb5\x005\xb9`>\x9f\xce\x80\x1d'
    b'\xb0z\x9a\x00i\x05\x0eA\xa0\t\x01\xc8\x07\xd6\x80\x16\x80\n\x00(\x00\xa0\x08\x81\x01\x89>'
    b'\xff\x00\xce\x80\x1d\xbdh\x01\xbfy\xb3\xd8P\x00\xfdG\xd2\x80%\xa0\x06\xeeQ\xde\x80\x14\x10'
    b'zP\x04m\xf7\x87\xe1\xfc\xe8\x01\xfb\xd6\x80\x18\xc7v\x00\xa0\x05q\xf2\x8fj\x00z\x9c\x80h'
    b'\x01\x87\xe6\x7f\xa7\xf4\xa0\t(\x00\xa0\x08\x80\x05\x8e}\xff\x00\x9d\x00I\xb5}\x05\x00/N'
    b'\x94\x01\x1b\x8e\x87\xf0\xa0\x07\x83\x91\x9a\x00B\xab\xd4\x8a\x00ju4\x00\x8d\xf7\x87\xe1'
    b'\xfc\xe8\x02M\xab\xe8(\x00\x00\x0e\x82\x80\x14\xf21@\x11)\xdb\xb8\x1f\xf2h\x01\xc8:\x9fZ'
    b'\x00}\x00\x14\x00\xc0\xa41=\xb9\xfdh\x01\xf4\x00P\x02\x11\x9e\r\x003k\x0e\x86\x80\x0c9\xeb'
    b'\xd3\xfc\xfaP\x02\xa8 \x9c\xd0\x00T\x96\x07\xb7\x1f\xa5\x00>\x80\n\x00(\x02\'\x1f7\x1d\xe8'
    b'\x02@01@\x0b@\x05\x00\x14\x00P\x01@\x05\x00\x14\x00P\x01@\x05\x00\x14\x00P\x01@\t\x81\x9c'
    b'\xf7\xa0\x05\xa0\x02\x80\n\x00(\x00\xa0\x02\x80\n\x00(\x00\xa0\x02\x80\n\x00(\x00\xa0\x02'
    b'\x80\n\x00(\x00\xa0\x02\x80\n\x00(\x00\xa0\x02\x80\n\x00(\x00\xa0\x02\x80\n\x00(\x00\xa0'
    b'\x02\x80\n\x00(\x00\xa0\x02\x80\n\x00(\x00\xa0\x02\x80\n\x00(\x00\xa0\x02\x80\n\x00(\x00'
    b'\xa0\x02\x80\n\x00(\x00\xa0\x02\x80\n\x00(\x00\xa0\x02\x80\n\x00(\x00\xa0\x02\x80\n\x00('
    b'\x00\xa0\x02\x80?\xff\xd9',
    ]
ua_subpkts = [bytearray(sp) + _trailer for sp in _uassps]


class TestUserAttributeSubPackets(object):
    @pytest.mark.parametrize('uasubpacket', ua_subpkts)
    def test_load(self, uasubpacket):
        spb = uasubpacket[:]
        sp = UserAttribute(spb)

        assert spb == _trailer
        assert len(sp) == len(uasubpacket) - len(_trailer)
        assert len(sp) == len(sp.__bytes__())
        assert sp.__bytes__() == uasubpacket[:-len(_trailer)]

        if sp.header.typeid in _uaspclasses:
            assert sp.__class__.__name__ == _uaspclasses[sp.header.typeid]

        else:
            assert isinstance(sp, OpaqueSP)


_s2k_parts = [
    # usage byte is always \xff
    b'\xff',
    # symmetric cipher algorithm list
    b'\x01\x02\x03\x04\x07\x08\x09\x0B\x0C\x0D',
    # specifier
    # b'\x00', (simple)
    # b'\x01', (iterated)
    # b'\x03', (salted)
    # hash algorithm list
    b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B',
    ]
_iv = b'\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF'
_salt = b'\xC0\xDE\xC0\xDE\xC0\xDE\xC0\xDE'
_count = b'\x10'  # expands from 0x10 to 2048
_gnu_scserials = [
    # standard 16 bytes serial
    bytearray(range(16)),
    # shorter serial
    b'\x42\x43\x44\x45'
    ]

# simple S2Ks
sis2ks = [bytearray(i) + _iv for i in itertools.product(*(_s2k_parts[:2] + [b'\x00'] + _s2k_parts[2:]))]
# salted S2Ks
sas2ks = [bytearray(i) + _salt + _iv for i in itertools.product(*(_s2k_parts[:2] + [b'\x01'] + _s2k_parts[2:]))]
# iterated S2Ks
is2ks = [bytearray(i) + _salt + _count + _iv for i in itertools.product(*(_s2k_parts[:2] + [b'\x03'] + _s2k_parts[2:]))]
# GNU extension S2Ks
gnus2ks = [bytearray(b'\xff\x00\x65\x00GNU' + i) for i in ([b'\x01'] + [b'\x02' + bytearray([len(s)]) + s for s in _gnu_scserials])]


class TestString2Key(object):
    @pytest.mark.parametrize('sis2k', sis2ks)
    def test_simple_string2key(self, sis2k):
        b = sis2k[:]
        s = String2Key()
        s.parse(sis2k)

        assert len(sis2k) == 0
        assert len(s) == len(b)
        assert s.__bytes__() == b

        assert bool(s)
        assert s.halg in HashAlgorithm
        assert s.encalg in SymmetricKeyAlgorithm
        assert s.specifier == String2KeyType.Simple
        assert s.iv == _iv

    @pytest.mark.parametrize('sas2k', sas2ks)
    def test_salted_string2key(self, sas2k):
        b = sas2k[:]
        s = String2Key()
        s.parse(sas2k)

        assert len(sas2k) == 0
        assert len(s) == len(b)
        assert s.__bytes__() == b

        assert bool(s)
        assert s.halg in HashAlgorithm
        assert s.encalg in SymmetricKeyAlgorithm
        assert s.specifier == String2KeyType.Salted
        assert s.salt == _salt
        assert s.iv == _iv

    @pytest.mark.parametrize('is2k', is2ks)
    def test_iterated_string2key(self, is2k):
        b = is2k[:]
        s = String2Key()
        s.parse(is2k)

        assert len(is2k) == 0
        assert len(s) == len(b)
        assert s.__bytes__() == b

        assert bool(s)
        assert s.halg in HashAlgorithm
        assert s.encalg in SymmetricKeyAlgorithm
        assert s.specifier == String2KeyType.Iterated
        assert s.salt == _salt
        assert s.count == 2048
        assert s.iv == _iv

    @pytest.mark.parametrize('gnus2k', gnus2ks)
    def test_gnu_extension_string2key(self, gnus2k):
        b = gnus2k[:]
        s = String2Key()
        s.parse(gnus2k)

        assert len(gnus2k) == 0
        assert len(s) == len(b)
        assert s.__bytes__() == b

        assert bool(s)
        assert s.encalg == SymmetricKeyAlgorithm.Plaintext
        assert s.specifier == String2KeyType.GNUExtension
        assert s.gnuext in S2KGNUExtension
        if s.gnuext == S2KGNUExtension.Smartcard:
            assert s.scserial is not None and len(s.scserial) <= 16
