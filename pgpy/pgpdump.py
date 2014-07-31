""" pgpdump.py
"""
import calendar
from datetime import datetime

from .packet.types import PubKeyAlgo

from .packet.fields.fields import Header
from .packet.fields.keyfields import String2Key
from .packet.subpackets import SigSubPacket
from .packet.subpackets import UASubPacket


class PGPDumpFormat(object):
    @staticmethod
    def bytefield(f):
        if not isinstance(f, bytearray):
            f = bytearray(f)
        return ''.join('{:02x} '.format(c) for c in f)

    def __init__(self, pktobj):
        self.out = []
        self.keycreation = 0

        for pkt in pktobj.packets:
            o = ""
            # print the header line first
            o += "{hformat}: {pktname}(tag {tagnum})({length} bytes)\n".format(
                hformat="Old" if pkt.header.format == 0 else "New",
                pktname=pkt.name,
                tagnum=pkt.header.tag.value,
                length=pkt.header.length
            )

            # state machine time!
            if pkt.header.tag.is_signature:
                o += self.signature_fields(pkt)

            if pkt.header.tag.is_key:
                o += self.pubkey_fields(pkt)

            if pkt.header.tag.is_privkey:
                o += self.privkey_fields(pkt)

            if pkt.header.tag == Header.Tag.Trust:
                o += "\tTrust - {trustbytes}\n".format(
                    trustbytes=self.bytefield(pkt.trust)
                )

            if pkt.header.tag == Header.Tag.UserID:
                o += "\tUser ID - {userid}\n".format(
                    userid=pkt.data.decode()
                )

            if pkt.header.tag == Header.Tag.UserAttribute:
                o += self.ua_subpkts(pkt)

            # because python 2.7 is stupid
            if bytes is str:
                o = o.decode()

            # add to self.out
            self.out.append(o[:-1])

    def pkt_ver(self, pkt):
        ##TODO: unhardcode this once PGPy can parse v3 packets
        o = "\tVer 4 - new\n" if pkt.version == 4 else ""
        return o

    def signature_fields(self, pkt):
        o = ""
        o += self.pkt_ver(pkt)
        o += "\tSig type - {tname}({thex}).\n".format(
            tname=str(pkt.type),
            thex="{:#04x}".format(pkt.type.value)
        )
        o += "\tPub alg - {paname}(pub {panum})\n".format(
            paname=str(pkt.key_algorithm),
            panum=pkt.key_algorithm.value
        )
        o += "\tHash alg - {haname}(hash {hanum})\n".format(
            haname=str(pkt.hash_algorithm),
            hanum=pkt.hash_algorithm.value
        )
        o += self.subpkt_fields(pkt)
        o += "\tHash left 2 bytes - {hash2}\n".format(
            hash2=self.bytefield(pkt.hash2)
        )
        o += self.mpi_fields(pkt)
        return o

    def pubkey_fields(self, pkt):
        o = ""
        o += self.pkt_ver(pkt)
        o += "\tPublic key creation time - {keycdate}\n".format(
            keycdate=pkt.key_creation.strftime("%a %b %e %H:%M:%S UTC %Y")
        )
        self.keycreation = calendar.timegm(pkt.key_creation.timetuple())
        o += "\tPub alg - {alg}(pub {algn})\n".format(
            alg=str(pkt.key_algorithm),
            algn=pkt.key_algorithm.value
        )
        o += self.mpi_fields(pkt)

        return o

    def privkey_fields(self, pkt):
        o = ""
        o += self.string2key_fields(pkt)
        if pkt.stokey.id == 0:
            o += self.mpi_fields(pkt, True)

        else:
            o += self.enc_mpi_fields(pkt)

        if pkt.stokey.id == 254:
            o += "\tEncrypted SHA1 hash\n"

        if pkt.stokey.id in [0, 255]:
            chksum = self.bytefield(pkt.checksum)
            o += "\tChecksum - {chksum}\n".format(chksum=chksum)

        return o

    def subpkt_fields(self, pkt):
        o = ""

        for st in [pkt.hashed_subpackets, pkt.unhashed_subpackets]:
            for sub in st.subpackets:
                o += "\t{hashed}Sub: {spname}(sub {spid})({splen} bytes)\n".format(
                    hashed="Hashed " if st.hashed else "",
                    spname=str(sub.type),
                    spid=sub.type.value,
                    splen=sub.length - 1
                )

                if sub.type == SigSubPacket.Type.SigCreationTime:
                    o += "\t\tTime - {date}\n".format(
                        date=sub.payload.strftime("%a %b %e %H:%M:%S UTC %Y")
                    )

                if sub.type == SigSubPacket.Type.KeyExpirationTime:
                    rt = datetime.utcfromtimestamp(self.keycreation + sub.payload)
                    o += "\t\tTime - {date}\n".format(
                        date=rt.strftime("%a %b %e %H:%M:%S UTC %Y")
                    )

                if sub.type == SigSubPacket.Type.Issuer:
                    o += "\t\tKey ID - 0x{keyid}\n".format(keyid=sub.payload.decode())

                if sub.type == SigSubPacket.Type.KeyFlags:
                    for flag in sub.payload:
                        o += "\t\tFlag - {flag}\n".format(flag=str(flag))

                if sub.type == SigSubPacket.Type.PreferredSymmetricAlgorithms:
                    for alg in sub.payload:
                        o += "\t\tSym alg - {alg}(sym {algn})\n".format(
                            alg=str(alg),
                            algn=alg.value
                        )

                if sub.type == SigSubPacket.Type.PreferredHashAlgorithms:
                    for alg in sub.payload:
                        o += "\t\tHash alg - {alg}(hash {algn})\n".format(
                            alg=str(alg),
                            algn=alg.value
                        )

                if sub.type == SigSubPacket.Type.PreferredCompressionAlgorithms:
                    for alg in sub.payload:
                        o += "\t\tComp alg - {alg}(comp {algn})\n".format(
                            alg=str(alg),
                            algn=alg.value
                        )

                if sub.type == SigSubPacket.Type.KeyServerPreferences:
                    for pref in sub.payload:
                        o += "\t\tFlag - {flag}\n".format(flag=str(pref))

                if sub.type == SigSubPacket.Type.Features:
                    for feature in sub.payload:
                        o += "\t\tFlag - {flag}\n".format(flag=str(feature))

                if sub.type == SigSubPacket.Type.Revocable:
                    o += "\t\tRevocable - {rev}\n".format(
                        rev="Yes" if sub.payload else "No"
                    )

                if sub.type == SigSubPacket.Type.PolicyURL:
                    o += "\t\tURL - {url}\n".format(url=sub.payload.decode())

                if sub.type == SigSubPacket.Type.PrimaryUserID:
                    o += "\t\tPrimary - {flag}\n".format(flag="Yes" if sub.payload else "No")

                if sub.type == SigSubPacket.Type.EmbeddedSignature:
                    o += self.signature_fields(sub.payload)

        return o

    def ua_subpkts(self, pkt):
        o = ""
        for spkt in pkt.subpackets.subpackets:
            o += "\tSub: {spname}(sub {spnum})({spsize} bytes)\n".format(
                spname=spkt.name,
                spnum=spkt.type.value,
                spsize=spkt.length - 1
            )

            if spkt.type == UASubPacket.Type.Image:
                o += "\t\tImage encoding - {enc}(enc {encn})\n" \
                     "\t\tImage data({idl} bytes)\n".format(
                         enc=spkt.encoding.name,
                         encn=spkt.encoding.value,
                         idl=len(spkt.payload)
                     )

        return o

    def string2key_fields(self, pkt):
        o = ""
        if pkt.stokey.id in [254, 255]:
            o += "\tSym alg - {salg}(sym {salgn})\n".format(
                salg=str(pkt.stokey.alg),
                salgn=pkt.stokey.alg.value
            )

            o += "\t{stokeytype}(s2k {stokeytypenum}):\n".format(
                stokeytype=str(pkt.stokey.type),
                stokeytypenum=pkt.stokey.type.value
            )

            o += "\t\tHash alg - {hash}(hash {hashn})\n".format(
                hash=str(pkt.stokey.hash),
                hashn=pkt.stokey.hash.value
            )

            if pkt.stokey.type in [String2Key.Type.Salted, String2Key.Type.Iterated]:
                o += "\t\tSalt - {saltbytes}\n".format(saltbytes=self.bytefield(pkt.stokey.salt))

            if pkt.stokey.type == String2Key.Type.Iterated:
                o += "\t\tCount - {count}(coded count {c})\n".format(
                    count=pkt.stokey.count,
                    c=pkt.stokey.c
                )

        if pkt.stokey.id != 0:
            o += "\tIV - {ivbytes}\n".format(ivbytes=self.bytefield(pkt.stokey.iv))

        return o

    def mpi_fields(self, pkt, sec=False):
        o = ""

        if pkt.header.tag.is_signature:
            mpis = pkt.signature
            mpifn = pkt.signature.sigfields

        if pkt.header.tag.is_key:
            mpis = pkt.key_material
            mpifn = pkt.key_material.pubfields

        if pkt.header.tag.is_privkey and sec:
            mpifn = pkt.key_material.privfields

        for mpi in mpifn:
            o += "\t{mname}({bitlen} bits) - {keybytes}\n".format(
                mname=getattr(mpis.__class__, mpi).__doc__,
                bitlen=getattr(mpis, mpi)['bitlen'],
                keybytes=self.bytefield(getattr(mpis, mpi)['bytes']),
            )

        # Only print the encoding if it's a signature packet
        if pkt.header.tag.is_signature:
            o += "\t\t-> {enc}\n".format(enc=mpis.encoding)

        return o

    def enc_mpi_fields(self, pkt):
        o = ""

        if pkt.key_algorithm == PubKeyAlgo.RSAEncryptOrSign:
            o += "\tEncrypted RSA d\n"
            o += "\tEncrypted RSA p\n"
            o += "\tEncrypted RSA q\n"
            o += "\tEncrypted RSA u\n"

        if pkt.key_algorithm == PubKeyAlgo.DSA:
            o += "\tEncrypted DSA x\n"

        if pkt.key_algorithm == PubKeyAlgo.ElGamal:
            o += "\tEncrypted ElGamal x\n"

        return o
