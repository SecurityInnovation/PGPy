""" pgpdump.py
"""
import calendar
from datetime import datetime

from .fields import Header, SubPacket, PubKeyAlgo


class PGPDumpFormat(object):
    def __init__(self, pktobj):
        self.out = []

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
            if pkt.header.tag == Header.Tag.Signature:
                o += self.signature_fields(pkt)

            if pkt.header.tag == Header.Tag.UserID:
                o += "\tUser ID - {userid}\n".format(
                    userid=pkt.data.decode()
                )

            if pkt.header.tag in [Header.Tag.PubKey, Header.Tag.PubSubKey]:
                o += self.pubkey_fields(pkt)

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

        # python 2.7
        if bytes is str:
            h2 = ''.join('{:02x} '.format(ord(c)) for c in pkt.hash2)

        # python 3
        else:
            h2 = ''.join('{:02x} '.format(c) for c in pkt.hash2)

        o += "\tHash left 2 bytes - {hash2}\n".format(
            hash2=h2
        )
        o += self.mpi_fields(pkt)
        return o

    def pubkey_fields(self, pkt):
        o = ""
        o += self.pkt_ver(pkt)
        o += "\tPublic key creation time - {keycdate}\n".format(
            keycdate=pkt.key_creation.strftime("%a %b %d %H:%M:%S UTC %Y")
        )
        o += "\tPub alg - {alg}(pub {algn})\n".format(
            alg=str(pkt.key_algorithm),
            algn=pkt.key_algorithm.value
        )
        o += self.mpi_fields(pkt)

        return o

    def subpkt_fields(self, pkt):
        o = ""

        for st in [pkt.hashed_subpackets, pkt.unhashed_subpackets]:
            for sub in st.subpackets:
                o += "\t{hashed}Sub: {spname}(sub {spid})({splen} bytes)\n".format(
                    hashed="Hashed " if st.hashed else "",
                    spname=str(sub.type),
                    spid=sub.type.value,
                    splen=sub.length - 2
                )

                if sub.type == SubPacket.Type.SigCreationTime:
                    o += "\t\tTime - {date}\n".format(
                        date=sub.payload.strftime("%a %b %e %H:%M:%S UTC %Y")
                    )

                if sub.type == SubPacket.Type.KeyExpirationTime:
                    ct = calendar.timegm([ p for p in pkt.hashed_subpackets.subpackets + pkt.unhashed_subpackets.subpackets
                                               if p.type == SubPacket.Type.SigCreationTime ][0].payload.timetuple())
                    rt = datetime.utcfromtimestamp(ct + sub.payload)
                    o += "\t\tTime - {date}\n".format(
                        date=rt.strftime("%a %b %e %H:%M:%S UTC %Y")
                    )

                if sub.type == SubPacket.Type.Issuer:
                    o += "\t\tKey ID - 0x{keyid}\n".format(keyid=sub.payload.decode())

                if sub.type == SubPacket.Type.KeyFlags:
                    for flag in sub.payload:
                        o += "\t\tFlag - {flag}\n".format(flag=str(flag))

                if sub.type == SubPacket.Type.PreferredSymmetricAlgorithms:
                    for alg in sub.payload:
                        o += "\t\tSym alg - {alg}(sym {algn})\n".format(
                            alg=str(alg),
                            algn=alg.value
                        )

                if sub.type == SubPacket.Type.PreferredHashAlgorithms:
                    for alg in sub.payload:
                        o += "\t\tHash alg - {alg}(hash {algn})\n".format(
                            alg=str(alg),
                            algn=alg.value
                        )

                if sub.type == SubPacket.Type.PreferredCompressionAlgorithms:
                    for alg in sub.payload:
                        o += "\t\tComp alg - {alg}(comp {algn})\n".format(
                            alg=str(alg),
                            algn=alg.value
                        )

                if sub.type == SubPacket.Type.KeyServerPreferences:
                    for pref in sub.payload:
                        o += "\t\tFlag - {flag}\n".format(flag=str(pref))

                if sub.type == SubPacket.Type.Features:
                    for feature in sub.payload:
                        o += "\t\tFlag - {flag}\n".format(flag=str(feature))

                if sub.type == SubPacket.Type.Revocable:
                    o += "\t\tRevocable - {rev}\n".format(
                        rev="Yes" if sub.payload else "No"
                    )
        return o

    def mpi_fields(self, pkt):
        o = ""

        if pkt.header.tag == Header.Tag.Signature:
            mpis = pkt.signature

        if pkt.header.tag in [Header.Tag.PubKey, Header.Tag.PubSubKey,
                              Header.Tag.PrivKey, Header.Tag.PrivSubKey]:
            mpis = pkt.key_material

        for mpi in mpis.fields.values():
            # python 2.7
            if bytes is str:
                kb = ''.join('{:02x} '.format(ord(c)) for c in mpi['bytes'])
            # python 3
            else:
                kb = ''.join('{:02x} '.format(c) for c in mpi['bytes'])

            o += "\t{mname}({bitlen} bits) - {keybytes}\n".format(
                mname=mpi['name'],
                bitlen=mpi['bitlen'],
                keybytes=kb,
            )

        # Only print the encoding if it's a signature packet
        if pkt.header.tag == Header.Tag.Signature:
            o += "\t\t-> {enc}\n".format(enc=mpis.encoding)

        return o