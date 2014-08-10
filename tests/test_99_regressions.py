""" regression testing
"""


class TestRegressions(object):
    # regression tests for actions
    def test_reg_bug_56(self, gpg_verify):
        # some imports only used by this regression test
        import hashlib

        from datetime import datetime

        from pgpy.types import Exportable

        from pgpy.packet.packets import PrivKeyV4
        from pgpy.packet.packets import PubKeyV4
        from pgpy.packet.packets import SignatureV4

        from pgpy.packet.types import MPI

        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        from pgpy.packet.subpackets.signature import CreationTime
        from pgpy.packet.subpackets.signature import Issuer
        # do a regression test on issue #56
        # re-create a signature that would have been encoded improperly as with issue #56
        # and see if it fails to verify or not

        # this was the old seckeys/TestRSA-2048.key, but stripped down to just the PrivKey packet
        sec = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" \
              "Version: GnuPG/MacGPG2 v2.0.20 (Darwin)\n" \
              "Comment: GPGTools - http://gpgtools.org\n" \
              "\n" \
              "lQOYBFOaNYoBCAC9FDOrASOxJoo3JhwCCln4wPy+A/UY1H0OYlc+MMolSwev2uDj\n" \
              "nnwmt8ziNTjLuLEh3AnKjDWA9xvY5NW2ZkB6Edo6HQkquKLH7AkpLd82kiTWHdOw\n" \
              "OH7OWQpz7z2z6e40wwHEduhyGcZ/Ja/A0+6GIb/2YFKlkwfnT92jtB94W//mL6wu\n" \
              "LOkZMoU/CS/QatervzAf9VCemvAR9NI0UJc7Y0RC1B/1cBTQAUg70EhjnmJkqyYx\n" \
              "yWqaXyfX10dsEX3+MyiP1kvUDfFwhdeL7E2H9sbFE5+MC9Eo99/Qezv3QoXzH2Tj\n" \
              "bTun+QMVkbM92dj70KiExAJya9lSLZGCoOrDABEBAAEAB/0Xie/NaVoRqvbIWytf\n" \
              "ylJyyEfOuhG7HRz9JkYD3TFqnMwgsEg7XhbI/9chuYwlZIv8vKF6wKNv4j4/wsFO\n" \
              "W1gfOktnh7Iv9Nt4YHda0+ChhmZ6l4JWl7nwTh/Mg2te6LpkgXseA8r4BXhzih62\n" \
              "tqD6ZtzjOxD0QaPZaqpw6l2D71fJ4KySAs+6tBHJCUK/b/8UGF1jYNwJFJqQw8fI\n" \
              "kcui7x4XC3kn6Ucf8rHlc0JP1H7edg4ZD83kATvybprGfhWt+TIl2edNT6Q8xoeE\n" \
              "Ypj/PNm6i5WTupo54ySlHWIo2yQxmF+4ZrupLb41EJVdXutVW8GT045SGWTyG9VY\n" \
              "zP/1BADIr7xmSjLZ9WLibi9RtQvzHPg97KlaKy475H4QhxbWkKR9drj5bWMD30Zd\n" \
              "AmD2fVJmbXBPCf0G0+wLh2X8OKptd7/oavRdafOvUbKNqTi2GFwV5CsjiTR65QCs\n" \
              "zrediV8pVdDEVu8O0vW5L9RfomsH40e4fX3izwr3VI9xqF3+lwQA8TFyYrhge1/f\n" \
              "f1iTgZM2e+GNMSPrYF2uYxZ4KBM5gW4IfFWhLoKT7G0T6LRUHka+0ruBi/eZ4nn2\n" \
              "1pAm6chSiIkJmFU+T5pzfOG509JZuedP+7dO3SUCpi7hDncpEWHIaEeBJ7pmIL6G\n" \
              "FQnTEV8mEA48Nloq+Py+c/I0D5xaprUD/3hCl7D58DkvvoIsLyyXrDHhmi68QZMU\n" \
              "7TFqVEvo0J4kx19cmF27hXe+IEt42yQwaYTrS/KtKGywPvevQ8LEan5tUTIPnuks\n" \
              "jILtgIIaMg2z/UJ7jqmjZbuoVVmqeaPTxl9thIgfmL9SlOzjwrX/9ZfKEvwaHXFr\n" \
              "ocveTSSnWCzIReI=\n" \
              "=7xdD\n" \
              "-----END PGP PRIVATE KEY BLOCK-----\n"

        pub = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" \
              "Version: GnuPG/MacGPG2 v2.0.20 (Darwin)\n" \
              "Comment: GPGTools - http://gpgtools.org\n" \
              "\n" \
              "mQENBFOaNYoBCAC9FDOrASOxJoo3JhwCCln4wPy+A/UY1H0OYlc+MMolSwev2uDj\n" \
              "nnwmt8ziNTjLuLEh3AnKjDWA9xvY5NW2ZkB6Edo6HQkquKLH7AkpLd82kiTWHdOw\n" \
              "OH7OWQpz7z2z6e40wwHEduhyGcZ/Ja/A0+6GIb/2YFKlkwfnT92jtB94W//mL6wu\n" \
              "LOkZMoU/CS/QatervzAf9VCemvAR9NI0UJc7Y0RC1B/1cBTQAUg70EhjnmJkqyYx\n" \
              "yWqaXyfX10dsEX3+MyiP1kvUDfFwhdeL7E2H9sbFE5+MC9Eo99/Qezv3QoXzH2Tj\n" \
              "bTun+QMVkbM92dj70KiExAJya9lSLZGCoOrDABEBAAE=\n" \
              "=FBhs\n" \
              "-----END PGP PUBLIC KEY BLOCK-----\n"

        # load the key above
        sk = PrivKeyV4(Exportable.ascii_unarmor(sec)['body'])
        _pk = PubKeyV4(Exportable.ascii_unarmor(pub)['body'])


        sigsubject = b"Hello!I'm a test document.I'm going to get signed a bunch of times.KBYE!"
        hdata = b"Hello!I'm a test document.I'm going to get signed a bunch of times.KBYE!" \
                b"\x04\x00\x01\n\x00\x06\x05\x02S\xe2\xba3\x04\xff\x00\x00\x00\x0c"

        # start with a shiny new SignatureV4
        sig = SignatureV4()
        sig.header.tag = 2
        sig.header.version = 4
        # signature of a binary document
        sig.sigtype = 0
        # algorithm is RSA
        sig.pubalg = 1
        # hash algorithm is SHA512
        sig.halg = 10
        # one hashed sub - creation time at `Wed Aug  6 23:28:51 UTC 2014`
        csp = CreationTime()
        csp.created = datetime(2014, 8, 6, 23, 28, 51)
        sig.subpackets['h_CreationTime'] = csp
        # one unhashed sub - issuer key ID `0xC0F2210E0F193DCD`
        isp = Issuer()
        isp.issuer = bytearray(b'\xC0\xF2\x21\x0E\x0F\x19\x3D\xCD')
        sig.subpackets['Issuer'] = isp
        # hash2; should be 0x9f 0x02
        sig.hleft = hashlib.new('sha512', hdata).digest()[:2]

        signer = sk.keymaterial.__privkey__().signer(padding.PKCS1v15(), hashes.SHA512(), default_backend())
        signer.update(hdata)
        s = signer.finalize()

        # add signature bytes to sig
        sig.signature.md_mod_n = MPI(sig.bytes_to_int(s))

        # update header length in sig
        sig.header.length += len(sig.__bytes__()[len(sig.header):])

        ##TODO: verify sig with PGPy

        # verify sig with gpg
        ##TODO: this is temporary until PGPSignature makes its return, or Signature objects become exportable
        class TempExportableSig(Exportable):
            magic = 'SIGNATURE'

            def __init__(self):
                super(TempExportableSig, self).__init__()
                self.sig = None

            def __bytes__(self):
                return self.sig.__bytes__()

        esig = TempExportableSig()
        esig.sig = sig


        # write the subject
        with open('tests/testdata/subj', 'w') as sf:
            sf.write(sigsubject.decode('latin-1'))
            sf.flush()

        # write the signature
        with open('tests/testdata/subj.asc', 'w') as sf:
            sf.write(str(esig))
            sf.flush()

        # write the pubkey
        with open('tests/testdata/pub.gpg', 'wb') as kr:
            kr.write(bytes(_pk))
            kr.flush()

        assert 'Good signature from' in gpg_verify('subj', 'subj.asc', keyring='./pub.gpg')

        os.remove('tests/testdata/subj')
        os.remove('tests/testdata/subj.asc')
        os.remove('tests/testdata/pub.gpg')
