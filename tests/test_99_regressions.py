""" I've got 99 problems but regression testing ain't one
"""
import os
import pytest
import glob
import tempfile
import warnings
from pgpy import PGPKey
from pgpy.types import Armorable


@pytest.mark.regression(issue=56)
def test_reg_bug_56(gpg_import, gpg_verify):
    # some imports only used by this regression test
    import hashlib
    from datetime import datetime

    from pgpy.pgp import PGPSignature

    from pgpy.constants import HashAlgorithm
    from pgpy.constants import PubKeyAlgorithm
    from pgpy.constants import SignatureType

    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    # do a regression test on issue #56
    # re-create a signature that would have been encoded improperly as with issue #56
    # and see if it fails to verify or not

    # this was the old seckeys/TestRSA-2048.key
    sec = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" \
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
          "ocveTSSnWCzIReK0M1Rlc3RSU0EtMjA0OCAoVEVTVElORy1VU0UtT05MWSkgPGVt\n" \
          "YWlsQGFkZHJlc3MudGxkPokBNwQTAQoAIQUCU5o1igIbIwULCQgHAwUVCgkICwUW\n" \
          "AgMBAAIeAQIXgAAKCRDA8iEODxk9zYQPB/4+kZlIwLE27J7IiZSkk+4T5CPrASxo\n" \
          "SsRMadUvoHc0eiZIlQD2Gu05oQcm4kZojJAzMv12rLtk+ZPwVOZU/TUxPYwuEyJP\n" \
          "4keFJEW9P0GiURAvYQRQCbQ5IOlIkZ0tPotb010Ej3u5rHAiVCvh/cxF16UhkXkn\n" \
          "f/wgDDWErfGIMaaruAIr0G05p4Q2G/NLgBccowSgFFfWprg3zfNPEQhH/qNs8O5m\n" \
          "ByniMZk4n2TsKGlX6eT9RrfJVQhSLoQXxYikMtiZTki4yPUhTQev62KWHQcY6zNV\n" \
          "2p9VQ24NUhVCIBnZ0CLkm38QFsS5flWVGat5kraHTXxvffz7yGHJiFkinQOYBFOa\n" \
          "NYoBCADBPjB83l1O2m/Nr5KDm6/BwKfrRsoJDmMZ8nNHNUc/zK4RI4EFKkr35PSm\n" \
          "gbA8yOlaSDWVz9zuKyOtb8Nohct2/lrac8zI+b4enZ/Z6qehoAdY1t4QYmA2PebK\n" \
          "uerBXjIF1RWsPQDpu3GIZw4oBbdu5oUGB4I9yIepindM2b2I9dlY3ct4uhRbBmXP\n" \
          "FcslmJ1K4pCurXvr4Po4DCcWqUmsGUQQbI1GUyAzSad7u9y3CRqhHFwzyFRRfl+/\n" \
          "mgB2a6XvbGlG5Dkp1g7T/HIVJu+zv58AQkFw+ABuWNKCXa3TB51bkiBQlkRTSAu2\n" \
          "tVZ8hVGZE+wUw0o9rLiy6mldFvbLABEBAAEAB/4g13LiJeBxwEn0CPy7hUAPi7B+\n" \
          "Gd/IPju1czEITxO20hBbNU9+Ezv+eVji23OaQQL3pwIEXflMOOStWys4nlR/+qZy\n" \
          "LfAFz/vxtBQwsuKeY1YcURgYbL+xOD/7ADHXfyy9NQOj7BI1pveamPkc8CvGm0LM\n" \
          "TYZi/augsrmnw/GkTuhsKwNG5G21S2YC1/I+1QlwUSLoX68pLxp/FVR5PhTWLTua\n" \
          "vzkXuPu6YGitPW9SKSqGSJCgtoDYKLBrXIqH2/UJAdVP94pXrGSu4CiqtR8kn3Vx\n" \
          "oIfVs+IRihWVZ9ATh8I3xUM4VHCnVupW0jov19bY9oGXEBKf7pYJpe+dIeyBBADZ\n" \
          "RmYfL/JSmU4HWzHmlEXjb9wnyPGls8eScfFVTZ6ULwUiqwgyOlTKqop3pIVeeIdM\n" \
          "ZnDqYTeD5bf6URNoXKmHGuQxdyUVv0aTaLTOi/GNBOk/blvaE/m/h3fKj1AnNx1r\n" \
          "AOKjY/5mJ557i2GIdfYOVYgnGJTiu1CXAcra6TqCoQQA469Hpf0fXAjDMATI4lfg\n" \
          "8nU8q7OFskBp26gjGqH0pGHdEJ4wvIZcTo/G4qrN8oIpcBkKn/3jYltIbbR31zTe\n" \
          "XuNztWcaJj0I1NhYJvDTtI8mreAvdeJPHimrCbU9HYog84aY/Ir2ogClP94tw/Tz\n" \
          "9uQs+By8IhimXzFUqtYy7esEAJZW7MNE0MnWjAZzw/iJRhwb6gIzZC9H9iHDXXmG\n" \
          "EHJ7hNnDBkViltm+ROCRPG2zh9xtaR9VBqipaEQNVZhdJXRybJ5Z+MIMeX+tGcSN\n" \
          "WaYWB6PQhqSsV9ovnFsEzNynWz/HZ2qqT4AW1v19DqpYQbPmapDdmVPmR0AXTtQh\n" \
          "WFYrPJ2JAR8EGAEKAAkFAlOaNYoCGwwACgkQwPIhDg8ZPc1uDwf/SGoiZHjUsTWm\n" \
          "4gZgZCzAjOpZs7dKjLL8Wm5G3HTFIGX0O8HCzQJARWq05N6EYmI4nPXxu08ba30S\n" \
          "ubybSeFU+iAPymqm2YNXrE2RwLWko78M0r9enUep6SvbGKnukPG7lz/33PsxIVyA\n" \
          "TfMmcmzV4chyC7pICTwgHv/zC3S/k7GoS82Z39LO4R4aDa4aubNq6mx4eHUd0MSn\n" \
          "Yud1IzRxD8cPxh9fCdoW0OpddqKNczAvO4bl5wwDafrEa7HpIX/sMVMZXo2h6Tki\n" \
          "tdLCdEfktgEjS0hTsFtfwsXt9TKi1x3HJIbcm8t78ubpWXepB/iNKVzv4punFHhK\n" \
          "iz54ZFyNdQ==\n" \
          "=WLpc\n" \
          "-----END PGP PRIVATE KEY BLOCK-----\n"

    pub = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" \
          "\n" \
          "mQENBFOaNYoBCAC9FDOrASOxJoo3JhwCCln4wPy+A/UY1H0OYlc+MMolSwev2uDj\n" \
          "nnwmt8ziNTjLuLEh3AnKjDWA9xvY5NW2ZkB6Edo6HQkquKLH7AkpLd82kiTWHdOw\n" \
          "OH7OWQpz7z2z6e40wwHEduhyGcZ/Ja/A0+6GIb/2YFKlkwfnT92jtB94W//mL6wu\n" \
          "LOkZMoU/CS/QatervzAf9VCemvAR9NI0UJc7Y0RC1B/1cBTQAUg70EhjnmJkqyYx\n" \
          "yWqaXyfX10dsEX3+MyiP1kvUDfFwhdeL7E2H9sbFE5+MC9Eo99/Qezv3QoXzH2Tj\n" \
          "bTun+QMVkbM92dj70KiExAJya9lSLZGCoOrDABEBAAG0M1Rlc3RSU0EtMjA0OCAo\n" \
          "VEVTVElORy1VU0UtT05MWSkgPGVtYWlsQGFkZHJlc3MudGxkPokBNwQTAQoAIQUC\n" \
          "U5o1igIbIwULCQgHAwUVCgkICwUWAgMBAAIeAQIXgAAKCRDA8iEODxk9zYQPB/4+\n" \
          "kZlIwLE27J7IiZSkk+4T5CPrASxoSsRMadUvoHc0eiZIlQD2Gu05oQcm4kZojJAz\n" \
          "Mv12rLtk+ZPwVOZU/TUxPYwuEyJP4keFJEW9P0GiURAvYQRQCbQ5IOlIkZ0tPotb\n" \
          "010Ej3u5rHAiVCvh/cxF16UhkXknf/wgDDWErfGIMaaruAIr0G05p4Q2G/NLgBcc\n" \
          "owSgFFfWprg3zfNPEQhH/qNs8O5mByniMZk4n2TsKGlX6eT9RrfJVQhSLoQXxYik\n" \
          "MtiZTki4yPUhTQev62KWHQcY6zNV2p9VQ24NUhVCIBnZ0CLkm38QFsS5flWVGat5\n" \
          "kraHTXxvffz7yGHJiFkiuQENBFOaNYoBCADBPjB83l1O2m/Nr5KDm6/BwKfrRsoJ\n" \
          "DmMZ8nNHNUc/zK4RI4EFKkr35PSmgbA8yOlaSDWVz9zuKyOtb8Nohct2/lrac8zI\n" \
          "+b4enZ/Z6qehoAdY1t4QYmA2PebKuerBXjIF1RWsPQDpu3GIZw4oBbdu5oUGB4I9\n" \
          "yIepindM2b2I9dlY3ct4uhRbBmXPFcslmJ1K4pCurXvr4Po4DCcWqUmsGUQQbI1G\n" \
          "UyAzSad7u9y3CRqhHFwzyFRRfl+/mgB2a6XvbGlG5Dkp1g7T/HIVJu+zv58AQkFw\n" \
          "+ABuWNKCXa3TB51bkiBQlkRTSAu2tVZ8hVGZE+wUw0o9rLiy6mldFvbLABEBAAGJ\n" \
          "AR8EGAEKAAkFAlOaNYoCGwwACgkQwPIhDg8ZPc1uDwf/SGoiZHjUsTWm4gZgZCzA\n" \
          "jOpZs7dKjLL8Wm5G3HTFIGX0O8HCzQJARWq05N6EYmI4nPXxu08ba30SubybSeFU\n" \
          "+iAPymqm2YNXrE2RwLWko78M0r9enUep6SvbGKnukPG7lz/33PsxIVyATfMmcmzV\n" \
          "4chyC7pICTwgHv/zC3S/k7GoS82Z39LO4R4aDa4aubNq6mx4eHUd0MSnYud1IzRx\n" \
          "D8cPxh9fCdoW0OpddqKNczAvO4bl5wwDafrEa7HpIX/sMVMZXo2h6TkitdLCdEfk\n" \
          "tgEjS0hTsFtfwsXt9TKi1x3HJIbcm8t78ubpWXepB/iNKVzv4punFHhKiz54ZFyN\n" \
          "dQ==\n" \
          "=lqIH\n" \
          "-----END PGP PUBLIC KEY BLOCK-----\n"

    # load the keypair above
    sk = PGPKey()
    sk.parse(sec)
    pk = PGPKey()
    pk.parse(pub)

    sigsubject = bytearray(b"Hello!I'm a test document.I'm going to get signed a bunch of times.KBYE!")

    sig = PGPSignature.new(SignatureType.BinaryDocument, PubKeyAlgorithm.RSAEncryptOrSign, HashAlgorithm.SHA512,
                           sk.fingerprint.keyid)
    sig._signature.subpackets['h_CreationTime'][-1].created = datetime(2014, 8, 6, 23, 28, 51)
    sig._signature.subpackets.update_hlen()
    hdata = sig.hashdata(sigsubject)
    sig._signature.hash2 = hashlib.new('sha512', hdata).digest()[:2]

    # create the signature
    signer = sk.__key__.__privkey__().signer(padding.PKCS1v15(), hashes.SHA512())
    signer.update(hdata)
    sig._signature.signature.from_signer(signer.finalize())
    sig._signature.update_hlen()

    # check encoding
    assert sig._signature.signature.md_mod_n.to_mpibytes()[2:3] != b'\x00'

    # with PGPy
    assert pk.verify(sigsubject, sig)

    # with GnuPG
    with tempfile.NamedTemporaryFile('w+') as subjf, \
            tempfile.NamedTemporaryFile('w+') as sigf, \
            tempfile.NamedTemporaryFile('w+') as pubf:
        subjf.write(sigsubject.decode('latin-1'))
        sigf.write(str(sig))
        pubf.write(str(pk))

        subjf.flush()
        sigf.flush()
        pubf.flush()

        with gpg_import(pubf.name):
            assert gpg_verify(subjf.name, sigf.name)


@pytest.mark.regression(issue=157)
def test_reg_bug_157(monkeypatch):
    # local imports for this
    import pgpy.constants
    from pgpy.packet.fields import String2Key
    from time import time as rtime

    # to more easily replicate this bug, hash only 8 bytes instead of 100 KiB
    monkeypatch.setattr('pgpy.constants._hashtunedata', bytearray([10, 11, 12, 13, 14, 15, 16, 17]))
    # also monkeypatch time.time to return fewer significant digits
    monkeypatch.setattr('time.time', lambda: round(rtime(), 3))
    assert len(pgpy.constants._hashtunedata) == 8

    pgpy.constants.HashAlgorithm.SHA256.tune_count()
    assert pgpy.constants.HashAlgorithm.SHA256.tuned_count > 0

    # now let's try it out and ensure that the count actually worked
    s2k = String2Key()
    s2k.encalg = pgpy.constants.SymmetricKeyAlgorithm.AES256
    s2k.specifier = pgpy.constants.String2KeyType.Iterated
    s2k.halg = pgpy.constants.HashAlgorithm.SHA256
    s2k.count = pgpy.constants.HashAlgorithm.SHA256.tuned_count

    start = rtime()
    sk = s2k.derive_key('sooper_sekret_passphrase')
    elapsed = rtime() - start

    # check that we're actually close to our target
    assert len(sk) == 32
    try:
        assert 0.1 <= round(elapsed, 1) <= 0.2

    except AssertionError:
        warnings.warn("tuned_count: {}; elapsed time: {:.5f}".format(pgpy.constants.HashAlgorithm.SHA256.tuned_count, elapsed))


_seckeys = {sk.key_algorithm.name: sk for sk in (PGPKey.from_file(f)[0] for f in sorted(glob.glob('tests/testdata/keys/*.sec.asc')))}
seckm = [
    _seckeys['DSA']._key,                                # DSA private key packet
    _seckeys['DSA'].subkeys['1FD6D5D4DA0170C4']._key,    # ElGamal private key packet
    _seckeys['RSAEncryptOrSign']._key,                   # RSA private key packet
    _seckeys['ECDSA']._key,                              # ECDSA private key packet
    _seckeys['ECDSA'].subkeys['A81B93FD16BD9806']._key,  # ECDH private key packet
]


@pytest.mark.regression(issue=172)
@pytest.mark.parametrize('keypkt', seckm, ids=[sk.pkalg.name for sk in seckm])
def test_check_checksum(keypkt):
    # this test is dirty and simple
    # take the key packet provided, and store the key material checksum
    # recompute the checksum, and ensure they match
    goodsum = keypkt.keymaterial.chksum[:]
    keypkt.keymaterial._compute_chksum()
    assert goodsum == keypkt.keymaterial.chksum


@pytest.mark.regression(issue=183)
def test_decrypt_unsigned_message():
    from pgpy import PGPKey, PGPMessage
    from pgpy.errors import PGPError

    # these keys are small because the regression test doesn't really need the security
    # if you're reading this, *DO NOT GENERATE RSA KEYS THIS SMALL*
    # also, it's probably better to sign-then-encrypt rather than encrypt-then-sign
    decrypt_key = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" \
                  "Version: PGPy v0.4.2\n" \
                  "\n" \
                  "xcA4BFlKzk4BAgDL9E6Lpzq9yNhRP49HXeOSYTz4DPI1A2wxwI97qjZFsJ2lJ2aV\n" \
                  "SYFpbuS6DEPaya+98HQ6xM7o2PhbUnHqcXHzABEBAAEAAf9U/XOVwpQ57e4mvWPJ\n" \
                  "i5h/sUGk5FAyQ0Dc4q9oCyAenaIIe5npbsR+oKmUHwJ5wWgfrTaxvAkBl15kMtSN\n" \
                  "VItBAQDv/8BdIdW2Bc9+qvCtC2xiUJ/3Rd+eyXMZhn4VMdA8sQEA2Y1aRBpWjHo9\n" \
                  "g9KydxAewt8LUwchRHeonMmILuZ58eMBALP8euss11ELnjDOLrgRP2swnOTTTk3b\n" \
                  "P6aV8/rbcEXOUgPNG1JlZ3Jlc3NvIEVuY3J5cHRlciAoUFIjMTgzKcJrBBMBAgAV\n" \
                  "BQJZSs6CAhsOAgsHAhUCAhYAAh4BAAoJEA2I8KkOVzh/+IMCAI308quFk/lJXPF/\n" \
                  "bpvwwgFa9bRdIzl07Qu+3oQcEm+1cu6ivznewIEmQclSUpSLjXrS/LysQSAQye+J\n" \
                  "PgSEalQ=\n" \
                  "=Sg/Y\n" \
                  "-----END PGP PRIVATE KEY BLOCK-----\n"
    sign_key = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" \
               "Version: PGPy v0.4.2\n" \
               "\n" \
               "xcA4BFlKzkMBAgDQZA3bao1qo3XkuUDOaFm1x5TkAAMUUUxtmj+dSR0wl7uRzxWm\n" \
               "8naFpsJ1Mah/I8RlS1oZizaDI7BzbOvGUGjLABEBAAEAAf95RBAQQ/QhPxfmzqrY\n" \
               "sj6qGocZGqywERMxoJYuOBLFaCjdT8xk0syI0LOCetwDmUWerUPWO52w9T5Gj295\n" \
               "YUDpAQD7DSmifDMssvG5F9JYWdKobEwWxVsjyaYR/vbH/1Iy3QEA1H+e66Jz1ERl\n" \
               "yPLyl4E5chwO2l+VMxiFod3Dvo8C68cA/0GWJIdK0NzSNZwS6wFabZg2R1pZWxJJ\n" \
               "B0tsI0EqbUgNTiXNGFJlZ3Jlc3NvIFNpZ25lciAoUFIjMTgzKcJoBBMBAgASBQJZ\n" \
               "Ss53AhsCAhUCAhYAAh4BAAoJED6S3OqHJjksTzQCAM73UuXFtM2qXp4zfOGYEMsj\n" \
               "gcKFuFFLyNOhPZo6REeJC7o2+9d7Mwys8wVNTuS3D3o1h49QpYYNjYlgNSZ85pU=\n" \
               "=DBkI\n" \
               "-----END PGP PRIVATE KEY BLOCK-----\n"

    msg = "-----BEGIN PGP MESSAGE-----\n" \
          "Version: PGPy v0.4.2\n" \
          "\n" \
          "xA0DAAIBPpLc6ocmOSwAwUwDDYjwqQ5XOH8BAfwOTH6C/lk5bQevArYnrf0q3Dde\n" \
          "JDjM/otBckiTS8kvFz1XFfQhIDkZl+fDcRwDFNe9+JKLqOM4jU6FIUwToYgz0ksB\n" \
          "f6iZ80U0dzHGtvmEzYSnsYWAglik0ch/E9tyNq/lryrLnrxWu7V26wPfI1TISuKd\n" \
          "U+w1HPGoH8ugo6GkeqBdeED6gJfKEm1qgrHCXAQAAQIABgUCWUrVMQAKCRA+ktzq\n" \
          "hyY5LLcHAgDHYjKVbpd5/FV4+CZ0H5yTnrD/vZ+QebDC7CmOM7f1Q5L1AdG/K1rr\n" \
          "+Ud/YHq3NVk5UGU0LDfjdBwVaJmOjEUx\n" \
          "=ITfp\n" \
          "-----END PGP MESSAGE-----\n"

    dkey, _ = PGPKey.from_blob(decrypt_key)
    skey, _ = PGPKey.from_blob(sign_key)
    encmsg = PGPMessage.from_blob(msg)

    # this should work
    decmsg = dkey.decrypt(encmsg)
    assert decmsg.message == "Regression Test for PR#183"

    # this should raise PGPError, not PGPDecryptionError
    with pytest.raises(PGPError):
        skey.decrypt(encmsg)


@pytest.mark.regression(194)
def test_pubkey_subkey_parent():
    from pgpy import PGPKey

    # import this small key that has a subkey
    keyblob = ('-----BEGIN PGP PRIVATE KEY BLOCK-----\n'
               'Version: PGPy v0.4.2\n'
               '\n'
               'xcA4BFlULU4BAgDeq2bKPPOBzdgd1WF3RBQ0E0kkZbTfpgZjamDzdb6gfQ5TcBhs\n'
               'drI4XpxWOV3DorbsZ8Usj4zHx/XmLNCmxwqvABEBAAEAAgCSO76l0qGY/baQ4THB\n'
               'QdSC3qeKX8EJn99SKurA+PLYMg6IxLGBpWYIK8tT68xpqQ5ZwE9GodZ2QjfOVz2R\n'
               'o4IBAQD/UjtthEtyiMA1CDCPEksfIyd0QDjt82C19MSeqau8WQEA30LydxkjlvgH\n'
               'u5/uWVGqoFWhhfw5hDrYy72L6EbCfkcA/2csk7uGw/yg2MDUTlDwdokn1DLGkt/+\n'
               'Q/fPAMYvX6gvVoXNFVJlZ3Jlc3NvIChJc3N1ZSAjMTk0KcJrBBMBAgAVBQJZVC3O\n'
               'AhsDAgsHAhUCAhYAAh4BAAoJEC4sMTkKIj+F8ywB/AqaNHwi8xM1Rg99mOSib1zi\n'
               'jlXALY8pOrNU7Nqtc/6oks+49WeVW5zpE1vl1JPm2WYzvCEnE1KffdyjNR0bQ1XH\n'
               'wDgEWVQtUQECAKsWCdSRh6YDP9yuSonfHpBfUzRD/EQvpNnUDiTclV9w6RPMZYk9\n'
               'o5oUQTumPKnznsovLpNmIm48DCALMzdTzH0AEQEAAQACAJDfsKNYOM3Toph03pmx\n'
               'XmhS0FpJ16zFy4rJjtCYGcUerUqRQ1ehXIY9Ig9J5LitJXThrP4dvUlRCWUcxxl6\n'
               '9eEBANOiM8ktXW0bPZfBKunWn7ajA0PMBKG8p2d9iBCawBbbAQDO88L8V0cxCRvH\n'
               '8L1J4gsttPWDOnhw5z8Dq4Zv5U3thwD/WwE0miqfEpYAmkhc0g7lHf6l7qo+SrUZ\n'
               'ZKl0GLPLKKFRscK9BBgBAgAJBQJZVC3mAhsMAGgJEC4sMTkKIj+FXSAEGQECAAYF\n'
               'AllULeYACgkQCK0qxtsEtqzY7QIAoayZGB78eaImQVOpTLX2jnaDR2UY7NtUy6YI\n'
               'XMSumCeZj+n+BexmUm6x2kqg0FJLRwAE4i+rnvFA0HHX40/9d221AgCzUxHuHjKP\n'
               'b5wNW20vanc6b6ZMi52MyhluXAIdnvgPkPEzVIS+gGOX2DeT4TXAdosKfD1o5qS7\n'
               'ANRbocmpDuO3\n'
               '=UjzO\n'
               '-----END PGP PRIVATE KEY BLOCK-----\n')

    privkey, _ = PGPKey.from_blob(keyblob)
    pubkey = privkey.pubkey

    assert pubkey.subkeys['08AD2AC6DB04B6AC'].parent is pubkey


cleartext_sigs = ['tests/testdata/messages/cleartext.oneline.signed.asc',
                  'tests/testdata/messages/cleartext.empty.signed.asc']
cleartexts = ['This is stored, literally\!',
              '']


@pytest.mark.regression(issue=192)
@pytest.mark.parametrize('sf,cleartext', zip(cleartext_sigs, cleartexts), ids=[os.path.basename(f) for f in cleartext_sigs])
def test_oneline_cleartext(sf, cleartext):
    with open(sf) as of:
        oc = of.read()

    dearmor = Armorable.ascii_unarmor(oc)
    # It is a signature
    assert dearmor['magic'] == 'SIGNATURE'
    # No newline at the end
    assert dearmor['cleartext'] == cleartext
