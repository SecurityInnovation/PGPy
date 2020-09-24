""" I've got 99 problems but regression testing ain't one
"""
from conftest import gpg_ver, gnupghome

try:
    import gpg
except ImportError:
    gpg = None
import os
import datetime
import pytest
import glob
import warnings
from pgpy import PGPKey
from pgpy.types import Armorable


@pytest.mark.regression(issue=56)
def test_reg_bug_56():
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
    signature = sk.__key__.__privkey__().sign(hdata, padding.PKCS1v15(), hashes.SHA512())
    sig._signature.signature.from_signer(signature)
    sig._signature.update_hlen()

    # check encoding
    assert sig._signature.signature.md_mod_n.to_mpibytes()[2:3] != b'\x00'

    # with PGPy
    assert pk.verify(sigsubject, sig)

    if gpg:
        # with GnuPG
        with gpg.Context(armor=True, offline=True) as c:
            c.set_engine_info(gpg.constants.PROTOCOL_OpenPGP, home_dir=gnupghome)

            # import the key
            key_data = gpg.Data(string=pub)
            gpg.core.gpgme.gpgme_op_import(c.wrapped, key_data)

            _, vres = c.verify(gpg.Data(string=sigsubject.decode('latin-1')), gpg.Data(string=str(sig)))
            assert vres



# load mixed keys separately so they do not overwrite "single algo" keys in the _seckeys mapping
_seckeys = {sk.key_algorithm.name: sk for sk in (PGPKey.from_file(f)[0] for f in sorted(glob.glob('tests/testdata/keys/*.sec.asc')) if 'keys/mixed' not in f)}
_mixed1 = PGPKey.from_file('tests/testdata/keys/mixed.1.sec.asc')[0]
seckm = [
    _seckeys['DSA']._key,                                # DSA private key packet
    _seckeys['DSA'].subkeys['1FD6D5D4DA0170C4']._key,    # ElGamal private key packet
    _seckeys['RSAEncryptOrSign']._key,                   # RSA private key packet
    _seckeys['ECDSA']._key,                              # ECDSA private key packet
    _seckeys['ECDSA'].subkeys['A81B93FD16BD9806']._key,  # ECDH private key packet
    _seckeys['EdDSA']._key,                              # EdDSA private key packet
    _seckeys['EdDSA'].subkeys['AFC377493D8E897D']._key,  # Curve25519 private key packet
    _mixed1._key,                                        # RSA private key packet
    _mixed1.subkeys['B345506C90A428C5']._key,            # ECDH Curve25519 private key packet
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
cleartexts = [r'This is stored, literally\!',
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


@pytest.mark.regression(issue=199)
def test_armorable_empty_str():
    with pytest.raises(ValueError, match='Expected: ASCII-armored PGP data'):
        Armorable.ascii_unarmor('')


@pytest.mark.regression(issue=226)
def test_verify_subkey_revocation_signature():
    keyblob = ('-----BEGIN PGP PUBLIC KEY BLOCK-----\n'
               '\n'
               'mI0EWgtKbAEEAOEjq2UsapzI996tHhvGB7mJTo1sneUso20vz5VluECI0Xv0nr0j\n'
               'BfknMFNeuPRR5sopgnrYT2ezJxp60D1NFaKgDh0z0qv9spk9FTP4YtaE5pfZRk3l\n'
               'iGgyY7WiJBhKLb7ne3PeG8mtju4T+9ejbN4hVx1Vz9WHKkLGeBGkOcYZABEBAAG0\n'
               'HVRlc3QgUmV2b2NhdGlvbiA8YWJjQGRlZi5naGk+iM4EEwEIADgWIQRIuXHQYB9/\n'
               'm0hHY/8zq5Y87Iwq4QUCWgtKbAIbAwULCQgHAgYVCAkKCwIEFgIDAQIeAQIXgAAK\n'
               'CRAzq5Y87Iwq4RKuA/46Zg3OSmRPJJNQegoDGLGwj81sgrLFPVDV2dSAxYPiGH3j\n'
               'JNM760NS51FLHQvxwa9XV9/4xzL9jqsV8vD+lX5aphZS6h2olPAy9CP2FK8KFrv1\n'
               'Rap2y9D68LStDv2jFyEYEGCCvon3Ff6O2PxwG98xkaskBPH6knGjK6rrMvYI/7iN\n'
               'BFoLSmwBBACbGvXVtDH4aTJ3UbN/3UnLKb05ogmZDpkx8A2qGnUu1QvIxqi56emU\n'
               'TfbxKv8jne0qas0IJ1OWrcTAuPvwgH4TJERAkngxzdYXR6ZHEO3/L8s0XSLobW5E\n'
               'nsGnFw/PG5Lrxv1YA7nBlCKennrlaU9iiUguOUK7SW7To1SOojTOcQARAQABiLYE\n'
               'KAEIACAWIQRIuXHQYB9/m0hHY/8zq5Y87Iwq4QUCWgtKuAIdAwAKCRAzq5Y87Iwq\n'
               '4eFnA/4oOnM7kjgIYqs2TgAxuddMabx1US9yYZDG097Nxfw1DFJoFOg4ozrrWNRz\n'
               'F3AHo7Ocue288VYIJtjH4KB2vGAYdWq8j6bywW7t4Be2WsU4MCJqETxS+3Gv65B6\n'
               'NBq4Y8lJvKO/cwsqYI6XWsJsmnVns0XOdv/k6ZouVdpUu5Fpr4i2BBgBCAAgFiEE\n'
               'SLlx0GAff5tIR2P/M6uWPOyMKuEFAloLSmwCGwwACgkQM6uWPOyMKuFrOAP/ZemA\n'
               'yfU6zSfiReQ5fsiQhiy2jZx+JVweZ0ESgDuIvT4tlB4WK87OcITd40rTalGezRuE\n'
               'fhi3IcnDc7L+kBGNhP3IY8IFVNYGqfowIYLl/RX+3BUjuaDpunO9kIBrhm0WrC6Y\n'
               '+padVqwTFNFteQR0N9BW1qNf7HB20BCaElxGCuI=\n'
               '=EoFv\n'
               '-----END PGP PUBLIC KEY BLOCK-----\n')

    pubkey, _ = PGPKey.from_blob(keyblob)
    subkey = pubkey.subkeys['8ABD4FB3046BBCF8']

    revsig = subkey._signatures[1]

    assert pubkey.verify(subkey, revsig)

@pytest.mark.regression(issue=243)
def test_preference_unsupported_ciphers():
    from pgpy import PGPMessage
    keyblob = ('-----BEGIN PGP PUBLIC KEY BLOCK-----\n'
               '\n'
               'mQENBFtKbSQBCADDMwreTvJkDQkgB+n0GsNbMFKEjPYGKP365y5w+FlJ2zg69F3W\n'
               'ituYFQcTwuge2XSh58k/XHln+MwjNc5cDQaWLtMuyJbRvLK+8MdpdYlzrlyrsgDI\n'
               'L/1PAlGMVWB83Iu2kxqc0ppTxwsltAcvRJBE+9oSiWRACQviDmX5LeBmPoGqM93w\n'
               'LeN3QT/tu26rxha374HPgSqqNR13r3xl7gQre+pA3jmNQqwzPnEmUKN3hO852NAw\n'
               'QOPbf4yTCcbeZ6iZ/h0mW4DvbLiPbzUsXRvgTo3X/kzJD+ZnznvJvjcKrkXzaOAp\n'
               'qt6Nd1LmWyv5h7gBYgBNaQONFeMl9MVBFUflABEBAAG0GnRlc3RrZXkgPHRlc3RA\n'
               'ZXhhbXBsZS5jb20+iQFPBBMBCAA5AhsDAh4BAheAFiEEL7Bmz7+mS4Q3LDSMbIbe\n'
               'TttFc4wFAltKbXsFCwoJCAcGFQoJCAsCBRYCAwEAAAoJEGyG3k7bRXOMI34IAINL\n'
               'bYmZ95RgVX98+tjBAliV9xZaaxu4xpY8vz4pCwwFj9QBMxkzmITC1yb/Vav6pLFK\n'
               'UISLGeOUqskVg9uQn8YGSnRaKoxetL894o0jGLyQF6ujF4OFhbfRlaLbNACDQqg0\n'
               'bzV1E+s6RsnbwR7aFlOcgz5m/j7+c9t/BnZ4qOYBW85iLyzQA4BgTBSocdyom3EA\n'
               'osCNY4tFuySFlOF34OLu1k8y9RP0KsJJptEdIwEqSxRKuQ5KTbopx9kvxVfOOwgy\n'
               'RVYuP/OQrc/MQPGSC0Rmh/iCNEsTOIxcwnotmyRd8qDpw/EBj1a0iWxzPYOzXoEQ\n'
               'Ff2ipWRkzS3AyWVJJxi5AQ0EW0ptJAEIAJXwfVD+3oSLPedMBvpfnveu/LjFvxJk\n'
               'ohawApu63JzJNXoRpjeBhox073iEjeSbvq/pJ/+y0t6KkFZXoXgpqACGDNjPpojk\n'
               '6YTo6Da7GpyXefhKyH4IQ9Lbd9UIEhOKfktXTJfR/EoCZb+rmTm0WnjwkwOAVdQv\n'
               'vuMRm8Hc39xn+Mt0CV+0KcYHhNfK+A2XU6bZkHuwaTzxTaotmeLeCgC+BA2Phwxp\n'
               'BIhkSNE8ayYLN0VBPraw28xONzNV5e6f8RWNoGTDQxhZflmvIGz/XO5wo1DV1G0k\n'
               'VIR49brAmrapqpCW7XWhuuupVbrpbjRUa+c4G03tySXQXUTdA3etH0EAEQEAAYkB\n'
               'NgQYAQgAIBYhBC+wZs+/pkuENyw0jGyG3k7bRXOMBQJbSm0kAhsMAAoJEGyG3k7b\n'
               'RXOMKbMIAKymk6Fe1qpjXtK56jpMurz1wBL0/twQbvtKQlgMBNdro0MX30xKGXh1\n'
               'rCEIV3ls7CJnUm2NEeqFPzFZhsZS2FkgDXXT20K3S6nscv8xlF2z+jktK2RY6oCJ\n'
               'Lgw447Rgjw5ARgW2XNrGRzapAf4KBgcyO1KtTCbjh8leg4Fs1O7B8EbiBvoeUJR0\n'
               'wj2xNG4cOHoWN7Zjv8lLsJn60+ZbTeU25ghybmt7WjCs4ht7TZmamerLPzrFvP2c\n'
               'ftLsb17HhrBPdfs42SsD8A816JDM7PcJWujlDV9FPJgoVjndK+4Jfpg9b4jOBA7J\n'
               '7zeGuobtKdS9Y97BVFNtTPZK66YUIEQ=\n'
               '=lGIy\n'
               '-----END PGP PUBLIC KEY BLOCK-----\n')
    pubkey, _ = PGPKey.from_blob(keyblob)
    msg = PGPMessage.new('asdf')
    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        pubkey.encrypt(msg)

@pytest.mark.regression(issue=291)
def test_sig_timezone():
    from pgpy import PGPKey, PGPSignature
    # from https://tools.ietf.org/html/draft-bre-openpgp-samples-00#section-2.2:
    alice_sec = '''-----BEGIN PGP PRIVATE KEY BLOCK-----
Comment: Alice's OpenPGP Transferable Secret Key

lFgEXEcE6RYJKwYBBAHaRw8BAQdArjWwk3FAqyiFbFBKT4TzXcVBqPTB3gmzlC/U
b7O1u10AAP9XBeW6lzGOLx7zHH9AsUDUTb2pggYGMzd0P3ulJ2AfvQ4RtCZBbGlj
ZSBMb3ZlbGFjZSA8YWxpY2VAb3BlbnBncC5leGFtcGxlPoiQBBMWCAA4AhsDBQsJ
CAcCBhUKCQgLAgQWAgMBAh4BAheAFiEE64W7X6M6deFelE5j8jFVDE9H444FAl2l
nzoACgkQ8jFVDE9H447pKwD6A5xwUqIDprBzrHfahrImaYEZzncqb25vkLV2arYf
a78A/R3AwtLQvjxwLDuzk4dUtUwvUYibL2sAHwj2kGaHnfICnF0EXEcE6RIKKwYB
BAGXVQEFAQEHQEL/BiGtq0k84Km1wqQw2DIikVYrQrMttN8d7BPfnr4iAwEIBwAA
/3/xFPG6U17rhTuq+07gmEvaFYKfxRB6sgAYiW6TMTpQEK6IeAQYFggAIBYhBOuF
u1+jOnXhXpROY/IxVQxPR+OOBQJcRwTpAhsMAAoJEPIxVQxPR+OOWdABAMUdSzpM
hzGs1O0RkWNQWbUzQ8nUOeD9wNbjE3zR+yfRAQDbYqvtWQKN4AQLTxVJN5X5AWyb
Pnn+We1aTBhaGa86AQ==
=n8OM
-----END PGP PRIVATE KEY BLOCK-----
'''

    alice_key, _ = PGPKey.from_blob(alice_sec)

    class FixedOffset(datetime.tzinfo):
        def __init__(self, hours, name):
            self.__offset = datetime.timedelta(hours=hours)
            self.__name = name
        def utcoffset(self, dt):
            return self.__offset
        def tzname(self, dt):
            return self.__name
        def dst(self, dt):
            return datetime.timedelta(0)
    # America/New_York during DST:
    tz = FixedOffset(-4, 'EDT')
    # 2019-10-20T09:18:11-0400
    when = datetime.datetime.fromtimestamp(1571577491, tz)

    pgpsig = alice_key.sign('this is a test', created=when)
    roundtrip = PGPSignature.from_blob(str(pgpsig))

    assert pgpsig.created.utctimetuple() == roundtrip.created.utctimetuple()


@pytest.mark.regression
def test_ops_order():
    from pgpy import PGPKey, PGPMessage

    # from https://tools.ietf.org/html/draft-bre-openpgp-samples-00#section-2.2:
    alice_sec = '''-----BEGIN PGP PRIVATE KEY BLOCK-----
Comment: Alice's OpenPGP Transferable Secret Key

lFgEXEcE6RYJKwYBBAHaRw8BAQdArjWwk3FAqyiFbFBKT4TzXcVBqPTB3gmzlC/U
b7O1u10AAP9XBeW6lzGOLx7zHH9AsUDUTb2pggYGMzd0P3ulJ2AfvQ4RtCZBbGlj
ZSBMb3ZlbGFjZSA8YWxpY2VAb3BlbnBncC5leGFtcGxlPoiQBBMWCAA4AhsDBQsJ
CAcCBhUKCQgLAgQWAgMBAh4BAheAFiEE64W7X6M6deFelE5j8jFVDE9H444FAl2l
nzoACgkQ8jFVDE9H447pKwD6A5xwUqIDprBzrHfahrImaYEZzncqb25vkLV2arYf
a78A/R3AwtLQvjxwLDuzk4dUtUwvUYibL2sAHwj2kGaHnfICnF0EXEcE6RIKKwYB
BAGXVQEFAQEHQEL/BiGtq0k84Km1wqQw2DIikVYrQrMttN8d7BPfnr4iAwEIBwAA
/3/xFPG6U17rhTuq+07gmEvaFYKfxRB6sgAYiW6TMTpQEK6IeAQYFggAIBYhBOuF
u1+jOnXhXpROY/IxVQxPR+OOBQJcRwTpAhsMAAoJEPIxVQxPR+OOWdABAMUdSzpM
hzGs1O0RkWNQWbUzQ8nUOeD9wNbjE3zR+yfRAQDbYqvtWQKN4AQLTxVJN5X5AWyb
Pnn+We1aTBhaGa86AQ==
=n8OM
-----END PGP PRIVATE KEY BLOCK-----
'''
    bob_sec = '''-----BEGIN PGP PRIVATE KEY BLOCK-----
Comment: Bob's OpenPGP Transferable Secret Key
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
=miES
-----END PGP PRIVATE KEY BLOCK-----
'''

    alice_key, _ = PGPKey.from_blob(alice_sec)
    bob_key, _ = PGPKey.from_blob(bob_sec)

    msg = PGPMessage.new('this is a test')
    sig1 = alice_key.sign(msg)
    sig2 = bob_key.sign(msg)
    msg |= sig1
    msg |= sig2

    it = iter(msg)
    assert sig2.signer == next(it).signer # OPS 1
    assert sig1.signer == next(it).signer # OPS 2
    next(it) # skip contents
    assert sig1 == next(it)
    assert sig2 == next(it)


@pytest.mark.regression(issue=341)
def test_spurious_dash_escapes():
    from pgpy import PGPKey, PGPMessage

    message_data = r'''-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA1,SHA256

- This is stored, literally\!

-----BEGIN PGP SIGNATURE-----
Version: GnuPG/MacGPG2 v2.0.20 (Darwin)

iJwEAQECAAYFAlQaCpEACgkQBM3VPIdAqKYrhwQAyQhwiqrR6oZ5fTBm4JyCOEND
72Kxbaz1i9Qh0jv7DmgRjb4udh95UQ8U0qVnmnhA8E2deKeDcWTS4fzUkU6J9OdH
/GPHpL9QEtOJ7xifzJsnKaNJVynmNMtYOqHQ9gCmXx7jM2ngxbTKBT8YZlSLMUdO
uoUFKrJGv0LWlSWHkeOJARwEAQECAAYFAlQaCpEACgkQKoNNjlkY6IYrhwf/ZnMN
yKIVxGl+5/9oovvgz2MtGt9B09xRg4BqD+lUDshzQUvQIjBXZ7ZEGSWqerRymZDg
ZzHpb1lv9oAOVU8f1qsMQJJkiz7Q+xu5FfgAp0WzMHJNy4QOmB4Kw/7UbTwdUXzw
EzKwbJ8Eg97vJgYdfqUZLu949dwJvyYZzGDdkbrnsaZ8H29XkKXNMlMinDQjvFBR
djgkILl3ZIdC3p+KechV3uYsqwje2qNEo69KukihPhzCe9o6/Yub5gdC+DSQDGl4
uPjk0zXjds4G5J5Jd5g4o7vhDWs8InxX4AcLfD6lH1XQ1VCZBpucun5CVsU3dUAv
yvO7C7FubDu1GUxdbYheBAERCAAGBQJUGgqRAAoJEKXc3JZkUxQOZ+IA/3KI8Mnl
k3jfpRQcvtSYFlU9WZk9SqZX6xirnV7Hloq6AP9ZlivPrJdWmjRyyShkMNgP/c63
cjMX82ahGPUVlyMP4A==
=bcSu
-----END PGP SIGNATURE-----
'''

    key = PGPKey.from_file('tests/testdata/keys/rsa.1.pub.asc')[0]
    message = PGPMessage.from_blob(message_data)
    assert key.verify(message)
