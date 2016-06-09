""" I've got 99 problems but regression testing ain't one
"""


def test_reg_bug_56(write_clean, gpg_import, gpg_verify):
    # some imports only used by this regression test
    import hashlib
    from datetime import datetime

    from pgpy.pgp import PGPKey
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
    with write_clean('tests/testdata/subj', 'w', sigsubject.decode('latin-1')), \
            write_clean('tests/testdata/subj.asc', 'w', str(sig)), \
            write_clean('tests/testdata/pub.asc', 'w', str(pk)), \
            gpg_import('pub.asc'):
        assert gpg_verify('subj', 'subj.asc')


def test_reg_bug_157(monkeypatch):
    # local imports for this
    import pgpy
    from time import time as rtime

    # to more easily replicate this bug, hash only 8 bytes instead of 100 KiB
    monkeypatch.setattr('pgpy.constants._hashtunedata', bytearray([10, 11, 12, 13, 14, 15, 16, 17]))
    # also monkeypatch time.time to return fewer significant digits
    monkeypatch.setattr('time.time', lambda: round(rtime(), 3))
    assert len(pgpy.constants._hashtunedata) == 8

    pgpy.constants.HashAlgorithm.SHA256.tune_count()
    assert pgpy.constants.HashAlgorithm.SHA256.tuned_count > 0