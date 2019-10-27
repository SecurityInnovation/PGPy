#!/usr/bin/python3
# PYTHON_ARGCOMPLETE_OK
'''OpenPGP Interoperability Test Suite Generic Functionality using PGPy

Author: Daniel Kahn Gillmor
Date: 2019-10-24
License: MIT (see below)

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation files
(the "Software"), to deal in the Software without restriction,
including without limitation the rights to use, copy, modify, merge,
publish, distribute, sublicense, and/or sell copies of the Software,
and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
'''

import io
import os
import sop
import pgpy
import codecs
import logging

from typing import List, Union, Optional, Set, Tuple

class SOPGPy(sop.StatelessOpenPGP):
    def __init__(self):
        super().__init__(prog='SOPGPy', version=pgpy.__version__,
                         description=f'Stateless OpenPGP using PGPy {pgpy.__version__}')

    # implemented ciphers, in the order we prefer them:
    _cipherprefs = [pgpy.constants.SymmetricKeyAlgorithm.AES256,
                    pgpy.constants.SymmetricKeyAlgorithm.AES192,
                    pgpy.constants.SymmetricKeyAlgorithm.AES128,
                    pgpy.constants.SymmetricKeyAlgorithm.Camellia256,
                    pgpy.constants.SymmetricKeyAlgorithm.Camellia192,
                    pgpy.constants.SymmetricKeyAlgorithm.Camellia128,
                    pgpy.constants.SymmetricKeyAlgorithm.CAST5,
                    pgpy.constants.SymmetricKeyAlgorithm.TripleDES,
                    pgpy.constants.SymmetricKeyAlgorithm.Blowfish,
                    pgpy.constants.SymmetricKeyAlgorithm.IDEA]

        
    def _maybe_armor(self, armor:bool, data:Union[pgpy.PGPSignature,pgpy.PGPMessage,pgpy.PGPKey]):
        if (armor):
            return str(data).encode('ascii')
        else:
            return bytes(data)

    def _get_session_key(self, fname:str) -> Tuple[pgpy.constants.SymmetricKeyAlgorithm,Optional[bytes]]:
        data:str = ''
        if fname.startswith('@FD:'):
            fd = int(fname.split(':', maxsplit=1)[1])
            with open(fd, 'r') as filed:
                data = filed.read()
        elif fname.startswith('@ENV:'):
            data = os.environ[fname.split(':', maxsplit=1)[1]]
        else:
            with open(fname, 'r') as f:
                data = f.read()
        data = data.strip()
        algostr, keystr = data.split(':', maxsplit=2)
        algo:pgpy.constants.SymmetricKeyAlgorithm = pgpy.constants.SymmetricKeyAlgorithm(int(algostr))
        key:Optional[bytes] = None
        if keystr != '':
            key = codecs.decode(keystr, 'hex')
            if len(key) * 8 != algo.key_size:
                raise sop.SOPInvalidDataType(f'session key {fname} has wrong size ({len(key)*8} bits) for cipher {algo} (expected: {algo.key_size} bits)')
        return algo, key

    def _get_pgp_signature(self, fname:str) -> pgpy.PGPSignature:
        sig:Optional[pgpy.PGPSignature] = None
        if fname.startswith('@FD:'):
            fd = int(fname.split(':', maxsplit=1)[1])
            with open(fd, 'rb') as filed:
                data:bytes = filed.read()
                sig = pgpy.PGPSignature.from_blob(data)
        elif fname.startswith('@ENV:'):
            sig = pgpy.PGPSignature.from_blob(os.environ[fname.split(':', maxsplit=1)[1]])
        else:
            sig = pgpy.PGPSignature.from_file(fname)
        return sig
        
    def _get_pgp_key(self, fname:str, secret:bool) -> pgpy.PGPKey:
        # handle @FD: and @ENV: here
        key:Optional[pgpy.PGPKey] = None
        if fname.startswith('@FD:'):
            fd = int(fname.split(':', maxsplit=1)[1])
            with open(fd, 'rb') as filed:
                data:bytes = filed.read()
                key, _ = pgpy.PGPKey.from_blob(data)
        elif fname.startswith('@ENV:'):
            key, _ = pgpy.PGPKey.from_blob(os.environ[fname.split(':', maxsplit=1)[1]])
        else:
            key, _ = pgpy.PGPKey.from_file(fname)
        if secret:
            if key.is_public:
                raise Exception(f'file "{fname}" does not contain OpenPGP secret key material (probably a certificate)')
            logging.info(f'loaded secret key {key.fingerprint} from {fname}')

        if not secret:
            if not key.is_public:
                raise Exception(f'file "{fname}" does not contain an OpenPGP certificate (probably a secret key)')
            logging.info(f'loaded certificate {key.fingerprint} from {fname}')
        return key
        
    def generate(self,
                 inp:io.BufferedReader,
                 armor:bool,
                 uids:List[str]) -> bytes:
        primary = pgpy.PGPKey.new(pgpy.constants.PubKeyAlgorithm.EdDSA,
                                  pgpy.constants.EllipticCurveOID.Ed25519)
        primaryflags: Set[int] = set()
        primaryflags.add(pgpy.constants.KeyFlags.Certify)
        primaryflags.add(pgpy.constants.KeyFlags.Sign)
        first: bool = True
        uidoptions = {
            'usage': primaryflags,
            'primary': True,
            'hashes': [pgpy.constants.HashAlgorithm.SHA512,
                       pgpy.constants.HashAlgorithm.SHA384,
                       pgpy.constants.HashAlgorithm.SHA256,
                       pgpy.constants.HashAlgorithm.SHA224],
            'ciphers': [pgpy.constants.SymmetricKeyAlgorithm.AES256,
                        pgpy.constants.SymmetricKeyAlgorithm.AES192,
                        pgpy.constants.SymmetricKeyAlgorithm.AES128],
            'compression': [pgpy.constants.CompressionAlgorithm.Uncompressed],
            'keyserver_flags': [pgpy.constants.KeyServerPreferences.NoModify]
        }

        for uid in uids:
            primary.add_uid(pgpy.PGPUID.new(uid), **uidoptions)
            if 'primary' in uidoptions: # only first User ID is Primary
                del uidoptions['primary']

        subkey = pgpy.PGPKey.new(pgpy.constants.PubKeyAlgorithm.ECDH,
                                 pgpy.constants.EllipticCurveOID.Curve25519)
        subflags: Set[int] = set()
        subflags.add(pgpy.constants.KeyFlags.EncryptCommunications)
        subflags.add(pgpy.constants.KeyFlags.EncryptStorage)
        primary.add_subkey(subkey, usage=subflags)
        return self._maybe_armor(armor, primary)


    def convert(self,
                inp:io.BufferedReader,
                armor:bool) -> bytes:
        data: bytes = inp.read()
        seckey, _ = pgpy.PGPKey.from_blob(data)
        return self._maybe_armor(armor, seckey.pubkey)


    def sign(self,
             inp:io.BufferedReader,
             armor:bool,
             sigtype:str,
             signers:List[str]) -> bytes:
        if not signers:
            raise Exception("Need at least one OpenPGP Secret Key file as an argument")

        seckeys = []
        for keyfile in signers:
            seckey = self._get_pgp_key(keyfile, True)
            seckeys.append(seckey)

        data:bytes = inp.read()
        msg:Optional[pgpy.PGPMessage] = None
        if sigtype == 'text':
            msg = pgpy.PGPMessage.new(data.decode('utf8'), cleartext=True, format='u')
        elif sigtype == 'binary':
            msg = pgpy.PGPMessage.new(data, format='b')
        else:
            raise Exception(f'unknown signature type {sigtype}')
        signatures:List[pgpy.PGPSignature] = []
        for seckey in seckeys:
            signatures.append(seckey.sign(msg))

        # hack to assemble multiple signature packets! FIXME: need to report to PGPy
        sigdata:bytes = b''
        for signature in signatures:
            sigdata += bytes(seckey.sign(msg))
        class _multisig(pgpy.types.Armorable):
            @property
            def magic(self):
                return 'SIGNATURE'
            def parse(self, x):
                self._bytes = x
            def __bytes__(self):
                return self._bytes
        return self._maybe_armor(armor, _multisig.from_blob(sigdata))


    def verify(self,
               inp:io.BufferedReader,
               start:Optional[str],
               end:Optional[str],
               sig:str,
               signers:List[str]) -> bytes:
        signature = self._get_pgp_signature(sig)
        certs: List[pgpy.PGPKey] = []
        for fname in signers:
            cert = self._get_pgp_key(fname, False)
            certs.append(cert)

        if not certs:
            raise Exception('needs at least one OpenPGP certificate')

        if start is not None or end is not None:
            raise Exception('have not implemented --not-before and --not-after')
        
        data:bytes = inp.read()
        good:bool = False
        ret:bytes = b''
        for cert in certs:
            try:
                verif = cert.verify(data, signature=signature)
                for sig in verif.good_signatures:
                    if sig.verified:
                        ts = sig.signature.created.strftime('%Y-%m-%dT%H:%M:%SZ\n')
                        good = True
                        ret += ts.encode('ascii')
            except:
                pass
        if not good:
            raise Exception("No good signature found")
        return ret


    def encrypt(self,
                inp:io.BufferedReader,
                literaltype:str,
                armor:bool,
                mode:str,
                passwords:List[str],
                sessionkey:Optional[str],
                signers:List[str],
                recipients:List[str]) -> bytes:
        # FIXME!
        if literaltype != 'binary':
            raise sop.SOPUnsupportedOption('sopgpy encrypt does not support --as yet')
        if mode != 'any':
            raise sop.SOPUnsupportedOption('sopgpy encrypt does not support --mode yet')
        if passwords:
            raise sop.SOPUnsupportedOption('sopgpy encrypt does not support --with-password yet')
        if signers:
            raise sop.SOPUnsupportedOption('sopgpy encrypt does not support --sign-with yet')
        
        certs: List[pgpy.PGPKey] = []
        for fname in recipients:
            cert = self._get_pgp_key(fname, False)
            certs.append(cert)

        if not certs:
            raise Exception('needs at least one OpenPGP certificate')

        cipher:Optional[pgpy.constants.SymmetricKeyAlgorithm] = None
        symmetrickey:Optional[bytes] = None

        if sessionkey:
            (cipher, symmetrickey) = self._get_session_key(sessionkey)
            del sessionkey
        else:
            ciphers = set(self._cipherprefs)
            for cert in certs:
                keyciphers=set()
                for uid in cert.userids:
                    if uid.selfsig and uid.selfsig.cipherprefs:
                        for cipher in uid.selfsig.cipherprefs:
                            keyciphers.add(cipher)
                ciphers = ciphers.intersection(keyciphers)
            for c in self._cipherprefs:
                if c in ciphers:
                    cipher = c
                    break
        # AES128 is MTI in RFC4880:
        if cipher is None:
            cipher = pgpy.constants.SymmetricKeyAlgorithm.AES128
        if symmetrickey is None:
            symmetrickey = cipher.gen_key()

        data: bytes = inp.read()
        msg = pgpy.PGPMessage.new(data, compression=pgpy.constants.CompressionAlgorithm.Uncompressed)
        for cert in certs:
            msg = cert.encrypt(msg, cipher=cipher, sessionkey=symmetrickey)
        del symmetrickey
        return self._maybe_armor(armor, msg)


    def decrypt(self,
                inp:io.BufferedReader,
                sessionkey:Optional[str],
                passwords:List[str],
                verifications:Optional[str],
                signers:List[str],
                start:Optional[str],
                end:Optional[str],
                secretkeys:List[str]) -> bytes:
        # FIXME!!!
        if sessionkey:
            raise sop.SOPUnsupportedOption('sopgpy does not support --session-key yet')
        if passwords: 
            raise sop.SOPUnsupportedOption('sopgpy does not support --with-password yet')
        if verifications:
            raise sop.SOPUnsupportedOption('sopgpy does not support --verify-out yet')
        if signers:
            raise sop.SOPUnsupportedOption('sopgpy does not support --verify-with yet')
        if start or end:
            raise sop.SOPUnsupportedOption('sopgpy does not support --verify-not-before or --verify-not-after yet')
        
        seckeys: List[pgpy.PGPKey] = []
        for fname in secretkeys:
            seckey = self._get_pgp_key(fname, True)
            seckeys.append(seckey)

        if not seckeys:
            raise Exception('needs at least one OpenPGP secret key')
        data: bytes = inp.read()
        encmsg:pgpy.PGPMessage = pgpy.PGPMessage.from_blob(data)
        ret:Optional[bytes] = None
        for seckey in seckeys:
            try:
                msg: pgpy.PGPMessage = seckey.decrypt(encmsg)
                out:Union[str,bytes] = msg.message
                if isinstance(out, str):
                    ret = out.encode('utf8')
                else:
                    ret = out
                break
            except pgpy.errors.PGPDecryptionError as e:
                logging.warning(f'could not decrypt with {seckey.fingerprint}')
        if ret is None:
            raise Exception(f'could not find anything capable of decryption')
        return ret

    def armor(self,
              inp:io.BufferedReader,
              label:Optional[str]) -> bytes:
        data:bytes = inp.read()
        obj:Union[None,pgpy.PGPMessage,pgpy.PGPKey,pgpy.PGPSignature] = None
        try:
            if label == 'message':
                obj = pgpy.PGPMessage.from_blob(data)
            elif label == 'key':
                obj, _ = pgpy.PGPKey.from_blob(data)
                if obj.is_public or not obj.is_primary:
                    raise sop.SOPInvalidDataType('not an OpenPGP secret key')
            elif label == 'cert':
                obj, _ = pgpy.PGPKey.from_blob(data)
                if not obj.is_public:
                    raise sop.SOPInvalidDataType('not an OpenPGP certificate')
            elif label == 'sig':
                obj = pgpy.PGPSignature.from_blob(data)
            elif label is None: # try to guess
                try:
                    obj, _ = pgpy.PGPKey.from_blob(data)
                except:
                    try:
                        obj = pgpy.PGPSignature.from_blob(data)
                    except:
                        try:
                            obj = pgpy.PGPMessage.from_blob(data)
                        except:
                            obj = pgpy.PGPMessage.new(data)
            else:
                raise sop.SOPInvalidDataType(f'unknown armor type {label}')
        except (ValueError,TypeError) as e:
            raise sop.SOPInvalidDataType(f'{e}')
        return str(obj).encode('ascii')

    def dearmor(self,
                inp:io.BufferedReader) -> bytes:
        data:bytes = inp.read()
        try:
            key, _ = pgpy.PGPKey.from_blob(data)
            return bytes(key)
        except:
            pass
        for cls in [ pgpy.PGPSignature, pgpy.PGPMessage ]:
            try:
                obj:cls = cls.from_blob(data)
                return bytes(obj)
            except:
                pass
        raise sop.SOPInvalidDataType()
        
def main():
    sop = SOPGPy()
    sop.dispatch()

if __name__ == '__main__':
    main()
