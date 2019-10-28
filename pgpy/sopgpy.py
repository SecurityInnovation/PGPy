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
import pgpy #type: ignore
import codecs
import logging

from datetime import datetime
from typing import List, Union, Optional, Set, Tuple, MutableMapping, Dict

__version__ = '0.1.0'

class SOPGPy(sop.StatelessOpenPGP):
    def __init__(self) -> None:
        super().__init__(name='SOPGPy', version=f'{__version__}/{pgpy.__version__}',
                         description=f'Stateless OpenPGP using PGPy {pgpy.__version__}')

    # implemented ciphers that we are willing to use to encrypt, in
    # the order we prefer them:
    _cipherprefs:List[pgpy.constants.SymmetricKeyAlgorithm] = \
        [pgpy.constants.SymmetricKeyAlgorithm.AES256,
         pgpy.constants.SymmetricKeyAlgorithm.AES192,
         pgpy.constants.SymmetricKeyAlgorithm.AES128,
         pgpy.constants.SymmetricKeyAlgorithm.Camellia256,
         pgpy.constants.SymmetricKeyAlgorithm.Camellia192,
         pgpy.constants.SymmetricKeyAlgorithm.Camellia128,
         pgpy.constants.SymmetricKeyAlgorithm.CAST5,
         pgpy.constants.SymmetricKeyAlgorithm.TripleDES,
         pgpy.constants.SymmetricKeyAlgorithm.Blowfish]
        
    def _maybe_armor(self, armor:bool, data:Union[pgpy.PGPSignature,pgpy.PGPMessage,pgpy.PGPKey]) -> bytes:
        if (armor):
            return str(data).encode('ascii')
        else:
            return bytes(data)

    def _get_pgp_signature(self, data:bytes) -> Optional[pgpy.PGPSignature]:
        sig:Optional[pgpy.PGPSignature] = None
        sig = pgpy.PGPSignature.from_blob(data)
        return sig

    def _get_certs(self, vals:MutableMapping[str,bytes]) -> MutableMapping[str,pgpy.PGPKey]:
        certs:Dict[str,pgpy.PGPKey] = {}
        for handle, data in vals.items():
            cert:pgpy.PGPKey
            cert, _ = pgpy.PGPKey.from_blob(data)
            if not cert.is_public:
                raise sop.SOPInvalidDataType('cert {handle} is not an OpenPGP certificate (maybe secret key?)')
            certs[handle] = cert
        return certs

    def _get_keys(self, vals:MutableMapping[str,bytes]) -> MutableMapping[str,pgpy.PGPKey]:
        keys:Dict[str,pgpy.PGPKey] = {}
        for handle, data in vals.items():
            key:pgpy.PGPKey
            key, _  = pgpy.PGPKey.from_blob(data)
            if key.is_public:
                raise sop.SOPInvalidDataType('cert {handle} is not an OpenPGP transferable secret key (maybe certificate?)')
            keys[handle] = key
        return keys
    
    def generate(self, armor:bool, uids:List[str]) -> bytes:
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
                key:bytes,
                armor:bool) -> bytes:
        seckey, _ = pgpy.PGPKey.from_blob(key)
        return self._maybe_armor(armor, seckey.pubkey)


    def sign(self,
             data:bytes,
             armor:bool,
             sigtype:sop.SOPSigType,
             signers:MutableMapping[str, bytes]) -> bytes:
        if not signers:
            raise sop.SOPMissingRequiredArgument("Need at least one OpenPGP Secret Key file as an argument")
        seckeys:MutableMapping[str,pgpy.PGPKey] = self._get_keys(signers)
        msg:pgpy.PGPMessage
        if sigtype is sop.SOPSigType.text:
            msg = pgpy.PGPMessage.new(data.decode('utf8'), cleartext=True, format='u')
        elif sigtype == sop.SOPSigType.binary:
            msg = pgpy.PGPMessage.new(data, format='b')
        else:
            raise sop.SOPUnsupportedOption(f'unknown signature type {sigtype}')
        signatures:List[pgpy.PGPSignature] = []
        for handle,seckey in seckeys.items():
            signatures.append(seckey.sign(msg))

        # hack to assemble multiple signature packets! FIXME: need to report to PGPy
        sigdata:bytes = b''
        for signature in signatures:
            sigdata += bytes(seckey.sign(msg))
        class _multisig(pgpy.types.Armorable): #type: ignore
            @property
            def magic(self) -> str:
                return 'SIGNATURE'
            def parse(self, x:bytes) -> None:
                self._bytes:bytes = x
            def __bytes__(self) -> bytes:
                return self._bytes
        return self._maybe_armor(armor, _multisig.from_blob(sigdata))


    def verify(self,
               data:bytes,
               start:Optional[datetime],
               end:Optional[datetime],
               sig:bytes,
               signers:MutableMapping[str,bytes]) -> List[sop.SOPSigResult]:
        if not signers:
            raise sop.SOPMissingRequiredArgument('needs at least one OpenPGP certificate')
        signature = self._get_pgp_signature(sig)
        certs:MutableMapping[str,pgpy.PGPKey] = self._get_certs(signers)
        if start is not None or end is not None:
            raise sop.SOPUnsupportedOption('have not implemented --not-before and --not-after')
        
        ret:List[sop.SOPSigResult] = []
        for (handle,cert) in certs.items():
            try:
                verif:pgpy.types.SignatureVerification = cert.verify(data, signature=signature)
                goodsig:pgpy.types.sigsubj
                for goodsig in verif.good_signatures:
                    if goodsig.verified:
                        ret += [sop.SOPSigResult(goodsig.signature.created, cert.fingerprint, goodsig.signature.__repr__())]
            except:
                pass
        if not ret:
            raise sop.SOPNoSignature("No good signature found")
        return ret


    def encrypt(self,
                data:bytes,
                literaltype:sop.SOPLiteralDataType,
                armor:bool,
                mode:sop.SOPEncryptMode,
                passwords:MutableMapping[str,bytes],
                sessionkey:Optional[sop.SOPSessionKey],
                signers:MutableMapping[str,bytes],
                recipients:MutableMapping[str,bytes]) -> bytes:
        handle:str
        # FIXME!
        if literaltype is not sop.SOPLiteralDataType.binary:
            raise sop.SOPUnsupportedOption('sopgpy encrypt does not support --as yet')
        if mode is not sop.SOPEncryptMode.any:
            raise sop.SOPUnsupportedOption('sopgpy encrypt does not support --mode yet')
        if passwords:
            raise sop.SOPUnsupportedOption('sopgpy encrypt does not support --with-password yet')
        if signers:
            raise sop.SOPUnsupportedOption('sopgpy encrypt does not support --sign-with yet')

        if not recipients and not passwords:
            raise sop.SOPMissingRequiredArgument('needs at least one OpenPGP certificate or password to encrypt to')

        certs:MutableMapping[str,pgpy.PGPKey] = self._get_certs(recipients)


        cipher:Optional[pgpy.constants.SymmetricKeyAlgorithm] = None
        symmetrickey:Optional[bytes] = None

        if sessionkey:
            cipher = pgpy.constants.SymmetricKeyAlgorithm(sessionkey.algo)
            symmetrickey = sessionkey.key
            del sessionkey
        else:
            ciphers = set(self._cipherprefs)
            for handle, cert in certs.items():
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

        msg = pgpy.PGPMessage.new(data, compression=pgpy.constants.CompressionAlgorithm.Uncompressed)
        for handle, cert in certs.items():
            msg = cert.encrypt(msg, cipher=cipher, sessionkey=symmetrickey)
        del symmetrickey
        return self._maybe_armor(armor, msg)


    def decrypt(self,
                data:bytes,
                wantsessionkey:bool,
                passwords:MutableMapping[str,bytes],
                signers:MutableMapping[str,bytes],
                start:Optional[datetime],
                end:Optional[datetime],
                secretkeys:MutableMapping[str,bytes]) -> Tuple[bytes, List[sop.SOPSigResult], Optional[sop.SOPSessionKey]]:
        # FIXME!!!
        if wantsessionkey:
            raise sop.SOPUnsupportedOption('sopgpy does not support --session-key-out yet')
        if passwords: 
            raise sop.SOPUnsupportedOption('sopgpy does not support --with-password yet')
        if signers:
            raise sop.SOPUnsupportedOption('sopgpy does not support --verify-with yet')
        if start or end:
            raise sop.SOPUnsupportedOption('sopgpy does not support --verify-not-before or --verify-not-after yet')
        
        if not secretkeys and not passwords:
            raise sop.SOPMissingRequiredArgument('needs at least one OpenPGP secret key')

        seckeys:MutableMapping[str,pgpy.PGPKey] = self._get_keys(secretkeys)

        encmsg:pgpy.PGPMessage = pgpy.PGPMessage.from_blob(data)
        ret:Optional[bytes] = None
        for handle,seckey in seckeys.items():
            try:
                msg:pgpy.PGPMessage = seckey.decrypt(encmsg)
                out:Union[str,bytes] = msg.message
                if isinstance(out, str):
                    ret = out.encode('utf8')
                else:
                    ret = out
                break
            except pgpy.errors.PGPDecryptionError as e:
                logging.warning(f'could not decrypt with {seckey.fingerprint}')
        if ret is None:
            raise sop.SOPCouldNotDecrypt(f'could not find anything capable of decryption')
        return (ret, [], None)

    def armor(self, data:bytes, label:Optional[sop.SOPArmorLabel]) -> bytes:
        obj:Union[None,pgpy.PGPMessage,pgpy.PGPKey,pgpy.PGPSignature] = None
        try:
            if label is sop.SOPArmorLabel.message:
                obj = pgpy.PGPMessage.from_blob(data)
            elif label is sop.SOPArmorLabel.key:
                obj, _ = pgpy.PGPKey.from_blob(data)
                if obj.is_public or not obj.is_primary:
                    raise sop.SOPInvalidDataType('not an OpenPGP secret key')
            elif label is sop.SOPArmorLabel.cert:
                obj, _ = pgpy.PGPKey.from_blob(data)
                if not obj.is_public:
                    raise sop.SOPInvalidDataType('not an OpenPGP certificate')
            elif label is sop.SOPArmorLabel.sig:
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

    def dearmor(self, data:bytes) -> bytes:
        try:
            key:pgpy.PGPKey
            key, _ = pgpy.PGPKey.from_blob(data)
            return bytes(key)
        except:
            pass
        try:
            sig:pgpy.PGPSignature = pgpy.PGPSignature.from_blob(data)
            return bytes(sig)
        except:
            pass
        try:
            msg:pgpy.PGPMessage = pgpy.PGPMessage.from_blob(data)
            return bytes(msg)
        except:
            pass
        raise sop.SOPInvalidDataType()
        
def main() -> None:
    sop = SOPGPy()
    sop.dispatch()

if __name__ == '__main__':
    main()
