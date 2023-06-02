#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK
'''OpenPGP Interoperability Test Suite Generic Functionality using PGPy

Author: Daniel Kahn Gillmor
Date: 2023-06-01
License: 3-clause BSD, same as PGPy itself

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

* Neither the name of the {organization} nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
'''

import io
import os
import codecs
import logging
import packaging.version
from importlib import metadata

from datetime import datetime, timezone
from typing import List, Union, Optional, Set, Tuple, MutableMapping, Dict, Callable
from argparse import Namespace, _SubParsersAction, ArgumentParser

import sop
import pgpy

# hack to assemble multiple signature packets! reported to PGPy at
# https://github.com/SecurityInnovation/PGPy/issues/197#issuecomment-1027582415
class _multisig(pgpy.types.Armorable): #type: ignore
    @property
    def magic(self) -> str:
        return 'SIGNATURE'
    def parse(self, x:bytes) -> None:
        self._bytes:bytes = x
    def __bytes__(self) -> bytes:
        return self._bytes
    @classmethod
    def from_signatures(cls, signatures:List[pgpy.PGPSignature]) -> pgpy.types.Armorable:
        obj = cls()
        sigdata:bytes = b''
        for signature in signatures:
            sigdata += bytes(signature)
        obj.parse(sigdata)
        return obj

class SOPGPy(sop.StatelessOpenPGP):
    def __init__(self) -> None:
        self.pgpy_version = packaging.version.Version(metadata.version('pgpy'))
        super().__init__(name='SOPGPy', version=f'{self.pgpy_version}',
                         backend=f'PGPy {self.pgpy_version}',
                         description=f'Stateless OpenPGP using PGPy {self.pgpy_version}')

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

    def _maybe_armor(self, armor:bool, data:pgpy.types.Armorable) -> bytes:
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

    # FIXME: consider making the return type a generic instead of this clunky Union:
    # https://docs.python.org/3/library/typing.html#generics
    def _op_with_locked_key(self, seckey:pgpy.PGPKey, keyhandle:str,
                            keypasswords:MutableMapping[str,bytes],
                            func:Callable[[pgpy.PGPKey],
                                          Union[pgpy.PGPMessage,pgpy.PGPSignature]]) -> \
                                          Union[pgpy.PGPMessage,pgpy.PGPSignature]:
        # try all passphrases in map:
        for handle,pw in keypasswords.items():
            # FIXME: be cleverer about which password to try
            # when multiple passwords and keys are
            # present. see for example the discussion in:
            # https://gitlab.com/dkg/openpgp-stateless-cli/-/issues/60
            # FIXME: if pw fails, retry with normalized form
            # https://www.ietf.org/archive/id/draft-dkg-openpgp-stateless-cli-04.html#name-consuming-password-protecte
            try:
                with seckey.unlock(pw):
                    return func(seckey)
            except pgpy.errors.PGPDecryptionError:
                pass
        err:str
        if len(keypasswords) == 0:
            err = "; no passwords provided"
        elif len(keypasswords) == 1:
            err = "by the provided password"
        else:
            err = f"by any of the {len(keypasswords)} passwords provided"
        raise sop.SOPKeyIsProtected(f"Key found at {keyhandle} could not be unlocked {err}.")


    def generate_key(self, armor:bool=True, uids:List[str]=[],
                     keypassword:Optional[bytes]=None,
                     **kwargs:Namespace) -> bytes:
        self.raise_on_unknown_options(**kwargs)
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
        if keypassword is not None:
            try:
                pstring = keypassword.decode(encoding='utf-8')
            except UnicodeDecodeError:
                raise sop.SOPPasswordNotHumanReadable(f'Key password was not UTF-8')
            keypassword = pstring.strip().encode(encoding='utf-8')

            primary.protect(keypassword,
                            pgpy.constants.SymmetricKeyAlgorithm.AES256,
                            pgpy.constants.HashAlgorithm.SHA512)
        return self._maybe_armor(armor, primary)


    def extract_cert(self,
                     key:bytes=b'',
                     armor:bool=True,
                     **kwargs:Namespace) -> bytes:
        self.raise_on_unknown_options(**kwargs)
        seckey, _ = pgpy.PGPKey.from_blob(key)
        return self._maybe_armor(armor, seckey.pubkey)


    def sign(self,
             data:bytes=b'',
             armor:bool=True,
             sigtype:sop.SOPSigType=sop.SOPSigType.binary,
             signers:MutableMapping[str, bytes]={},
             wantmicalg:bool=False,
             keypasswords:MutableMapping[str,bytes]={},
             **kwargs:Namespace) -> Tuple[bytes, Optional[str]]:
        self.raise_on_unknown_options(**kwargs)
        if not signers:
            raise sop.SOPMissingRequiredArgument("Need at least one OpenPGP Secret Key file as an argument")
        seckeys:MutableMapping[str,pgpy.PGPKey] = self._get_keys(signers)
        msg:pgpy.PGPMessage
        if sigtype is sop.SOPSigType.text:
            try:
                datastr:str = data.decode(encoding='utf-8')
            except UnicodeDecodeError:
                raise sop.SOPNotUTF8Text('Message was not encoded UTF-8 text')
            msg = pgpy.PGPMessage.new(datastr, cleartext=True, format='u')
        elif sigtype == sop.SOPSigType.binary:
            msg = pgpy.PGPMessage.new(data, format='b')
        else:
            raise sop.SOPUnsupportedOption(f'unknown signature type {sigtype}')
        signatures:List[pgpy.PGPSignature] = []
        hashalgs:Set[pgpy.constants.HashAlgorithm] = set()
        for handle,seckey in seckeys.items():
            sig:pgpy.PGPSignature
            if seckey.is_protected:
                res = self._op_with_locked_key(seckey, handle, keypasswords, lambda key: key.sign(msg))
                if isinstance(res, pgpy.PGPSignature):
                    sig = res
                else:
                    raise TypeError("Expected signature to be produced")
            else:
                sig = seckey.sign(msg)
            hashalgs.add(sig.hash_algorithm)
            signatures.append(sig)

        micalg:Optional[str] = None
        if wantmicalg:
            if len(hashalgs) != 1:
                micalg = ''
            else:
                micalg = f'pgp-{hashalgs.pop().lower()}'

        return (self._maybe_armor(armor, _multisig.from_signatures(signatures)), micalg)


    def verify(self,
               data:bytes,
               start:Optional[datetime]=None,
               end:Optional[datetime]=None,
               sig:bytes=b'',
               signers:MutableMapping[str,bytes]={},
               **kwargs:Namespace) -> List[sop.SOPSigResult]:
        self.raise_on_unknown_options(**kwargs)
        if not signers:
            raise sop.SOPMissingRequiredArgument('needs at least one OpenPGP certificate')
        signature = self._get_pgp_signature(sig)
        certs:MutableMapping[str,pgpy.PGPKey] = self._get_certs(signers)
        
        ret:List[sop.SOPSigResult] = self._check_sigs(certs, data, signature, start, end)
        if not ret:
            raise sop.SOPNoSignature("No good signature found")
        return ret


    def encrypt(self,
                data:bytes,
                literaltype:sop.SOPLiteralDataType=sop.SOPLiteralDataType.binary,
                armor:bool=True,
                passwords:MutableMapping[str,bytes]={},
                signers:MutableMapping[str,bytes]={},
                keypasswords:MutableMapping[str,bytes]={},
                recipients:MutableMapping[str,bytes]={},
                **kwargs:Namespace) -> bytes:
        self.raise_on_unknown_options(**kwargs)
        handle:str
        keys:MutableMapping[str,pgpy.PGPKey] = {}
        pws:MutableMapping[str,str] = {}
        format_octet:str

        if literaltype is sop.SOPLiteralDataType.text:
            format_octet = 'u'
            try:
                data.decode(encoding='utf-8')
            except UnicodeDecodeError:
                raise sop.SOPNotUTF8Text('Message was not encoded UTF-8 text')
        elif literaltype is sop.SOPLiteralDataType.binary:
            format_octet = 'b'
        elif literaltype is sop.SOPLiteralDataType.mime:
            format_octet = 'm'
        else:
            raise sop.SOPUnsupportedOption(f'sopgpy encrypt --as with value {literaltype}')

        if passwords:
            for p, pwdata in passwords.items():
                try:
                    pstring = pwdata.decode(encoding='utf-8')
                except UnicodeDecodeError:
                    raise sop.SOPPasswordNotHumanReadable(f'Password in {p} was not UTF-8')
                pws[p] = pstring.strip()
        if signers:
            keys = self._get_keys(signers)
        if not recipients and not passwords:
            raise sop.SOPMissingRequiredArgument('needs at least one OpenPGP certificate or password to encrypt to')

        certs:MutableMapping[str,pgpy.PGPKey] = self._get_certs(recipients)


        cipher:Optional[pgpy.constants.SymmetricKeyAlgorithm] = None

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
        sessionkey = cipher.gen_key()

        msg = pgpy.PGPMessage.new(data, format=format_octet, compression=pgpy.constants.CompressionAlgorithm.Uncompressed)
        for signer, key in keys.items():
            if key.is_protected:
                res:Union[pgpy.PGPMessage,pgpy.PGPSignature]
                res = self._op_with_locked_key(key, signer, keypasswords, lambda seckey: seckey.sign(msg))
                if isinstance(res, pgpy.PGPSignature):
                    sig = res
                else:
                    raise TypeError("Expected signature to be produced")
            else:
                sig = key.sign(msg)
            msg |= sig
        
        for handle, cert in certs.items():
            msg = cert.encrypt(msg, cipher=cipher, sessionkey=sessionkey)
        for p, pw in pws.items():
            msg = msg.encrypt(passphrase=pw, sessionkey=sessionkey)
        del sessionkey
        return self._maybe_armor(armor, msg)


    def _check_sigs(self,
                    certs:MutableMapping[str,pgpy.PGPKey],
                    msg:pgpy.PGPMessage,
                    sig:Optional[pgpy.PGPSignature]=None,
                    start:Optional[datetime]=None,
                    end:Optional[datetime]=None) -> List[sop.SOPSigResult]:
        sigs:List[sop.SOPSigResult] = []
        for signer, cert in certs.items():
            try:
                verif:pgpy.types.SignatureVerification = cert.verify(msg, signature=sig)
                goodsig:pgpy.types.sigsubj
                for goodsig in verif.good_signatures:
                    sigtime = goodsig.signature.created
                    # some versions of pgpy return tz-naive objects, even though all timestamps are in UTC:
                    # see https://docs.python.org/3/library/datetime.html#aware-and-naive-objects
                    if sigtime.tzinfo is None:
                        sigtime = sigtime.replace(tzinfo=timezone.utc)
                    if ('issues' in goodsig._fields and goodsig.issues == 0) or ('verified' in goodsig._fields and goodsig.verified):
                        if start is None or sigtime >= start:
                            if end is None or sigtime <= end:
                                sigs += [sop.SOPSigResult(goodsig.signature.created, goodsig.by.fingerprint, cert.fingerprint, goodsig.signature.__repr__())]
            except:
                pass
        return sigs

    def decrypt(self,
                data:bytes,
                wantsessionkey:bool=False,
                sessionkeys:MutableMapping[str,sop.SOPSessionKey]={},
                passwords:MutableMapping[str,bytes]={},
                signers:MutableMapping[str,bytes]={},
                start:Optional[datetime]=None,
                end:Optional[datetime]=None,
                keypasswords:MutableMapping[str,bytes]={},
                secretkeys:MutableMapping[str,bytes]={},
                **kwargs:Namespace) -> Tuple[bytes, List[sop.SOPSigResult], Optional[sop.SOPSessionKey]]:
        self.raise_on_unknown_options(**kwargs)
        certs:MutableMapping[str,pgpy.PGPKey] = {}
        # FIXME!!!
        if wantsessionkey:
            raise sop.SOPUnsupportedOption('sopgpy does not support --session-key-out yet')
        if sessionkeys: 
            raise sop.SOPUnsupportedOption('sopgpy does not support --with-session-key yet')
        
        if signers:
            certs = self._get_certs(signers)
        if not secretkeys and not passwords and not sessionkeys:
            raise sop.SOPMissingRequiredArgument('needs something to decrypt with (at least an OpenPGP secret key, a session key, or a password)')

        sigs:List[sop.SOPSigResult] = []
        seckeys:MutableMapping[str,pgpy.PGPKey] = self._get_keys(secretkeys)

        encmsg:pgpy.PGPMessage = pgpy.PGPMessage.from_blob(data)
        msg:pgpy.PGPMessage
        ret:Optional[bytes] = None
        out:Union[str,bytes]
        for handle,seckey in seckeys.items():
            try:
                if seckey.is_protected:
                    res = self._op_with_locked_key(seckey, handle, keypasswords,
                                                   lambda key: key.decrypt(encmsg))
                    if isinstance(res, pgpy.PGPMessage):
                        msg = res
                    else:
                        raise TypeError("Expected message to be produced")
                else:
                    msg = seckey.decrypt(encmsg)
                if certs:
                    sigs = self._check_sigs(certs, msg, None, start, end)
                out = msg.message
                if isinstance(out, str):
                    ret = out.encode('utf8')
                else:
                    ret = out
                break
            except pgpy.errors.PGPDecryptionError as e:
                logging.warning(f'could not decrypt with {seckey.fingerprint}')
            except sop.SOPKeyIsProtected as e:
                # FIXME: this means we couldn't unlock.  should we
                # propagate this forward if no eventual unlock is
                # found?
                logging.warning(e)
        if ret is None:
            for p, password in passwords.items():
                attempts:List[Union[bytes,str]] = [ password ]
                extratext = ''
                try:
                    trimmed = password.decode(encoding='utf-8').strip().encode('utf-8')
                    if trimmed != password:
                        # try the version with the trailing whitespace trimmed off first,
                        # as it is more likely to match the user's intent
                        attempts.insert(0, trimmed)
                        extratext = ' (also tried trimming trailing whitespace)'
                except UnicodeDecodeError:
                    pass
                for attempt in attempts:
                    if ret is None:
                        try:
                            # note: PGPy 0.5.4 and earlier don't accept bytes here:
                            # https://github.com/SecurityInnovation/PGPy/pull/388
                            if isinstance (attempt, bytes) and \
                               self.pgpy_version <= packaging.version.Version('0.5.4'):
                                attempt = attempt.decode(encoding='utf-8')
                            msg = encmsg.decrypt(passphrase=attempt)
                            if certs:
                                sigs = self._check_sigs(certs, msg, None, start, end)
                            out = msg.message
                            if isinstance(out, str):
                                ret = out.encode('utf8')
                            else:
                                ret = out
                            break
                        except pgpy.errors.PGPDecryptionError:
                            pass
                if ret is None:
                    logging.warning(f'could not decrypt with password from {p}{extratext}')
        if ret is None:
            raise sop.SOPCouldNotDecrypt(f'could not find anything capable of decryption')
        return (ret, sigs, None)

    def armor(self, data:bytes,
              label:sop.SOPArmorLabel=sop.SOPArmorLabel.auto,
              **kwargs:Namespace) -> bytes:
        self.raise_on_unknown_options(**kwargs)
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
            elif label is sop.SOPArmorLabel.auto: # try to guess
                try:
                    obj, _ = pgpy.PGPKey.from_blob(data)
                    len(str(obj)) # try to get a string out of the supposed PGPKey, triggering an error if unset
                except:
                    try:
                        obj = pgpy.PGPSignature.from_blob(data)
                        len(str(obj)) # try to get a string out of the supposed PGPKey, triggering an error if unset
                    except:
                        try:
                            obj = pgpy.PGPMessage.from_blob(data)
                            len(str(obj)) # try to get a string out of the supposed PGPKey, triggering an error if unset
                        except:
                            obj = pgpy.PGPMessage.new(data)
            else:
                raise sop.SOPInvalidDataType(f'unknown armor type {label}')
        except (ValueError,TypeError) as e:
            raise sop.SOPInvalidDataType(f'{e}')
        return str(obj).encode('ascii')

    def dearmor(self, data:bytes, **kwargs:Namespace) -> bytes:
        self.raise_on_unknown_options(**kwargs)
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

    def inline_detach(self,
                      clearsigned:bytes,
                      armor:bool=True,
                      **kwargs:Namespace) -> Tuple[bytes,bytes]:
        self.raise_on_unknown_options(**kwargs)
        msg:pgpy.PGPMessage
        msg = pgpy.PGPMessage.from_blob(clearsigned)
        body:Union[bytes,bytearray,str] = msg.message
        if isinstance(body, str):
            body = body.encode('utf-8')
        return (bytes(body), self._maybe_armor(armor, _multisig.from_signatures(msg.signatures)))

    def inline_sign(self,
                    data:bytes,
                    armor:bool=True,
                    sigtype:sop.SOPInlineSigType=sop.SOPInlineSigType.binary,
                    signers:MutableMapping[str,bytes]={},
                    keypasswords:MutableMapping[str,bytes]={},
                    **kwargs:Namespace
                    ) -> bytes:
        self.raise_on_unknown_options(**kwargs)
        if not signers:
            raise sop.SOPMissingRequiredArgument("Need at least one OpenPGP Secret Key file as an argument")
        seckeys:MutableMapping[str,pgpy.PGPKey] = self._get_keys(signers)
        msg:pgpy.PGPMessage
        if sigtype in [sop.SOPInlineSigType.text, sop.SOPInlineSigType.clearsigned]:
            try:
                datastr:str = data.decode(encoding='utf-8')
            except UnicodeDecodeError:
                raise sop.SOPNotUTF8Text('Message was not encoded UTF-8 text')
            msg = pgpy.PGPMessage.new(datastr, cleartext=(sigtype == sop.SOPInlineSigType.clearsigned), format='u', compression=pgpy.constants.CompressionAlgorithm.Uncompressed)
        elif sigtype == sop.SOPInlineSigType.binary:
            msg = pgpy.PGPMessage.new(data, format='b', compression=pgpy.constants.CompressionAlgorithm.Uncompressed)
        else:
            raise sop.SOPUnsupportedOption(f'unknown signature type {sigtype}')
        signatures:List[pgpy.PGPSignature] = []
        for handle,seckey in seckeys.items():
            sig:pgpy.PGPSignature
            if seckey.is_protected:
                res = self._op_with_locked_key(seckey, handle, keypasswords, lambda key: key.sign(msg))
                if isinstance(res, pgpy.PGPSignature):
                    sig = res
                else:
                    raise TypeError("Expected signature to be produced")
            else:
                sig = seckey.sign(msg)
            signatures.append(sig)

        # FIXME: this creates one-pass signatures even for the
        # non-clearsigned output.  it would make more sense for the
        # non-clearsigned output to create a normal signature series.
        for sig in signatures:
            msg |= sig
        if armor or sigtype == sop.SOPInlineSigType.clearsigned:
            return str(msg).encode('utf-8')
        else:
            return bytes(msg)
        
    def inline_verify(self, data:bytes,
                      start:Optional[datetime]=None,
                      end:Optional[datetime]=None,
                      signers:MutableMapping[str,bytes]={},
                      **kwargs:Namespace) -> Tuple[bytes, List[sop.SOPSigResult]]:
        self.raise_on_unknown_options(**kwargs)
        if not signers:
            raise sop.SOPMissingRequiredArgument('needs at least one OpenPGP certificate')
        msg:pgpy.PGPMessage = pgpy.PGPMessage.from_blob(data)
        certs:MutableMapping[str,pgpy.PGPKey] = self._get_certs(signers)

        sigresults:List[sop.SOPSigResult] = self._check_sigs(certs, msg, None, start, end)
        if not sigresults:
            raise sop.SOPNoSignature("No good signature found")
        outmsg:Union[bytes,str] = msg.message
        if isinstance(outmsg, str):
            outmsg = outmsg.encode("utf-8")
        return (outmsg, sigresults)


def main() -> None:
    sop = SOPGPy()
    sop.dispatch()

if __name__ == '__main__':
    main()
