#!/bin/bash
# gpg_sign_and_verify.sh

source gpg.sh

for keyfp in `gpg_get_fingerprint sec`; do
    keyname=`gpg_get_name $keyfp`

    echo "Signing signed_message with ${keyfp}"
    $GPG --default-key ${keyfp} --batch --armor \
        --passphrase "QwertyUiop" \
        --output signatures/signed_message.${keyname}.asc \
        --detach-sign --sign \
        signed_message

    # echo "Inline signing inline_signed_message with ${keyfp}"
    # $GPG --default-key ${keyfp} --batch --armor \
    #     --passphrase "QwertyUiop" \
    #     --output signatures/inline_signed_message.${keyname}.asc \
    #     --clearsign \
    #     inline_signed_message

    # echo -n "Verifying signature ... "
    # $GPG -vv --verify signatures/signed_message.${keyname}.asc signed_message >/dev/null 2>&1  \
    #     && echo "verified" \
    #     || echo "failed!"
    echo ""
done