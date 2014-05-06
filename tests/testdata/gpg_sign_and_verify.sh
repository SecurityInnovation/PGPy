#!/bin/bash
# gpg_sign_and_verify.sh

source gpg.sh

for keyfp in `gpg_get_fingerprint sec`; do
    keyname=`gpg_get_name $keyfp`

    echo "Signing tests/testdata/signed_message with ${keyfp}"
    $GPG --default-key ${keyfp} --batch --armor \
        --passphrase "QwertyUiop" \
        --detach-sign --sign --output signatures/signed_message.${keyname}.asc \
        signed_message

    echo -n "Verifying signature ... "
    $GPG -vv --verify signatures/signed_message.${keyname}.asc signed_message >/dev/null 2>&1  \
        && echo "verified" \
        || echo "failed!"
    echo ""
done
