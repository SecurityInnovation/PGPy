#!/bin/bash
# gpg_sign_and_verify.sh

source gpg.sh

GPG_SIGN_OPTS="--default-key ${RSA_KEY} --armor --detach-sign --sign"
GPG_VERIFY_OPTS="-vv --verify"

# oopts becomes the options string without --inline if it exists
oopts=( $( echo $* | sed -e 's/--inline//' ) )
if [[ "${#oopts[@]}" == "0" ]]; then
    echo "ERROR - need a filename to sign!"
    exit -1
fi

if [[ "$@" == *"--inline"* ]]; then
    # remove the --detach-sign; change --sign to --clearsign
    GPG_SIGN_OPTS=$( echo $GPG_SIGN_OPTS | sed -e 's/--detach-sign//' -e 's/--sign/--clearsign/')
fi

if [[ "$@" != *"--inline"* ]] && [[ "${#oopts[@]}" != "1" ]]; then
    GPG_SIGN_OPTS="${GPG_SIGN_OPTS} --output ${oopts[1]}"
    GPG_VERIFY_OPTS="${GPG_VERIFY_OPTS} ${oopts[1]}"

elif [[ "$@" != *"--inline"* ]] && [[ "${#oopts[@]}" == "1" ]]; then
    GPG_VERIFY_OPTS="${GPG_VERIFY_OPTS} ${oopts[0]}.asc"
fi

echo "Signing ${oopts[0]}..."
$GPG $GPG_SIGN_OPTS ${oopts[0]}

if [[ "$@" == *"--inline"* ]]; then
    mv ${oopts[0]}.asc ${oopts[0]}
fi

echo ""
echo "Verifying signature..."
$GPG $GPG_VERIFY_OPTS ${oopts[0]} && echo $'\n'"Signature verified." || echo $'\n'"Signing failed!"