#!/bin/bash
# generate_keyrings.sh

source gpg.sh

if [ ! -e "debutils.key" ]; then
    echo "No ASCII armored keyfile to import!"
    exit -1
fi

echo "importing public key(s) from debutils.key ..."
$GPG --import ./debutils.key

echo "importing secret key(s) from debutils.key ..."
$GPG --allow-secret-key-import --import ./debutils.key
