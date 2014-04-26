#!/bin/bash
# generate_keyrings.sh

source gpg.sh

for kfile in *.key; do
    echo "importing public key(s) from ${kfile} ..."
    $GPG --import $kfile

    echo "importing secret key(s) from ${kfile} ..."
    $GPG --allow-secret-key-import --import ${kfile}
done