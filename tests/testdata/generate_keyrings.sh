#!/bin/bash
# generate_keyrings.sh

source gpg.sh

for kfile in pubkeys/*.key; do
    echo "importing public key(s) from ${kfile} ..."
    $GPG --import "$kfile"
    echo ""
done

for skfile in seckeys/*.sec.key; do
    echo "importing secret key(s) from ${skfile} ..."
    $GPG --allow-secret-key-import --import "${skfile}"
    echo ""
done