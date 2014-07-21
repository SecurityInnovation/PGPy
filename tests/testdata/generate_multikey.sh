#!/bin/bash

source gpg.sh

# generate one big test key with multiple subkeys and User IDs
$GPG --batch --gen-key <<EOI
    %echo Generating MultiKey ...
    %no-protection
    %transient-key

    # this primary key is only used to certify the subkeys
    Key-Type: RSA
    Key-Length: 2048
    Key-Usage: sign
    Expire-Date: 0
    Preferences: AES256 CAMELLIA256 SHA256 SHA512 ZLIB

    # User ID
    Name-Real: TestMulti
    Name-Comment: MultiKey
    Name-Email: email@address.tld

    %commit
    %echo done
EOI

# set ownertrust to undefined
echo "Setting ownertrust to undefined"
$GPG --expert --batch --command-fd 0 --edit-key TestMulti >/dev/null 2>&1 <<EOI
trust
1
save
EOI

# add additional User ID
# $GPG --edit-key TestMulti adduid
echo "Adding second UID"
$GPG --expert --batch --command-fd 0 --edit-key TestMulti >/dev/null 2>&1 <<EOI
adduid
TestMulti2
email2@address.tld
MultiKey UID 2
O
uid 1
primary
save
EOI

# add a JPEG photo, because why not
echo "Adding photo: pgp.jpg"
$GPG --expert --batch --command-fd 0 --edit-key TestMulti >/dev/null 2>&1 <<EOI
addphoto
pgp.jpg
y
save
EOI


# now generate some subkeys!
ALG[7]="DSA"
ALG[8]="RSA"
for algn in 8 7; do
    # add one each of a sign-only, encrypt-only, and auth-only key
    echo "Generating ${ALG[${algn}]} (sign-only) 2048-bit subkey pair ..."
    $GPG --expert --batch --command-fd 0 --edit-key TestMulti >/dev/null 2>&1 <<EOI
addkey
${algn}
s
e
s
q
2048
0
save
EOI
    echo "Generating ${ALG[${algn}]} (encrypt-only) 2048-bit subkey pair ..."
    $GPG --expert --batch --command-fd 0 --edit-key TestMulti >/dev/null 2>&1 <<EOI
addkey
${algn}
s
e
e
q
2048
0
save
EOI
    echo "Generating ${ALG[${algn}]} (auth-only) 2048-bit subkey pair ..."
    $GPG --expert --batch --command-fd 0 --edit-key TestMulti >/dev/null 2>&1 <<EOI
addkey
${algn}
s
e
a
q
2048
0
save
EOI
done

# now export the public and private keys to ASCII
$GPG --armor --output pubkeys/TestMulti.key --export             TestMulti
$GPG --armor --output seckeys/TestMulti.key --export-secret-keys TestMulti
