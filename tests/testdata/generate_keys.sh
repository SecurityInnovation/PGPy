#!/bin/bash

source gpg.sh

unencrypted key generation
for alg in RSA DSA; do
    [[ "$alg" == "RSA" ]] && salg="RSA"
    [[ "$alg" == "DSA" ]] && salg="ELG"

    for bitlen in 1024 2048 3072 4096; do
        # sign/encrypt keys
        $GPG --batch --gen-key <<EOI
            %echo Generating Test${alg}-${bitlen} ...
            %no-protection
            %transient-key
            Key-Type: ${alg}
            Key-Length: ${bitlen}
            Key-Usage: sign,auth
            Subkey-Type: ${salg}
            Subkey-Length: ${bitlen}
            Subkey-Usage: encrypt
            Name-Real: Test${alg}-${bitlen}
            Name-Comment: TESTING-USE-ONLY
            Name-Email: email@address.tld
            Expire-Date: 0
            %commit
            %echo done
EOI

        # sign only keys
        $GPG --batch --gen-key <<EOI
            %echo Generating Test${alg}SignOnly-${bitlen} ...
            %no-protection
            %transient-key
            Key-Type: ${alg}
            Key-Length: ${bitlen}
            Key-Usage: sign,auth
            Name-Real: Test${alg}SignOnly-${bitlen}
            Name-Comment: TESTING-USE-ONLY
            Name-Email: email@address.tld
            Expire-Date: 0
            %commit
            %echo done
EOI
    done

    # encrypted key generation
    for symalg in IDEA 3DES CAST5 BLOWFISH AES AES192 AES256 TWOFISH CAMELLIA128 CAMELLIA192 CAMELLIA256; do
        $GPG --batch --s2k-cipher-algo ${symalg} --gen-key <<EOI
            %echo Generating Test${alg}-Enc${symalg}-1024 ...
            %transient-key
            Key-Type: ${alg}
            Key-Length: 1024
            Key-Usage: sign
            Subkey-Type: ${salg}
            Subkey-Length: 1024
            Subkey-Usage: encrypt
            Name-Real: Test${alg}-Enc${symalg}-1024
            Name-Comment: Passphrase: QwertyUiop
            Name-Email: email@address.tld
            Expire-Date: 0
            Passphrase: QwertyUiop
            %commit
            %echo done
EOI
    done
done

# additional encryption mode key generation
for flag in "--s2k-mode" "--s2k-digest-algo"; do
    if [[ "${flag}" == "--s2k-mode" ]]; then
        opts=( {0..1} )
    fi

    if [[ "${flag}" == "--s2k-digest-algo" ]]; then
        opts=( "MD5" "SHA1" "RIPEMD160" "SHA256" "SHA384" "SHA512" "SHA224" )
    fi

    for opt in ${opts[@]}; do
        [[ "${flag}" == "--s2k-mode" ]] && [[ "${opt}" == "0" ]] && optn="SimpleS2K"
        [[ "${flag}" == "--s2k-mode" ]] && [[ "${opt}" == "1" ]] && optn="SaltedS2K"
        [[ "${flag}" == "--s2k-digest-algo" ]] && optn=${opt}
        echo "${flag} ${opt}"
        $GPG --batch --s2k-cipher-algo CAST5 ${flag} ${opt} --gen-key <<EOI
            %echo Generating TestRSA-EncCAST5-${optn}-1024 ...
            %transient-key
            Key-Type: RSA
            Key-Length: 1024
            Key-Usage: sign,auth
            Subkey-Type: RSA
            Subkey-Length: 1024
            Subkey-Usage: encrypt
            Name-Real: TestRSA-EncCAST5${optn}-1024
            Name-Comment: Passphrase: QwertyUiop
            Name-Email: email@address.tld
            Expire-Date: 0
            Passphrase: QwertyUiop
            %commit
            %echo done
EOI
    done
done

# now export each key into their respective ASCII files
for keyfp in `gpg_get_fingerprint`; do
    keyname=`gpg_get_name $keyfp`

    # export public key
    echo "Exporting ${keyfp} to pubkeys/${keyname}.key ... "
    $GPG --armor --output pubkeys/${keyname}.key --export ${keyfp}

    # export private key
    echo "Exporting ${keyfp} to seckeys/${keyname}.sec.key ... "
    $GPG --armor --output seckeys/${keyname}.sec.key --export-secret-keys ${keyfp}
done