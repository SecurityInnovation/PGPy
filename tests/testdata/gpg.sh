#!/bin/bash
# GPG bash shortcuts for use in other scripts
# include with "source gpg.sh"

# shortcut to use debutils.gpg and debutils.sec.gpg keyring pair only
GPG="/usr/bin/gpg --no-default-keyring --keyring ./testkeys.gpg --secret-keyring ./testkeys.sec.gpg --trustdb-name ./testkeys.trust"

function gpg_get_name () {
    # $1 - keyid, fingerprint, etc
    echo $(
        /usr/bin/awk '
        BEGIN {
            FS = ":"
            names = ""
        }
        /^uid/ {
            str = $10
            sub(/ .*$/, "", str);
            if (match(names, str) == 0) {
                names = names " " str;
            }
        }
        END {
            print names
        }' <( $GPG --with-colons --list-keys $1)
    )
}

function gpg_get_fingerprint () {
    # $1 - optional - "pub", "sec", "both"; default = "both"
    # $2 - optional - keyid, fingerprint, etc
    case $1 in
        "pub" )
            k=$($GPG --with-colons --list-public-keys --fingerprint $2)
            ;;
        "sec" )
            k=$($GPG --with-colons --list-secret-keys --fingerprint $2)
            ;;
        "both"|"" )
            k=$($GPG --with-colons --list-public-keys --fingerprint $2; $GPG --with-colons --list-secret-keys --fingerprint $2)
    esac

    echo $(
        /usr/bin/awk '
        BEGIN {
            FS = ":"
            fps = ""
        }
        /^pub/ || /^sec/ {
            if (match(fps, $5) == 0) {
                fps = fps " " $5
            }
        }
        END {
            print fps
        }' <( echo "${k}" )
    )
}

# # the TestRSA key signature
# RSA_KEY=$( $GPG --list-secret-keys | 
#     sed -e 'N;/^[A-Za-z0-9\-\_ \.\/]*\n\-*$/d' | 
#     awk 'BEGIN {RS = "";} $5 == "TestRSAKey" { split($2, a, "/"); print a[2]; }' )

# # the TestDSA key signature
# DSA_KEY=$( $GPG --list-secret-keys | 
#     sed -e 'N;/^[A-Za-z0-9\-\_ \.\/]*\n\-*$/d' | 
#     awk 'BEGIN {RS = "";} $5 == "TestDSAKey" { split($2, a, "/"); print a[2]; }' )

# # the TestDSAandElGamal key signature
# DSA_E_KEY=$( $GPG --list-secret-keys | 
#     sed -e 'N;/^[A-Za-z0-9\-\_ \.\/]*\n\-*$/d' | 
#     awk 'BEGIN {RS = "";} $5 == "TestDSAandElGamalKey" { split($2, a, "/"); print a[2]; }' )

# # the TestRSASignOnly key signature
# RSA_SIGN_ONLY_KEY=$( $GPG --list-secret-keys | 
#     sed -e 'N;/^[A-Za-z0-9\-\_ \.\/]*\n\-*$/d' | 
#     awk 'BEGIN {RS = "";} $5 == "TestRSASignOnlyKey" { split($2, a, "/"); print a[2]; }' )
