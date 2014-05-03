#!/bin/bash
# GPG bash shortcuts for use in other scripts
# include with "source gpg.sh"

# shortcut to use debutils.gpg and debutils.sec.gpg keyring pair only
GPG="`which gpg` --no-default-keyring --keyring ./testkeys.gpg --secret-keyring ./testkeys.sec.gpg"


# the TestRSA key signature
RSA_KEY=$( $GPG --list-secret-keys | 
    sed -e 'N;/^[A-Za-z0-9\-\_ \.\/]*\n\-*$/d' | 
    awk 'BEGIN {RS = "";} $5 == "TestRSAKey" { split($2, a, "/"); print a[2]; }' )

# the TestDSA key signature
DSA_KEY=$( $GPG --list-secret-keys | 
    sed -e 'N;/^[A-Za-z0-9\-\_ \.\/]*\n\-*$/d' | 
    awk 'BEGIN {RS = "";} $5 == "TestDSAKey" { split($2, a, "/"); print a[2]; }' )

# the TestDSAandElGamal key signature
DSA_E_KEY=$( $GPG --list-secret-keys | 
    sed -e 'N;/^[A-Za-z0-9\-\_ \.\/]*\n\-*$/d' | 
    awk 'BEGIN {RS = "";} $5 == "TestDSAandElGamalKey" { split($2, a, "/"); print a[2]; }' )

# the TestRSASignOnly key signature
RSA_SIGN_ONLY_KEY=$( $GPG --list-secret-keys | 
    sed -e 'N;/^[A-Za-z0-9\-\_ \.\/]*\n\-*$/d' | 
    awk 'BEGIN {RS = "";} $5 == "TestRSASignOnlyKey" { split($2, a, "/"); print a[2]; }' )
