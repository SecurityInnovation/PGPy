#!/bin/bash
# GPG bash shortcuts for use in other scripts
# include with "source gpg.sh"

# shortcut to use debutils.gpg and debutils.sec.gpg keyring pair only
GPG="`which gpg` --no-default-keyring --keyring ./debutils.gpg --secret-keyring ./debutils.sec.gpg"

# the Debutils key signature
# DEBUTILS_KEY=$( $GPG --list-sigs | awk '/^sig/ {print $3}' )
DEBUTILS_KEY=$( $GPG --list-secret-keys | 
    sed -e 'N;/^[A-Za-z0-9\-\_ \.\/]*\n\-*$/d' | 
    awk 'BEGIN {RS = "";} $5 == "Debutils" { split($2, a, "/"); print a[2]; }' )
