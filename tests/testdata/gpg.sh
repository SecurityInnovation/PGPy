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
    # return primary key fingerprint(s)
    # $1 - optional - "pub", "sec", "both"; default = "both"
    # $2 - optional - keyid, fingerprint, userid, etc
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

function gpg_get_subkey_fingerprint () {
    # return subkey fingerprint(s)
    # $1 - optional - "pub", "sec", "both"; default = "both"
    # $2 - optional - keyid, fingerprint, userid, etc

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
        /^sub/ || /^ssb/ {
            if (match(fps, $5) == 0 {
                fps = fps " " $5
            }
        }
        END {
            print fps
        }' <( echo "${k}" )
    )
}

