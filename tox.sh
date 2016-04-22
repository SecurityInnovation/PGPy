#!/bin/bash

# homebrew is installed and so is a brewed openssl
if [[ $(uname) == "Darwin" ]] && command -v brew &>/dev/null && brew list openssl &>/dev/null; then
    export ARCHFLAGS="-arch x86_64"
    export LDFLAGS="-L/usr/local/opt/openssl/lib"
    export CFLAGS="-I/usr/local/opt/openssl/include"
fi

tox $*
