#!/bin/bash

brew unlink python@3.9 && brew link --overwrite python@3.9
brew update 1>/dev/null
brew install -q libffi gnupg2 pgpdump openssl@1.1 gpgme swig
