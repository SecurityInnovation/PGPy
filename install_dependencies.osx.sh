#!/bin/bash

brew update 1>/dev/null
brew install -q libffi gnupg2 pgpdump openssl@1.1 gpgme swig
