#!/bin/bash
# mapping to get from the TRAVIS_PYTHON_VERSION environment variable to something pyenv understands
# this will need to be manually kept up to date until travis support for python on osx improves
declare -A pyver
pyver["2.7"]="2.7.13"
pyver["3.3"]="3.3.6"
pyver["3.4"]="3.4.6"
pyver["3.5"]="3.5.3"
pyver["3.6"]="3.6.0"
pyver["pypy"]="pypy2-5.6.0"
pyver["pypy3"]="pypy3.3-5.5-alpha"

sudo brew update
# travis doesn't natively support python on osx yet, so start by installing pyenv
# also install newer openssl here
sudo brew install -y pyenv openssl
# now install the requested version of python, and set it to local
pyenv install ${pyver[${TRAVIS_PYTHON_VERSION}]}
pyenv local ${pyver[${TRAVIS_PYTHON_VERSION}]}

# make sure libffi-dev, gnupg2, pgpdump, and newer openssl are installed as well
sudo brew install -y libffi-dev gnupg2 pgpdump
