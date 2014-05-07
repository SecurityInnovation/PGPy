#!/bin/bash
# $1 - signature
# $2 - subject

source gpg.sh

$GPG -vv --verify ${1} ${2}