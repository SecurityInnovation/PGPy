#!/bin/bash

brew unlink python@3.13 && brew link --overwrite python@3.13
brew bundle install
