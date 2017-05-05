#!/bin/sh

set -e

autoreconf --warnings=all --install
echo "autoconfiguration done, to build: ./configure ; make"
