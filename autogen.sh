#!/bin/sh

libtoolize
aclocal -I m4
autoheader
automake --add-missing
autoconf
echo "autoconfiguration done, to build: ./configure ; make"
