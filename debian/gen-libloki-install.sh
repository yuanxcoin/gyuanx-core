#!/bin/bash

set -e

UPSTREAM_VER="$1"
LIBLOKI_VER="${UPSTREAM_VER/[^0-9.]*/}"
if ! grep -q "^Package: libloki-core$LIBLOKI_VER\$" debian/control; then
    echo -e "\nError: debian/control doesn't contain the correct libloki-core$LIBLOKI_VER version; you should run:\n\n    ./debian/update-libloki-ver.sh\n"
    exit 1
fi

for sublib in "" "-wallet"; do
    if ! [ -f debian/libloki-core$sublib$LIBLOKI_VER ]; then
        rm -f debian/libloki-core$sublib[0-9]*.install
        sed -e "s/@LIBLOKI_VER@/$LIBLOKI_VER/" debian/libloki-core$sublib.install.in >debian/libloki-core$sublib$LIBLOKI_VER.install
    fi
done
