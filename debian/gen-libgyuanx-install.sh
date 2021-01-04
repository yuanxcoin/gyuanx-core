#!/bin/bash

set -e

UPSTREAM_VER="$1"
LIBGYUANX_VER="${UPSTREAM_VER/[^0-9.]*/}"
if ! grep -q "^Package: libgyuanx-core$LIBGYUANX_VER\$" debian/control; then
    echo -e "\nError: debian/control doesn't contain the correct libgyuanx-core$LIBGYUANX_VER version; you should run:\n\n    ./debian/update-libgyuanx-ver.sh\n"
    exit 1
fi

for sublib in "" "-wallet"; do
    if ! [ -f debian/libgyuanx-core$sublib$LIBGYUANX_VER ]; then
        rm -f debian/libgyuanx-core$sublib[0-9]*.install
        sed -e "s/@LIBGYUANX_VER@/$LIBGYUANX_VER/" debian/libgyuanx-core$sublib.install.in >debian/libgyuanx-core$sublib$LIBGYUANX_VER.install
    fi
done
