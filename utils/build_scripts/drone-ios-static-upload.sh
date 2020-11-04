#!/usr/bin/env bash

# Script used with Drone CI to upload build artifacts (because specifying all this in
# .drone.jsonnet is too painful).



set -o errexit

if [ -z "$SSH_KEY" ]; then
    echo -e "\n\n\n\e[31;1mUnable to upload artifact: SSH_KEY not set\e[0m"
    # Just warn but don't fail, so that this doesn't trigger a build failure for untrusted builds
    exit 0
fi

echo "$SSH_KEY" >ssh_key

set -o xtrace  # Don't start tracing until *after* we write the ssh key

chmod 600 ssh_key

branch_or_tag=${DRONE_BRANCH:-${DRONE_TAG:-unknown}}

upload_to="builds.lokinet.dev/${DRONE_REPO// /_}/${branch_or_tag// /_}"

tmpdir=ios-deps-${DRONE_COMMIT}
mkdir -p $tmpdir/lib
mkdir -p $tmpdir/include

# Merge the arm64 and simulator libs into a single multi-arch merged lib:
lipo -create build/{arm64,sim64}/src/wallet/api/libwallet_merged.a -o $tmpdir/lib/libwallet_merged.a

# Collect all the headers
# Loki core:
cd src
find . \( -name '*.h' -or -name '*.hpp' \) -exec cp -v --parents {} ../$tmpdir/include \;
cp -v daemonizer/posix_daemonizer.inl ../$tmpdir/include/daemonizer
cd ..
# epee:
cp -rv contrib/epee/include/epee $tmpdir/include
# external libs:
mkdir $tmpdir/include/lokimq
cp -v external/{easylogging++/*.h,db_drivers/liblmdb/lmdb.h,randomx/src/randomx.h} $tmpdir/include
cp -v external/loki-mq/lokimq/*.h $tmpdir/include/lokimq
cp -rv external/{boost,cpr/include/cpr,ghc-filesystem/include/ghc,libuv/include/*,rapidjson/include/rapidjson} $tmpdir/include
cp -rv build/arm64/external/uWebSockets/* $tmpdir/include
# static libs:
cp -rv build/arm64/static-deps/include/* $tmpdir/include


filename=ios-deps-${DRONE_COMMIT}.tar.xz
XZ_OPTS="--threads=6" tar --dereference -cJvf $filename $tmpdir

# sftp doesn't have any equivalent to mkdir -p, so we have to split the above up into a chain of
# -mkdir a/, -mkdir a/b/, -mkdir a/b/c/, ... commands.  The leading `-` allows the command to fail
# without error.
upload_dirs=(${upload_to//\// })
mkdirs=
dir_tmp=""
for p in "${upload_dirs[@]}"; do
    dir_tmp="$dir_tmp$p/"
    mkdirs="$mkdirs
-mkdir $dir_tmp"
done

sftp -i ssh_key -b - -o StrictHostKeyChecking=off drone@builds.lokinet.dev <<SFTP
$mkdirs
put $filename $upload_to
SFTP

set +o xtrace

echo -e "\n\n\n\n\e[32;1mUploaded to https://${upload_to}/${filename}\e[0m\n\n\n"

