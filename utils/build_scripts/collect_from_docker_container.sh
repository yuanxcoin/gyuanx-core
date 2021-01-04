set -ex && mkdir -p build/release/bin
set -ex && docker create --name gyuanx-daemon-container gyuanx-daemon-image
set -ex && docker cp gyuanx-daemon-container:/usr/local/bin/ build/release/
set -ex && docker rm gyuanx-daemon-container
