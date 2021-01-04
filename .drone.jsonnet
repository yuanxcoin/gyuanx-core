local distro = "bionic";
local distro_name = 'Ubuntu 18.04';
local distro_docker = 'ubuntu:bionic';

local apt_get_quiet = 'apt-get -o=Dpkg::Use-Pty=0 -q';

local repo_suffix = '/'; // can be /beta or /staging for non-primary repo deps

local submodules_commands = ['git fetch --tags', 'git submodule update --init --recursive --depth=1'];
local submodules = {
    name: 'submodules',
    image: 'drone/git',
    commands: submodules_commands
};

local deb_pipeline(image, buildarch='amd64', debarch='amd64', jobs=6) = {
    kind: 'pipeline',
    type: 'docker',
    name: distro_name + ' (' + debarch + ')',
    platform: { arch: buildarch },
    steps: [
        submodules,
        {
            name: 'build',
            image: image,
            environment: { SSH_KEY: { from_secret: "SSH_KEY" } },
            commands: [
                'echo "Building on ${DRONE_STAGE_MACHINE}"',
                'echo "man-db man-db/auto-update boolean false" | debconf-set-selections',
                'cp debian/deb.gyuanx.network.gpg /etc/apt/trusted.gpg.d/deb.gyuanx.network.gpg',
                'echo deb http://deb.gyuanx.network' + repo_suffix + ' ' + distro + ' main >/etc/apt/sources.list.d/gyuanx.list',
                apt_get_quiet + ' update',
                apt_get_quiet + ' install -y eatmydata',
                'eatmydata ' + apt_get_quiet + ' dist-upgrade -y',
                'eatmydata ' + apt_get_quiet + ' install --no-install-recommends -y git-buildpackage devscripts equivs ccache openssh-client curl ca-certificates gnupg',
                'curl https://apt.kitware.com/keys/kitware-archive-latest.asc | gpg --dearmor - >/etc/apt/trusted.gpg.d/kitware.gpg',
                'echo deb https://apt.kitware.com/ubuntu/ bionic main >/etc/apt/sources.list.d/kitware.list',
                'eatmydata ' + apt_get_quiet + ' update',
                'cd debian',
                'eatmydata mk-build-deps -i -r --tool="' + apt_get_quiet + ' -o Debug::pkgProblemResolver=yes --no-install-recommends -y" control',
                'cd ..',
                'patch -i debian/dh-lib.patch /usr/share/perl5/Debian/Debhelper/Dh_Lib.pm', # patch debian bug #897569
                'eatmydata gbp buildpackage --git-no-pbuilder --git-builder=\'debuild --preserve-envvar=CCACHE_*\' --git-upstream-tag=HEAD -us -uc -j' + jobs,
                './debian/ci-upload.sh ' + distro + ' ' + debarch,
            ],
        }
    ]
};

[
    deb_pipeline(distro_docker),
# Don't have cmake 3.13+ for these (kitware only provides cmake for amd64, and it isn't worth
# building cmake ourselves for a fairly obscure distro+architecture combination).
#    deb_pipeline("i386/" + distro_docker, debarch="i386"),
#    deb_pipeline("arm64v8/" + distro_docker, buildarch='arm64', debarch="arm64", jobs=1),
#    deb_pipeline("arm32v7/" + distro_docker, buildarch='arm64', debarch="armhf", jobs=1),
]
