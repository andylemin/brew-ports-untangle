#!/bin/sh
# Build the release tarballs dist/brew-ports-VERSION-macos-ARCH.tar.gz and their dist/SHA256SUMS.
#
#   tools/build-release.sh [arm64] [x86_64]       both architectures when none is named
#
# A tarball unpacks to brew-ports-VERSION/ holding bin/brew-ports, lib/brew-ports.pyz and python/, the
# CPython that tools/fetch-python.sh pins.
set -eu

sha256() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1"
  else
    sha256sum "$1"
  fi
}

root=$(cd "$(dirname "$0")/.." && pwd -P)
version=$(sed -n 's/^__version__ = "\(.*\)"$/\1/p' "${root}/brew_ports/__init__.py")
if [ -z "${version}" ]; then
  echo "build-release.sh: no __version__ in brew_ports/__init__.py" >&2
  exit 1
fi
if [ $# -eq 0 ]; then
  set -- arm64 x86_64
fi

"${root}/tools/build-zipapp.sh" >/dev/null
: > "${root}/dist/SHA256SUMS"
for arch in "$@"; do
  stage="${root}/build/release/${arch}"
  bundle="${stage}/brew-ports-${version}"
  tarball="brew-ports-${version}-macos-${arch}.tar.gz"
  rm -rf "${stage:?}"
  mkdir -p "${bundle}/bin" "${bundle}/lib"
  "${root}/tools/fetch-python.sh" "${arch}" "${bundle}/python" >/dev/null
  cp "${root}/dist/brew-ports.pyz" "${bundle}/lib/"
  cp "${root}/tools/launcher.sh" "${bundle}/bin/brew-ports"
  chmod 755 "${bundle}/bin/brew-ports"
  # COPYFILE_DISABLE keeps macOS tar from adding AppleDouble ._ files.
  COPYFILE_DISABLE=1 tar -czf "${root}/dist/${tarball}" -C "${stage}" "brew-ports-${version}"
  (cd "${root}/dist" && sha256 "${tarball}") >> "${root}/dist/SHA256SUMS"
done
cat "${root}/dist/SHA256SUMS"
