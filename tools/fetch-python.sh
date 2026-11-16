#!/bin/sh
# Fetch the CPython that brew-ports releases bundle, check its SHA-256 and unpack it.
#
#   tools/fetch-python.sh arm64|x86_64 DEST
#
# DEST receives the interpreter as DEST/bin/python3. The build is python-build-standalone's relocatable
# install_only_stripped CPython, which depends on neither Homebrew, MacPorts nor the Command Line Tools.
set -eu

version=3.15.2
release=20261110
case "${1:-}" in
  arm64)
    triple=aarch64-apple-darwin
    sha256=7e58607647b5b4832092a339ff1c55eeeccee128221232509b8fc8d27957065e
    ;;
  x86_64)
    triple=x86_64-apple-darwin
    sha256=11143c2a2556b14619e8241d3f74bb43ad97181c0eb4909bab87d7aad1154e49
    ;;
  *)
    echo "usage: fetch-python.sh arm64|x86_64 DEST" >&2
    exit 2
    ;;
esac
dest=${2:?usage: fetch-python.sh arm64|x86_64 DEST}
name="cpython-${version}+${release}-${triple}-install_only_stripped.tar.gz"
url="https://github.com/astral-sh/python-build-standalone/releases/download/${release}/${name}"

work=$(mktemp -d)
trap 'rm -rf "${work:?}"' EXIT
curl -q -fsSL --retry 3 -o "${work}/${name}" "${url}"
if command -v shasum >/dev/null 2>&1; then
  actual=$(shasum -a 256 "${work}/${name}" | cut -d' ' -f1)
else
  actual=$(sha256sum "${work}/${name}" | cut -d' ' -f1)
fi
if [ "${actual}" != "${sha256}" ]; then
  echo "fetch-python.sh: ${name} has SHA-256 ${actual}, expected ${sha256}" >&2
  exit 1
fi
mkdir -p "${work}/unpack" "$(dirname "${dest}")"
tar -xzf "${work}/${name}" -C "${work}/unpack"
rm -rf "${dest:?}"
mv "${work}/unpack/python" "${dest}"
echo "${dest}/bin/python3: CPython ${version} for ${triple}"
