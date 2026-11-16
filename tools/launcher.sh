#!/bin/sh
# bin/brew-ports of a release bundle: run lib/brew-ports.pyz on the bundle's own python/.
set -eu

self=$0
while [ -L "${self}" ]; do
  link=$(readlink "${self}")
  case ${link} in
    /*) self=${link} ;;
    *) self=$(dirname "${self}")/${link} ;;
  esac
done
root=$(cd "$(dirname "${self}")/.." && pwd -P)
exec "${root}/python/bin/python3" -I "${root}/lib/brew-ports.pyz" "$@"
