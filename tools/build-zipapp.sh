#!/bin/bash
# Build dist/brew-ports.pyz, the archive a release bundle runs on its own CPython.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd -P)"
stage="${root}/build/zipapp"

rm -rf "${stage:?}"
mkdir -p "${stage}" "${root}/dist"
cp -R "${root}/brew_ports" "${stage}/"
find "${stage}" -name __pycache__ -type d -prune -exec rm -rf {} +

# zipapp's own -m entry point drops main()'s return value; the exit code matters.
cat > "${stage}/__main__.py" <<'EOF'
import sys
if sys.version_info < (3, 15):
    sys.stderr.write("brew-ports needs Python 3.15 or newer: run the bin/brew-ports of a release bundle\n")
    sys.exit(3)
from brew_ports.cli import main
sys.exit(main())
EOF

python3 -m zipapp "${stage}" -o "${root}/dist/brew-ports.pyz"
echo "${root}/dist/brew-ports.pyz"
