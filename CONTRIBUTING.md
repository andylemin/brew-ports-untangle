# Contributing

brew-ports migrates real Macs between package managers, so a change includes
tests that show what it does and keeps the rules below.

## Set up

The unit tests never start `brew`, `port`, or `sudo`. `FakeRunner` answers each
command from a table.

The code uses Python 3.15 and its standard library only. Run the unit tests
with the bundled Python, or in a `python:3.15-slim` container:

```sh
tools/fetch-python.sh "$(uname -m)" build/python
build/python/bin/python3 -B -m unittest discover -s tests/unit -t .
```

Try a change on a disposable virtual machine, never on the Mac you work on.
CI's two integration jobs migrate a throwaway CI machine in each direction.

## The gates

CI also runs these gates on each push and pull request, with the checkers
pinned in `tools/requirements-dev.txt`. Run them in CI's container:

```sh
docker run --rm -it -v "$PWD:/src" -w /src python:3.15-slim bash
apt-get update && apt-get install -y --no-install-recommends doxygen shellcheck
pip install -r tools/requirements-dev.txt
pylint --rcfile pyproject.toml brew_ports tools/check_docs.py
pylint --rcfile pyproject.toml --disable=protected-access tests tests/unit/fixtures
mypy --config-file pyproject.toml
python3 -I tools/check_docs.py brew_ports tests
mkdir -p build && doxygen docs/Doxyfile
shellcheck brew-ports tools/*.sh
```

Each gate reports nothing on a clean tree. Fix the code a checker flags. Never
silence it with `# pylint: disable`, `# noqa`, `# type: ignore`, or a `cast()`.

## Code

A change keeps these conventions:

- Lines stay within 120 columns. Formatted strings are f-strings. Type hints
  use the built-in generics and `X | None`.
- Every module, class, and function carries a Doxygen block. In the tests,
  every helper does too. A `test_*` method needs none: its name says what it
  checks.
- A block's first line is its brief, with no closing period. A body follows
  only for a contract the code cannot show. Then come the tags, their
  descriptions in one column:

  ```python
  def receipt_dependencies(receipt: dict[str, Any] | None, kind: str = "formula") -> list[str]:
      """Return the short names of a receipt's runtime dependencies

      @param receipt  a keg or cask INSTALL_RECEIPT.json, or None
      @param kind     the list a cask receipt keeps: formula or cask
      @returns        the names; empty when the receipt lists none
      """
  ```

  `@param` documents every parameter except `self` and `cls`, `@returns` the
  value a function returns, and `@throws` an exception a caller catches.
- A comment states only what the code cannot show, such as an invariant, a
  quirk of `brew` or `port`, or the reason for a guard. It never describes the
  next line or tells the change's history.
- A finding's name starts with its area, such as `brew-unlinked-keg` or
  `system-clt-missing`. Never use codes like `V01` in code, output, tests, or
  documents.
- Every external program runs through `runner.py`, with an absolute path.

## Commits

Each commit makes one change and includes its tests. The title names the area
first, such as `runner:`, `doctor:`, or `plan:`, then what the commit does, in
about 72 columns. The body says what changed and why, in plain words, without
ticket numbers or planning labels.

## Releases

Raise `__version__` in `brew_ports/__init__.py`. Push the matching tag
`vX.Y.Z`. The release workflow builds the arm64 and x86_64 tarballs with
`tools/build-release.sh`, runs each one the CI machine can execute, and
publishes them with `SHA256SUMS`.

To move the bundled Python to a newer release, change the version, release
date, and checksums in `tools/fetch-python.sh`.
