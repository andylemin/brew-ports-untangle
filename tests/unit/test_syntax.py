"""Every module parses as Python 3.15, the interpreter a release bundles"""

import ast
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TARGET = (3, 15)


def python_files():
    """Yield every Python file of the package, the tests and the tools

    @returns  an iterator over absolute paths
    """
    for top in ("brew_ports", "tests", "tools"):
        for dirpath, dirnames, filenames in os.walk(os.path.join(ROOT, top)):
            dirnames[:] = [d for d in dirnames if d != "__pycache__"]
            for name in filenames:
                if name.endswith(".py"):
                    yield os.path.join(dirpath, name)


class SyntaxTest(unittest.TestCase):
    """Tests that no module uses syntax the bundled interpreter cannot parse"""

    def test_every_module_parses_as_the_target_version(self):
        files = list(python_files())
        self.assertGreater(len(files), 5)
        for path in files:
            with self.subTest(path=os.path.relpath(path, ROOT)):
                with open(path, encoding="utf-8") as fh:
                    source = fh.read()
                ast.parse(source, filename=path, feature_version=TARGET)


if __name__ == "__main__":
    unittest.main()
