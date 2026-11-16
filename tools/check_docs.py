"""Check the Doxygen blocks of every module, class and function, the part Doxygen itself cannot judge

    python3 -I tools/check_docs.py PATH...

Each PATH is a Python file or a directory searched for them. A block's first line is its brief, with no
closing period. A function documents every parameter but self and cls with `@param NAME`, and has
`@returns` exactly when it returns a value; the descriptions of its tags start in one column. Under a
`tests` directory only helpers need a block: the `test_*` methods and the unittest hooks are exempt.
Doxygen checks the rest (`docs/Doxyfile`). Exit status 1 when a block is missing or malformed.
"""

from __future__ import annotations

import ast
import os
import re
import sys
from collections.abc import Iterator

EXEMPT_IN_TESTS = re.compile(r"^(test_\w+|setUp|tearDown|setUpClass|tearDownClass)$")
NAMED_TAG = re.compile(r"^(?P<tag>@param|@throws)\s+(?P<name>\S+)\s+(?P<text>\S.*)$")
RETURNS_TAG = re.compile(r"^@returns\s+(?P<text>\S.*)$")
FunctionNode = ast.FunctionDef | ast.AsyncFunctionDef


def python_files(paths: list[str]) -> Iterator[str]:
    """Yield the Python files named by the arguments, searching directories

    @param paths  files and directories from the command line
    @returns      an iterator over the files, in sorted order within each directory
    """
    for path in paths:
        if os.path.isfile(path):
            yield path
            continue
        for dirpath, dirnames, filenames in os.walk(path):
            dirnames[:] = sorted(d for d in dirnames if d != "__pycache__")
            for name in sorted(filenames):
                if name.endswith(".py"):
                    yield os.path.join(dirpath, name)


def parameters(node: FunctionNode, method: bool) -> list[str]:
    """Return the names a function's block must document

    @param node    the function
    @param method  whether the function is defined in a class, so its first parameter is self or cls
    @returns       the parameter names in signature order
    """
    args = node.args
    names = [a.arg for a in args.posonlyargs + args.args]
    if method and names and names[0] in ("self", "cls") and not _is_static(node):
        names = names[1:]
    if args.vararg:
        names.append(args.vararg.arg)
    names += [a.arg for a in args.kwonlyargs]
    if args.kwarg:
        names.append(args.kwarg.arg)
    return names


def _is_static(node: FunctionNode) -> bool:
    """Return whether a method is a staticmethod, whose first parameter is an ordinary one

    @param node  the method
    @returns     True for `@staticmethod`
    """
    return any(isinstance(d, ast.Name) and d.id == "staticmethod" for d in node.decorator_list)


def returns_value(node: FunctionNode) -> bool:
    """Return whether a function hands back a value: by its annotation, else by its own return and yield

    @param node  the function
    @returns     False for `-> None` or a body that only returns None
    """
    if node.returns is not None:
        return not (isinstance(node.returns, ast.Constant) and node.returns.value is None)
    for child in _own_nodes(node):
        if isinstance(child, (ast.Yield, ast.YieldFrom)):
            return True
        if isinstance(child, ast.Return) and child.value is not None:
            if not (isinstance(child.value, ast.Constant) and child.value.value is None):
                return True
    return False


def _own_nodes(node: FunctionNode) -> Iterator[ast.AST]:
    """Yield the nodes of a function body, without descending into nested functions, classes or lambdas

    @param node  the function
    @returns     an iterator over the body's nodes
    """
    stack: list[ast.AST] = list(node.body)
    while stack:
        child = stack.pop()
        yield child
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        stack.extend(ast.iter_child_nodes(child))


def tag_problems(doc: str) -> tuple[list[str], set[str], bool, list[str]]:
    """Read the tags of a block

    @param doc  the docstring, as `ast.get_docstring` cleans it
    @returns    the problems found, the `@param` names, whether `@returns` is present, and the `@throws` names
    """
    problems: list[str] = []
    names: set[str] = set()
    has_returns = False
    throws: list[str] = []
    columns: set[int] = set()
    lines = doc.splitlines()
    first_tag = next((i for i, line in enumerate(lines) if line.startswith("@")), None)
    if first_tag is not None and first_tag > 0 and lines[first_tag - 1].strip():
        problems.append("a blank line goes between the text and the tags")
    for line in lines[first_tag or len(lines):]:
        if not line.startswith("@"):
            continue
        returns = RETURNS_TAG.match(line)
        if returns is not None:
            has_returns = True
            columns.add(returns.start("text"))
            continue
        m = NAMED_TAG.match(line)
        if m is None:
            problems.append(f"malformed tag line: {line.strip()}")
            continue
        name = m.group("name")
        if m.group("tag") == "@throws":
            throws.append(name)
        elif name in names:
            problems.append(f"@param {name} is given twice")
        else:
            names.add(name)
        columns.add(m.start("text"))
    if len(columns) > 1:
        problems.append("the tag descriptions start in different columns")
    return problems, names, has_returns, throws


def check_function(path: str, node: FunctionNode, method: bool, in_tests: bool) -> list[str]:
    """Return the problems of one function's block

    @param path      the file, for the messages
    @param node      the function
    @param method    whether it is defined in a class
    @param in_tests  whether the file lies under a tests directory
    @returns         one message per problem, `path:line: text`
    """
    if in_tests and EXEMPT_IN_TESTS.match(node.name):
        return []
    where = f"{path}:{node.lineno}: {node.name}"
    doc = ast.get_docstring(node)
    if not doc:
        return [f"{where}: no Doxygen block"]
    out = [f"{where}: {p}" for p in brief_problems(doc)]
    problems, documented, has_returns, _ = tag_problems(doc)
    out += [f"{where}: {p}" for p in problems]
    wanted = parameters(node, method)
    for name in wanted:
        if name not in documented:
            out.append(f"{where}: @param {name} is missing")
    for name in sorted(documented - set(wanted)):
        out.append(f"{where}: @param {name} names no parameter")
    if returns_value(node) and not has_returns:
        out.append(f"{where}: @returns is missing")
    if has_returns and not returns_value(node):
        out.append(f"{where}: @returns given for a function that returns nothing")
    return out


def brief_problems(doc: str) -> list[str]:
    """Return the problems of a block's first line

    @param doc  the docstring
    @returns    the problems; none for a one-line brief without a closing period
    """
    brief = doc.splitlines()[0].strip()
    if brief.startswith("@"):
        return ["the brief comes first, without @brief"]
    if brief.endswith(".") and not brief.endswith("..."):
        return ["the brief takes no closing period"]
    return []


def check_file(path: str) -> list[str]:
    """Return the problems of one file: its module block, its classes and its functions

    @param path  the Python file
    @returns     one message per problem
    """
    with open(path, encoding="utf-8") as fh:
        tree = ast.parse(fh.read(), filename=path)
    in_tests = "tests" in path.split(os.sep)
    out = []
    doc = ast.get_docstring(tree)
    if not doc:
        out.append(f"{path}:1: no module block")
    else:
        out += [f"{path}:1: module: {p}" for p in brief_problems(doc)]
    out += check_body(path, tree.body, False, in_tests)
    return out


def check_body(path: str, body: list[ast.stmt], in_class: bool, in_tests: bool) -> list[str]:
    """Return the problems of the classes and functions defined directly in a body

    @param path      the file, for the messages
    @param body      a module or class body
    @param in_class  whether the body is a class body
    @param in_tests  whether the file lies under a tests directory
    @returns         one message per problem
    """
    out = []
    for node in body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out += check_function(path, node, in_class, in_tests)
        elif isinstance(node, ast.ClassDef):
            doc = ast.get_docstring(node)
            if not doc:
                out.append(f"{path}:{node.lineno}: {node.name}: no class block")
            else:
                out += [f"{path}:{node.lineno}: {node.name}: {p}" for p in brief_problems(doc)]
            out += check_body(path, node.body, True, in_tests)
    return out


def main(argv: list[str]) -> int:
    """Check every file the arguments name and print each problem

    @param argv  the files and directories to check
    @returns     0 when every block is complete, 1 otherwise, 2 without arguments
    """
    if not argv:
        sys.stderr.write("usage: check_docs.py PATH...\n")
        return 2
    problems = [p for path in python_files(argv) for p in check_file(path)]
    for problem in problems:
        print(problem)
    print(f"check-docs: {len(problems)} problem{'' if len(problems) == 1 else 's'}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
