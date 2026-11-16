"""Shell environment analysis, read from the rc files without running them, and the syntax check of rewrites

Every line that matters to `env-cleanup` becomes a `LineRecord` with its file and line number.
"""

from __future__ import annotations

import contextlib
import glob
import os
import pwd
import re
import stat
import tempfile
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from .. import system
from ..model import Instance, Manager
from ..state import slug
from . import PrefixIndex

DSCL = system.DSCL
LAUNCHCTL = system.LAUNCHCTL
PATH_VARS = ("PATH", "MANPATH", "INFOPATH")
FISH_USER_PATHS = "fish_user_paths"
BUILD_VARS = ("PKG_CONFIG_PATH", "PKG_CONFIG_LIBDIR", "LDFLAGS", "CPPFLAGS", "CFLAGS", "CXXFLAGS",
              "LIBRARY_PATH", "CPATH", "C_INCLUDE_PATH", "CMAKE_PREFIX_PATH", "ACLOCAL_PATH",
              "PYTHONPATH", "PERL5LIB", "GEM_HOME", "GEM_PATH", "NODE_PATH")
FLAG_VARS = ("LDFLAGS", "CPPFLAGS", "CFLAGS", "CXXFLAGS")
STOCK_ETC_PATHS = ("/usr/local/bin", "/usr/local/sbin")
CHECKERS = {
    "zsh": ["/bin/zsh", "-f", "-n"],
    "bash": ["/bin/bash", "-n"],
    "sh": ["/bin/sh", "-n"],
    "tcsh": ["/bin/tcsh", "-f", "-n"],
    "csh": ["/bin/tcsh", "-f", "-n"],
}
COMPOUND_WORDS = frozenset((
    "if", "elif", "else", "then", "fi", "while", "until", "for", "do", "done", "case", "esac", "select",
    "function", "foreach", "switch", "begin", "end", "endif", "endsw", "repeat", "{", "}",
))

_MARK_START = re.compile(r"^\s*#\s*MacPorts Installer addition on ")
_MARK_END = re.compile(r"^\s*#\s*Finished adapting your (\S+) environment variable for use with MacPorts\.?\s*$")
_SHELLENV = re.compile(r"(?<![\w.@+-])(?P<brew>(?:[^\s\"'`$();|&<>]*/)?brew)[\"']?\s+shellenv\b")
_BREW_BY_NAME = re.compile(r"(?:\$\(|`)\s*brew\s")
_SH_ASSIGN = re.compile(r"(?:(?<=[\s;&|(`{])|^)(?:(?:export|declare|typeset|local|readonly)"
                        r"(?:\s+-[A-Za-z]+)*\s+)?([A-Za-z_][A-Za-z0-9_]*)(\+?=)")
_CSH_SETENV = re.compile(r"(?:(?<=[\s;&|(])|^)setenv\s+([A-Za-z_][A-Za-z0-9_]*)(?=\s|$)")
_CSH_SET = re.compile(r"(?:(?<=[\s;&|(])|^)set\s+([A-Za-z_][A-Za-z0-9_]*)\s*(\+?=)\s*")
_FISH_SET = re.compile(r"(?:(?<=[\s;&|(])|^)set\s+((?:-{1,2}[A-Za-z-]+\s+)*)([A-Za-z_][A-Za-z0-9_]*)(?=\s|$)")
_FISH_ADD = re.compile(r"(?:(?<=[\s;&|(])|^)fish_add_path(?=\s|$)")
_HEREDOC = re.compile(r"(?<!<)<<(-?)\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\2")
_FUNCTION = re.compile(r"^\s*(?:function\s+)?[\w.:-]+\s*\(\)")
_PATH_TOKEN = re.compile(r"(?:(?<=[\s\"'`=:(,])|^)((?:/|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?/)[^\s\"'`;|&<>(){}]*)")
_PATH_START = re.compile(r"^(?:/|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?/)")
_FLAG_PATH = re.compile(r"(?:(?<=[\s\"'=:,])|(?<=-[LIF])|^)(/[^\s\"'`;|&<>():,]*)")
_VAR = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)(?:(:?[-=+?])([^}]*))?\}|([A-Za-z_][A-Za-z0-9_]*))")
_ANSI = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\x07]*\x07")
_SELF = object()
# What a block word of the sh family opens: the closer it waits for, or first the header it reads, the condition of
# `if` and `while`, the words of `for` (`for:in` once past `in`) or the count of `repeat`.
_SH_BLOCKS = {"if": "if", "case": "esac", "for": "for", "select": "for", "while": "while", "until": "while",
              "repeat": "repeat", "foreach": "end"}
_SH_HEADERS = frozenset(("if", "while", "for", "for:in", "repeat"))
_FISH_BLOCKS = frozenset(("if", "for", "while", "function", "begin", "switch"))
_CSH_BLOCKS = {"foreach": "end", "while": "end", "switch": "endsw"}
_CLOSERS = {"'": "'", '"': '"', "`": "`", "$(": ")", "${": "}", "(": ")"}   # each quote, substitution, word list
_IO_NUMBER = re.compile(r"\d+(?=[<>])")


@dataclass
class PathEntry:
    """One entry of a PATH-like value: its text, the path it expands to and the instance that owns it"""

    text: str                        # the entry as written, quotes removed
    path: str | None              # expanded absolute path; None when it holds an unknown variable or is relative
    instance_prefix: str | None   # the instance whose owned roots it names
    exists: bool | None           # None when `path` is None
    usr_local: bool                  # names /usr/local or below


@dataclass
class LineRecord:
    """One rc-file line that matters to `env-cleanup`: what it assigns, runs or marks"""

    file: str
    lineno: int                      # 1-based
    text: str                        # the whole line as read
    kind: str                        # "assign", "shellenv", "marker", "dyld", "build", "source"
    var: str | None = None        # assign/dyld/build: PATH, MANPATH, INFOPATH, fish_user_paths, DYLD_*, LDFLAGS...
    entries: list[PathEntry] = field(default_factory=list)
    self_ref: bool = False           # the assignment keeps the old value ($PATH, ${PATH}, $path)
    position: str = ""               # "prepend", "append", "both", "reset" (no self reference), "none"
    # shellenv: the brew path text, "" when called by name; other kinds: "" when the line runs `$(brew ...)`
    brew: str | None = None
    command: str | None = None    # source: "source", ".", "eval" or "other"
    block: int | None = None      # index into ShellAnalysis.blocks
    compound: bool = False           # part of a compound command, a continuation or a here-document
    nested: bool = False             # a block, array, quote or substitution open before or after the line
    duplicate: bool = False          # shellenv: an earlier line of the same file runs the same brew
    instance_prefixes: list[str] = field(default_factory=list)


@dataclass
class RcFile:
    """A shell file the analysis reads, with its realpath, its owner and any read error"""

    path: str
    shell: str                       # "zsh", "bash", "sh", "tcsh", "fish"
    exists: bool
    realpath: str | None
    owner_uid: int | None
    error: str | None = None


@dataclass
class InstallerBlock:
    """A block the MacPorts installer added to a shell file, between its two marker comments"""

    file: str
    start: int                       # line of `# MacPorts Installer addition on ...`
    end: int                         # line of `# Finished adapting your <VAR> environment variable ...`
    var: str


@dataclass
class EtcPathLine:
    """One line of `/etc/paths` or of a file in `/etc/paths.d`"""

    file: str
    lineno: int
    entry: PathEntry
    stock: bool                      # /usr/local/bin or /usr/local/sbin in /etc/paths


@dataclass
class Shadowed:
    """A command that the `bin` or `sbin` of two or more instances provide, and the one the live PATH runs"""

    command: str
    providers: list[str]             # the command's path in each instance that has it
    prefixes: list[str]
    winner: str | None            # what the live PATH runs
    winner_prefix: str | None


@dataclass
class ShellAnalysis:
    """The shell analysis: rc files, line records, installer blocks, `/etc/paths`, live PATH, shadowed commands"""

    home: str
    zdotdir: str | None
    zdotdir_source: str | None    # "~/.zshenv", "environment" or None
    login_shell: str | None
    login_shell_realpath: str | None
    login_shell_prefix: str | None  # the instance whose owned roots hold the shell or its realpath
    read_order: list[str]            # the login shell's files in the order it reads them, for the PATH order edit
    files: list[RcFile]
    records: list[LineRecord]
    blocks: list[InstallerBlock]
    etc_paths: list[EtcPathLine]
    live: dict[str, list[PathEntry]]
    live_duplicates: dict[str, list[str]]
    gui_path: list[PathEntry] | None
    shadowed: list[Shadowed]


# Shell words ---------------------------------------------------------------------

def _family(shell: str) -> str:
    """Return the syntax family of a shell

    @param shell  zsh, bash, sh, tcsh, csh or fish
    @returns      `csh` for tcsh and csh, `fish` for fish, else `sh`
    """
    if shell in ("tcsh", "csh"):
        return "csh"
    if shell == "fish":
        return "fish"
    return "sh"


def _balanced(s: str, i: int, open_c: str, close_c: str) -> int:
    """Return the index just past the bracket closing the one at `s[i]`, skipping quotes and escapes

    @param s        the shell text
    @param i        the index of the opening bracket
    @param open_c   the opening bracket
    @param close_c  the closing bracket
    @returns        the index past the closing bracket; the length of the text when none closes it
    """
    depth, n = 0, len(s)
    while i < n:
        c = s[i]
        if c == "\\":
            i += 2
            continue
        if c == "'":
            j = s.find("'", i + 1)
            i = n if j < 0 else j + 1
            continue
        if c == '"':
            j = i + 1
            while j < n and s[j] != '"':
                j += 2 if s[j] == "\\" else 1
            i = j + 1
            continue
        if c == open_c:
            depth += 1
        elif c == close_c:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n


def read_word(s: str, i: int) -> tuple[str, int]:
    """Read one shell word from `s[i:]`: quotes removed, `$...` constructs kept as written

    @param s  the shell text
    @param i  where the word starts
    @returns  the word, and the index of the delimiter or end that stops it
    """
    out: list[str] = []
    n = len(s)
    while i < n:
        c = s[i]
        if c in " \t;&|<>)":
            break
        if c == "\\" and i + 1 < n:
            out.append(s[i + 1])
            i += 2
        elif c == "'":
            j = s.find("'", i + 1)
            j = n if j < 0 else j
            out.append(s[i + 1:j])
            i = j + 1
        elif c == '"':
            i += 1
            while i < n and s[i] != '"':
                if s[i] == "\\" and i + 1 < n and s[i + 1] in '"\\$`':
                    out.append(s[i + 1])
                    i += 2
                elif s.startswith("$(", i):
                    j = _balanced(s, i + 1, "(", ")")
                    out.append(s[i:j])
                    i = j
                else:
                    out.append(s[i])
                    i += 1
            i += 1
        elif s.startswith("$(", i):
            j = _balanced(s, i + 1, "(", ")")
            out.append(s[i:j])
            i = j
        elif s.startswith("${", i):
            j = _balanced(s, i + 1, "{", "}")
            out.append(s[i:j])
            i = j
        elif c == "`":
            j = s.find("`", i + 1)
            j = n if j < 0 else j + 1
            out.append(s[i:j])
            i = j
        else:
            out.append(c)
            i += 1
    return "".join(out), i


def split_words(s: str) -> list[str]:
    """Split shell text into words as `read_word` reads them

    @param s  the shell text
    @returns  the words; the delimiters between them are dropped
    """
    words, i, n = [], 0, len(s)
    while i < n:
        while i < n and s[i] in " \t\n":
            i += 1
        if i >= n:
            break
        word, j = read_word(s, i)
        if j == i:          # a delimiter read_word stops at
            i += 1
            continue
        words.append(word)
        i = j
    return words


def split_colon(text: str) -> list[str]:
    """Split a PATH-like value on `:` outside `${...}` and `$(...)`

    @param text  the value as written
    @returns     the parts, empty ones included
    """
    parts, current, depth, i = [], [], 0, 0
    while i < len(text):
        c = text[i]
        if text.startswith("${", i) or text.startswith("$(", i):
            depth += 1
            current.append(text[i:i + 2])
            i += 2
            continue
        if depth and c in "})":
            depth -= 1
        if c == ":" and not depth:
            parts.append("".join(current))
            current = []
        else:
            current.append(c)
        i += 1
    parts.append("".join(current))
    return parts


def strip_comment(line: str) -> str:
    """Return the line without its `#` comment (a `#` outside quotes that starts a word)

    @param line  a shell line
    @returns     the text before the comment; the whole line when it has none
    """
    quote: str | None = None
    i, n = 0, len(line)
    while i < n:
        c = line[i]
        if quote:
            if c == "\\" and quote != "'":
                i += 2
                continue
            if c == quote:
                quote = None
        elif c == "\\":
            i += 2
            continue
        elif c in "'\"`":
            quote = c
        elif c == "#" and (i == 0 or line[i - 1] in " \t;&|("):
            return line[:i]
        i += 1
    return line


def split_commands(code: str) -> list[str]:
    """Split shell text into the commands that `;`, `&`, `&&` and `||` separate; a pipeline stays one command

    Quotes and substitutions are read as `read_word` reads them, and the `&` of a redirection separates nothing.

    @param code  a shell line, its comment stripped
    @returns     the commands, without the blanks around them; empty ones left out
    """
    parts, start, i, n = [], 0, 0, len(code)
    while i < n:
        if code.startswith(("&&", "||"), i):
            width = 2
        elif code[i] == ";" or (code[i] == "&" and code[i - 1:i] not in ("<", ">", "|")
                                and not code.startswith("&>", i)):
            width = 1
        else:
            i = max(read_word(code, i)[1], i + 1)
            continue
        parts.append(code[start:i])
        i += width
        start = i
    parts.append(code[start:])
    return [part.strip() for part in parts if part.strip()]


def runs_brew_by_name(text: str) -> bool:
    """Return whether shell text runs `brew` by name, in a `$(...)` or backquote substitution

    @param text  a line, a command or an entry, as written
    @returns     True when a substitution starts with `brew`
    """
    return bool(_BREW_BY_NAME.search(text))


def expand(text: str, env: dict[str, str]) -> str | None:
    """Expand `~`, `$NAME`, `${NAME}` and `${NAME:-word}` forms from `env`

    @param text  a shell word, quotes removed
    @param env   the variables, `HOME` among them
    @returns     the expanded text; None when the text runs a command or names a variable `env` lacks
    """
    if "$(" in text or "`" in text:
        return None
    if text == "~" or text.startswith("~/"):
        text = env.get("HOME", "~") + text[1:]
    elif text.startswith("~"):
        return None
    failed: list[bool] = []

    def sub(m: "re.Match[str]") -> str:
        name = m.group(1) or m.group(4)
        op, word = m.group(2), m.group(3)
        value = env.get(name)
        if op in (":-", ":="):
            value = value if value else expand(word or "", env)
        elif op in ("-", "="):
            value = value if value is not None else expand(word or "", env)
        elif op in (":+", "+"):
            value = expand(word or "", env) if value else ""
        if value is None:
            failed.append(True)
            return ""
        return value

    out = _VAR.sub(sub, text)
    if failed or "$" in out:
        return None
    return out


def _odd_backslashes(line: str) -> bool:
    """Return whether a line ends in an odd number of backslashes, which continues it on the next line

    @param line  a shell line, its comment stripped
    @returns     True for a line the next one continues
    """
    count = len(line) - len(line.rstrip("\\"))
    return count % 2 == 1


def _compound(code: str) -> bool:
    """Return whether a line opens or continues a compound command, which `env-cleanup` only reports

    @param code  a shell line, its comment stripped
    @returns     True when it starts with one of `COMPOUND_WORDS`, opens a block or a function, or holds `;;`
    """
    words = code.strip().lstrip("!").split()
    if not words:
        return False
    first = words[0].rstrip(";")
    stripped = code.rstrip()
    return (first in COMPOUND_WORDS or stripped.endswith("{") or stripped.endswith(" then")
            or stripped.endswith(" do") or ";;" in code or bool(_FUNCTION.match(code)))


class _Nesting:
    """The constructs that stay open from one line of an rc file to the next, which make the lines inside compound

    The sh family opens blocks with its reserved words, `{`, a subshell and an array `name=(`, and a quote or a
    substitution a line leaves open spans lines too; fish closes `if`, `for`, `while`, `function`, `begin` and
    `switch` with `end`; csh closes `if (...) then` with `endif`, `foreach` and `while` with `end`, and `switch` with
    `endsw`. A closer that matches no open construct loses the structure, and every later line counts as inside one.

    zsh's short forms start their body without `do` or `then`: after the words of `for` and the count of `repeat`
    the first command is the body, and after a test such as `[[ ... ]]` so is a `{` or a command of `if` or `while`.
    A `{ ... }` body closes the block with its `}`, any other body at the end of its command list (`short`).
    """

    def __init__(self, family: str) -> None:
        """Start a file with no construct open

        @param family  the syntax family, as `_family` returns it
        """
        self.family = family
        self.stack: list[str] = []       # the closer or header each open construct waits for, the innermost last
        self.lost = False                # a closer matched no open construct
        self.cmd = True                  # the next word stands where a command's name goes
        self.touched = False             # the line holds a reserved word or a bracket of a block
        self.prev = ""                   # the word before, for the `else if` of fish and csh
        self.pending: str | None = None  # csh: the `if` or `else if` that a `then` ends
        self.delimited = False           # sh: a test, a subshell or a group ended right before
        self.brace_if = False            # sh: the `}` of an `if` body ended right before, so `elif` goes on
        self.joined = False              # sh: the last operator, `&&`, `||` or `|`, joins the next line on

    def line(self, code: str, continued: bool) -> tuple[bool, bool]:
        """Follow one line

        @param code       the line as written
        @param continued  whether the line before ends in a backslash, so this one goes on with its command
        @returns          whether a construct is open before or after the line, and whether it holds a part of one
        """
        before = self.lost or bool(self.stack)
        self.touched = False
        if not continued:
            self.prev, self.pending, self.delimited, self.brace_if = "", None, False, False
            if not self.stack or self.stack[-1] not in _CLOSERS:
                self.cmd = True
        i = 0
        while i < len(code) and not self.lost:
            i = self._step(code, i)
        if not self.joined and not _odd_backslashes(strip_comment(code)):
            self._end_short()
        return before or self.lost or bool(self.stack), self.touched

    def _end_short(self) -> None:
        """End the short bodies whose command list ends here"""
        while self.stack[-1:] == ["short"]:
            self.stack.pop()

    def _step(self, code: str, i: int) -> int:
        """Read on from one position: in a quote or a substitution, an array, a `case`, or a command line

        Outside a quote or a substitution, a `#` that starts a word starts a comment.

        @param code  the line
        @param i     where reading resumes
        @returns     where the next step starts, past at least one character
        """
        top = self.stack[-1] if self.stack else ""
        if top in _CLOSERS:
            return self._opaque(code, i)
        if code[i] in " \t":
            return i + 1
        if code[i] == "#":
            return len(code)
        if top == "=)":
            return self._array(code, i)
        if top == "esac":
            return self._case(code, i)
        return self._code(code, i)

    def _opaque(self, code: str, i: int) -> int:
        """Read on in a quote or a substitution, and in those nested in it, until it closes or the line ends

        The end of the word list of a `for` puts a command next: the body.

        @param code  the line
        @param i     where reading resumes
        @returns     where the text after its closing character starts; the line's length when it stays open
        """
        n = len(code)
        while i < n and self.stack and self.stack[-1] in _CLOSERS:
            top, c = self.stack[-1], code[i]
            if top == "'":
                j = code.find("'", i)
                if j < 0:
                    return n
                self.stack.pop()
                i = j + 1
            elif c == "\\":
                i += 2
            elif c == _CLOSERS[top]:
                self.stack.pop()
                self.cmd = self.cmd or top == "("
                i += 1
            elif code.startswith(("$(", "${"), i):
                self.stack.append(code[i:i + 2])
                i += 2
            elif c == "`" or (c in "'\"" and top != '"') or (c == "(" and top in ("$(", "(")):
                self.stack.append("$(" if c == "(" else c)
                i += 1
            else:
                i += 1
        return min(i, n)

    def _word(self, code: str, i: int) -> tuple[str, int]:
        """Read one word with its quotes and substitutions; one the line leaves open stays on the stack

        In the sh family a `(` right after a word `name=` opens an array.

        @param code  the line
        @param i     where the word starts, at no blank and no operator
        @returns     the word as written, and where the text after it starts
        """
        start, n = i, len(code)
        while i < n:
            c = code[i]
            if c in " \t;&|<>()":
                if c == "(" and self.family == "sh" and _SH_ASSIGN.fullmatch(code[start:i]):
                    self.stack.append("=)")
                    return code[start:i], i + 1
                break
            if c == "\\":
                i += 2
            elif c in "'\"`" or code.startswith(("$(", "${"), i):
                opener = code[i:i + 2] if c == "$" else c
                self.stack.append(opener)
                i = self._opaque(code, i + len(opener))
                if self.stack and self.stack[-1] in _CLOSERS:
                    break
            else:
                i += 1
        return code[start:i], min(i, n)

    def _code(self, code: str, i: int) -> int:
        """Read one word or operator of a command line

        A redirection leaves the state as it was; any other word or operator ends what came right before it.

        @param code  the line
        @param i     where it starts, at no blank
        @returns     where the text after it starts
        """
        c = code[i]
        delimited, brace_if = self.delimited, self.brace_if
        self.delimited = self.brace_if = self.joined = False
        number = _IO_NUMBER.match(code, i)
        if c in "<>" or number or code.startswith("&>", i):
            self.delimited, self.brace_if = delimited, brace_if
            return self._redirect(code, number.end() if number else i)
        if c in ";&|":
            return self._operator(code, i)
        if c == "(":
            return self._paren(code, i)
        if c == ")":
            self._end_short()
            if self.stack[-1:] == [")"]:
                self.stack.pop()
                self.cmd, self.delimited = False, True
            else:
                self.lost = True
            return i + 1
        word, i = self._word(code, i)
        self._reserved(word, delimited, brace_if)
        return i

    def _operator(self, code: str, i: int) -> int:
        """Read `;`, `&`, `|`, `&&` or `||`: a command goes next, and `;` or `&` ends the short bodies open

        @param code  the line
        @param i     where the operator starts
        @returns     where the text after it starts
        """
        pair = code[i:i + 2]
        self.cmd, self.joined = True, code[i] == "|" or pair == "&&"
        if not self.joined:
            self._end_short()
        return i + (2 if pair in ("&&", "||", "|&") else 1)

    def _redirect(self, code: str, i: int) -> int:
        """Read a redirection and its target, which is no command; `<(` and `>(` open a substitution

        @param code  the line
        @param i     where the operator starts
        @returns     where the text after the target starts
        """
        n = len(code)
        while i < n and code[i] in "<>&|":
            i += 1
        if i < n and code[i] == "(":
            self.stack.append("$(")
            return i + 1
        while i < n and code[i] in " \t":
            i += 1
        if i < n and code[i] not in ";&|<>()":
            i = self._word(code, i)[1]
        return i

    def _paren(self, code: str, i: int) -> int:
        """Read a `(`: in the sh family a function's `()`, a `for` word list or a subshell, else a group read through

        The group, read through to its `)`, is a test, a pattern, a word list or a command substitution; an arithmetic
        command `(( ... ))` ends as a subshell does. A `()` after a block word makes that word a function's name.

        @param code  the line
        @param i     where the `(` stands
        @returns     where the text after it starts
        """
        sh = self.family == "sh"
        if sh and code.startswith("()", i):
            if self.stack[-1:] == [_SH_BLOCKS.get(self.prev)]:
                self.stack.pop()
            self.touched, self.cmd = True, True
            return i + 2
        if sh and self.stack[-1:] == ["for"]:
            self.stack.append("(")
            return i + 1
        if sh and self.cmd and code.startswith("((", i):
            self.stack += [")", "$("]
            self.cmd = False
            return i + 2
        if sh and self.cmd:
            self.stack.append(")")
            self.touched = True
            return i + 1
        self.stack.append("$(")
        self.cmd = False
        return i + 1

    def _array(self, code: str, i: int) -> int:
        """Read on in an array `name=(...)`, whose words are no commands

        @param code  the line
        @param i     where reading resumes, at no blank
        @returns     where the text after the word or bracket starts
        """
        c = code[i]
        if c == ")":
            self.stack.pop()
            return i + 1
        if c == "(":
            self.stack.append("$(")
            return i + 1
        if c in ";&|<>":
            return i + 1
        return self._word(code, i)[1]

    def _case(self, code: str, i: int) -> int:
        """Read on in a `case`, which only its `esac` closes; a nested `case` waits for one more

        @param code  the line
        @param i     where reading resumes, at no blank
        @returns     where the text after the word or operator starts
        """
        if code[i] in ";&|<>()":
            return i + 1
        word, i = self._word(code, i)
        if word == "case":
            self.stack.append("esac")
        elif word == "esac":
            self.stack.pop()
            self.touched, self.cmd = True, False
        return i

    def _reserved(self, word: str, delimited: bool, brace_if: bool) -> None:
        """Follow a word of a command line in the syntax of the file's family

        @param word       the word as written
        @param delimited  sh: whether a test, a subshell or a group ended right before the word
        @param brace_if   sh: whether the `}` of an `if` body ended right before the word
        """
        if self.family == "fish":
            self._fish_word(word)
        elif self.family == "csh":
            self._csh_word(word)
        else:
            self._sh_word(word, delimited, brace_if)
        self.prev = word

    def _close(self, word: str) -> None:
        """Close the innermost construct when it waits for `word`; else the structure is lost

        @param word  a closing reserved word
        """
        if self.stack and self.stack[-1] == word:
            self.stack.pop()
        else:
            self.lost = True
        self.touched, self.cmd = True, False

    def _sh_word(self, word: str, delimited: bool, brace_if: bool) -> None:
        """Follow a word of the sh family: where a command goes, a reserved word opens, continues or closes a block

        `{` opens a group wherever it stands, and `}` closes one with the short bodies inside it; the `}` of an `if`
        body lets an `elif` go on with the `if`.

        @param word       the word as written
        @param delimited  whether a test, a subshell or a group ended right before the word
        @param brace_if   whether the `}` of an `if` body ended right before the word
        """
        if word == "}":
            self._end_short()
        top = self.stack[-1] if self.stack else ""
        if word == "}" and top in ("}", "if{"):
            self._close(top)
            self.delimited = True
            self.cmd = self.brace_if = top == "if{"
            return
        self.delimited = word == "]]"
        if top in _SH_HEADERS and self._header(word, top, delimited):
            return
        if word == "{" or (word == "elif" and brace_if):
            self.stack.append("}" if word == "{" else "if")
            self.touched, self.cmd = True, True
            return
        if not self.cmd:
            return
        top = self.stack[-1] if self.stack else ""
        if word in _SH_BLOCKS:
            self.stack.append(_SH_BLOCKS[word])
            self.touched, self.cmd = True, word in ("if", "while", "until")
        elif word in ("fi", "done", "esac", "}") or (word == "end" and top == "end"):
            self._close(word)
        elif word in ("then", "elif", "else", "do", "function"):
            if word == "elif" and top == "fi":
                self.stack[-1] = "if"
            self.touched, self.cmd = True, word != "function"
        elif word not in ("!", "time") and not _SH_ASSIGN.match(word):
            self.cmd = False

    def _header(self, word: str, top: str, delimited: bool) -> bool:
        """Follow a word in a block's header, which may start the body: `do`, `then`, `{` or a short body's command

        `for` and `repeat` start theirs at the first command after their words or count, `if` and `while` only
        right after a test; elsewhere a word of `if` or `while` belongs to the condition.

        @param word       the word as written
        @param top        the header the block reads: `if`, `while`, `for`, `for:in` or `repeat`
        @param delimited  whether a test, a subshell or a group ended right before the word
        @returns          True when the header takes the word: its count, its `in`, or the `do`, `then` or `{`
        """
        if (top == "repeat" or (top == "for" and word == "in")) and not self.cmd:
            self.stack[-1], self.cmd = "for:in", top == "repeat"
            return True
        starts = self.cmd if top in ("for", "for:in") else delimited
        if word == ("then" if top == "if" else "do") and (self.cmd or delimited):
            self.stack[-1] = "fi" if top == "if" else "done"
        elif word == "{" and starts:
            self.stack[-1] = "if{" if top == "if" else "}"
        elif starts:
            self.stack[-1], self.cmd = "short", True
            return False
        else:
            return False
        self.touched, self.cmd = True, True
        return True

    def _fish_word(self, word: str) -> None:
        """Follow a word of fish, whose blocks all close with `end`; the `if` of an `else if` opens none

        @param word  the word as written
        """
        if not self.cmd:
            return
        if word == "if" and self.prev == "else":
            self.touched = True
        elif word in _FISH_BLOCKS:
            self.stack.append("end")
            self.touched, self.cmd = True, word in ("if", "while", "begin")
        elif word == "end":
            self._close(word)
        elif word in ("else", "case"):
            self.touched, self.cmd = True, word == "else"
        elif word not in ("and", "or", "not", "!", "command", "builtin", "time"):
            self.cmd = False

    def _csh_word(self, word: str) -> None:
        """Follow a word of csh: `if (...) then` opens a block to `endif`, `foreach`, `while` and `switch` theirs

        @param word  the word as written
        """
        pending, self.pending = self.pending, None
        if word == "then" and pending:
            if pending == "if":
                self.stack.append("endif")
            self.touched = True
            return
        if not self.cmd:
            return
        if word == "if":
            self.pending = "else if" if self.prev == "else" else "if"
            self.touched = True
        elif word in _CSH_BLOCKS:
            self.stack.append(_CSH_BLOCKS[word])
            self.touched, self.cmd = True, False
        elif word in ("endif", "end", "endsw"):
            self._close(word)
        elif word in ("else", "case", "default", "default:", "breaksw"):
            self.touched, self.cmd = True, word == "else"
        else:
            self.cmd = False


# The analysis ----------------------------------------------------------------------

class _Analyser:
    """The reading of the rc files: a `LineRecord` for each line that matters, and the installer blocks"""

    def __init__(self, home: str, environ: dict[str, str], instances: Sequence[Instance]) -> None:
        """Start an analysis with no records

        @param home       the user's home, which `~` and `$HOME` expand to
        @param environ    the environment the variables expand from
        @param instances  the instances whose owned roots the entries may name
        """
        self.home = home
        self.env = dict(environ)
        self.env["HOME"] = home
        self.instances = list(instances)
        self.index = PrefixIndex(self.instances)
        self.records: list[LineRecord] = []
        self.blocks: list[InstallerBlock] = []

    # Entries ---------------------------------------------------------------

    def entry(self, text: str, directory: bool = True) -> PathEntry:
        """Return the entry of one path text: the path it expands to, its instance and whether it exists

        @param text       a path as written, quotes removed
        @param directory  whether only a directory counts as existing
        @returns          the entry; its path is None when the text holds an unknown variable or is relative
        """
        path = expand(text, self.env)
        if path is not None:
            path = os.path.normpath(path) if os.path.isabs(path) else None
        inst = self.index.owner(path) if path else None
        exists: bool | None = None
        if path is not None:
            exists = os.path.isdir(path) if directory else os.path.exists(path)
        usr_local = path is not None and system.text_names_prefix(path, ("/usr/local",), False)
        return PathEntry(text, path, inst.prefix if inst else None, exists, usr_local)

    def brew_owner(self, brew: str) -> Instance | None:
        """Return the instance a `brew shellenv` line belongs to: the one whose recorded `brew` path it names

        The paths are compared as text, so the match holds once phase 6 deleted the prefix.

        @param brew  the `brew` path the line names
        @returns     the Homebrew instance; None when the path names none
        """
        for inst in self.instances:
            if inst.manager is not Manager.BREW:
                continue
            fold = system.case_insensitive(inst.prefix) if os.path.exists(inst.prefix) else False
            known = [inst.binary] if inst.binary else []
            known += [os.path.join(s, "bin", "brew") for s in (inst.spellings or (inst.prefix,))]
            target = system.normalise_text_path(brew, fold)
            if any(target == system.normalise_text_path(k, fold) for k in known):
                return inst
        owner = self.index.owner(brew)
        return owner if owner is not None and owner.manager is Manager.BREW else None

    # Assignments ------------------------------------------------------------

    def assignments(self, code: str, shell: str) -> list[tuple[str, list[object]]]:
        """Return each assignment as (variable, tokens), `_SELF` marking the old value

        @param code   a shell line, its comment stripped
        @param shell  the shell that reads the line
        @returns      the assignments of the variables the analysis records, by canonical name
        """
        fam = _family(shell)
        if fam == "fish":
            return self._fish_assignments(code)
        if fam == "csh":
            return self._csh_assignments(code)
        return self._sh_assignments(code, shell)

    def _canonical(self, name: str, shell: str) -> str | None:
        """Return the name the analysis records a variable under

        zsh ties the arrays `path` and `manpath` to `PATH` and `MANPATH`; tcsh and csh tie only `path`.

        @param name   the variable as assigned
        @param shell  the shell that reads the line
        @returns      the name; None for a variable the analysis does not record
        """
        if name in PATH_VARS or name in BUILD_VARS or name.startswith("DYLD_") or name == FISH_USER_PATHS:
            return name
        # zsh ties path and manpath to their variables; tcsh and csh tie path alone.
        if (name == "path" and shell in ("zsh", "tcsh", "csh")) or (name == "manpath" and shell == "zsh"):
            return name.upper()
        return None

    def _tokens(self, canon: str, name: str, pieces: Iterable[str], append: bool, prepend: bool) -> list[object]:
        """Return the tokens of one assignment: its entries, and `_SELF` wherever the old value goes

        @param canon    the variable's canonical name
        @param name     the variable as assigned; its expansion marks the old value too
        @param pieces   the words assigned
        @param append   whether the assignment appends, which puts the old value first
        @param prepend  whether it prepends, which puts the old value last
        @returns        the entries, split on `:` except in a flag variable, with `_SELF` for each old value
        """
        tokens: list[object] = [_SELF] if append else []
        selfish = re.compile(r"^\$\{?(?:%s|%s)(?:\[@\]|\[\*\])?(?::?[-+=?][^}]*)?\}?$"
                             % (re.escape(canon), re.escape(name)))
        for piece in pieces:
            segments = [piece] if canon in FLAG_VARS else split_colon(piece)
            for seg in segments:
                if seg == "":
                    continue
                tokens.append(_SELF if selfish.match(seg) else seg)
        if prepend:
            tokens.append(_SELF)
        return tokens

    def _sh_assignments(self, code: str, shell: str) -> list[tuple[str, list[object]]]:
        """Return the assignments of an sh-family line: `NAME=value`, `NAME+=value` and `NAME=(words)`

        @param code   the line, its comment stripped
        @param shell  zsh, bash or sh
        @returns      the assignments, as `assignments` returns them
        """
        out = []
        pos = 0
        while True:
            m = _SH_ASSIGN.search(code, pos)
            if not m:
                break
            name, op = m.group(1), m.group(2)
            start = m.end()
            if code.startswith("(", start):
                end = _balanced(code, start, "(", ")")
                pieces = split_words(code[start + 1:end - 1])
            else:
                value, end = read_word(code, start)
                pieces = [value]
            pos = max(end, m.end())
            canon = self._canonical(name, shell)
            if canon is None:
                continue
            out.append((canon, self._tokens(canon, name, pieces, op == "+=", False)))
        return out

    def _csh_assignments(self, code: str) -> list[tuple[str, list[object]]]:
        """Return the assignments of a csh-family line: `setenv NAME value` and `set name = (words)`

        @param code  the line, its comment stripped
        @returns     the assignments, as `assignments` returns them
        """
        out = []
        for m in _CSH_SETENV.finditer(code):
            canon = self._canonical(m.group(1), "tcsh")
            if canon is None:
                continue
            i = m.end()
            while i < len(code) and code[i] in " \t":
                i += 1
            value, _ = read_word(code, i)
            out.append((canon, self._tokens(canon, m.group(1), [value], False, False)))
        for m in _CSH_SET.finditer(code):
            canon = self._canonical(m.group(1), "tcsh")
            if canon is None:
                continue
            start = m.end()
            if code.startswith("(", start):
                end = _balanced(code, start, "(", ")")
                pieces = split_words(code[start + 1:end - 1])
            else:
                pieces = [read_word(code, start)[0]]
            out.append((canon, self._tokens(canon, m.group(1), pieces, m.group(2) == "+=", False)))
        return out

    def _fish_assignments(self, code: str) -> list[tuple[str, list[object]]]:
        """Return the assignments of a fish line: `set` with its flags, and `fish_add_path`

        @param code  the line, its comment stripped
        @returns     the assignments, as `assignments` returns them; a `set` that erases or queries is none
        """
        out = []
        for m in _FISH_SET.finditer(code):
            flags = m.group(1).split()
            if any(f in ("-e", "--erase", "-q", "--query") for f in flags):
                continue
            canon = self._canonical(m.group(2), "fish")
            if canon is None:
                continue
            words = split_words(code[m.end():].split(";")[0])
            append = any(f in ("-a", "--append") or (f.startswith("-") and not f.startswith("--") and "a" in f[1:])
                         for f in flags)
            prepend = any(f in ("-p", "--prepend") or (f.startswith("-") and not f.startswith("--") and "p" in f[1:])
                          for f in flags)
            out.append((canon, self._tokens(canon, m.group(2), words, append, prepend)))
        for m in _FISH_ADD.finditer(code):
            words = split_words(code[m.end():].split(";")[0])
            flags = [w for w in words if w.startswith("-")]
            dirs = [w for w in words if not w.startswith("-")]
            append = any(f in ("-a", "--append") for f in flags)
            out.append(("PATH", self._tokens("PATH", "PATH", dirs, append, not append)))
        return out

    @staticmethod
    def _position(tokens: list[object]) -> tuple[bool, str]:
        """Return whether an assignment keeps the old value, and where its entries go

        @param tokens  the tokens, as `_tokens` returns them
        @returns       the self reference, and `prepend`, `append`, `both`, `reset` or `none`
        """
        selves = [k for k, t in enumerate(tokens) if t is _SELF]
        entries = [k for k, t in enumerate(tokens) if t is not _SELF]
        if not entries:
            return bool(selves), "none"
        if not selves:
            return False, "reset"
        before = any(k < selves[0] for k in entries)
        after = any(k > selves[-1] for k in entries)
        return True, "both" if before and after else ("prepend" if before else "append")

    # Lines ------------------------------------------------------------------

    def classify(self, path: str, lineno: int, raw: str, code: str, shell: str, *, compound: bool,
                 seen_brews: dict[str, int]) -> list[LineRecord]:
        """Return the records of one rc-file line: a `shellenv` line, the variables it assigns, or another line

        @param path        the rc file
        @param lineno      the line's number
        @param raw         the line as written
        @param code        the line without its comment
        @param shell       the shell that reads the file
        @param compound    whether a continuation, a here-document or a compound command holds the line
        @param seen_brews  the `brew` of each `shellenv` line met so far in the file, to its first line; updated
        @returns           the records
        """
        compound = compound or _compound(code)
        m = _SHELLENV.search(code)
        if m:
            brew = m.group("brew")
            brew_path = brew if "/" in brew else ""
            inst = self.brew_owner(brew_path) if brew_path else None
            key = system.normalise_text_path(brew_path, False) if brew_path else ""
            rec = LineRecord(path, lineno, raw, "shellenv", brew=brew_path, compound=compound,
                             duplicate=key in seen_brews,
                             entries=[self.entry(brew_path, directory=False)] if brew_path else [],
                             instance_prefixes=[inst.prefix] if inst else [])
            seen_brews.setdefault(key, lineno)
            return [rec]
        records = []
        for var, tokens in self.assignments(code, shell):
            texts = [t for t in tokens if isinstance(t, str)]
            if var in FLAG_VARS:
                # Compiler flags, not a list: the paths behind -L, -I, -F, each other flag as written, and the old
                # value inside the string.
                own = re.compile(r"\$\{?%s\b" % var)
                entries = [self.entry(p) for t in texts for word in split_words(t)
                           for p in (_FLAG_PATH.findall(word) or ([] if own.search(word) else [word]))]
                self_ref = len(texts) < len(tokens) or any(own.search(t) for t in texts)
                position = ""
            else:
                self_ref, position = self._position(tokens)
                entries = [self.entry(t) for t in texts]
            kind = "dyld" if var.startswith("DYLD_") else ("build" if var in BUILD_VARS else "assign")
            prefixes = sorted({e.instance_prefix for e in entries if e.instance_prefix})
            records.append(LineRecord(path, lineno, raw, kind, var=var, entries=entries, self_ref=self_ref,
                                      position=position, compound=compound, instance_prefixes=prefixes,
                                      brew="" if runs_brew_by_name(code) else None))
        if records:
            return records
        return self.other_line(path, lineno, raw, code, compound)

    def other_line(self, path: str, lineno: int, raw: str, code: str, compound: bool) -> list[LineRecord]:
        """Return the record of a line that names a path under an instance's owned roots, or runs `brew` by name

        Such a line runs `source`, `.` or `eval`, or another command (`other`) such as a completion or plugin load.

        @param path      the rc file
        @param lineno    the line's number
        @param raw       the line as written
        @param code      the line without its comment
        @param compound  whether the line is part of a compound command, a continuation or a here-document
        @returns         one `source` record; none when the line names no owned path and runs no `brew`
        """
        texts = [seg for token in _PATH_TOKEN.findall(code) for seg in split_colon(token) if _PATH_START.match(seg)]
        entries = [self.entry(t, directory=False) for t in texts]
        owned = [e for e in entries if e.instance_prefix]
        by_name = runs_brew_by_name(code)
        if not owned and not by_name:
            return []
        return [LineRecord(path, lineno, raw, "source", entries=owned, command=_command_of(code), compound=compound,
                           brew="" if by_name else None,
                           instance_prefixes=sorted({e.instance_prefix for e in owned if e.instance_prefix}))]

    def analyse_file(self, path: str, shell: str) -> str | None:
        """Record the lines of one rc file

        @param path   the rc file
        @param shell  the shell that reads it
        @returns      the read error; None when the file is read
        """
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                lines = fh.read().splitlines()
        except OSError as exc:
            return f"{type(exc).__name__}: {exc.strerror or exc}"
        fam = _family(shell)
        first = len(self.records)
        open_start: int | None = None
        heredoc: tuple[str, bool] | None = None
        continued = False
        nesting = _Nesting(fam)
        seen_brews: dict[str, int] = {}
        for lineno, raw in enumerate(lines, 1):
            if heredoc is not None:
                word, strip_tabs = heredoc
                if (raw.lstrip("\t") if strip_tabs else raw) == word:
                    heredoc = None
                else:
                    self.records.extend(self.other_line(path, lineno, raw, raw, True))
                continue
            if _MARK_START.match(raw):
                open_start = lineno
                self.records.append(LineRecord(path, lineno, raw, "marker"))
                continue
            end = _MARK_END.match(raw)
            if end:
                self.records.append(LineRecord(path, lineno, raw, "marker", var=end.group(1)))
                if open_start is not None:
                    self._close_block(path, open_start, lineno, end.group(1), first)
                    open_start = None
                continue
            code = strip_comment(raw)
            carried, continued = continued, _odd_backslashes(code)
            nested, touched = nesting.line(raw, carried)
            if not code.strip():
                continued = False
                continue
            compound = carried or continued or nested or touched
            if fam != "fish":
                doc = _HEREDOC.search(code)
                if doc:
                    heredoc = (doc.group(3), doc.group(1) == "-")
                    compound = True
            records = self.classify(path, lineno, raw, code, shell, compound=compound, seen_brews=seen_brews)
            for rec in records:
                rec.nested = nested
            self.records.extend(records)
        return None

    def _close_block(self, path: str, start: int, end: int, var: str, first: int) -> None:
        """Record an installer block and tie the file's records between its markers to it

        @param path   the rc file
        @param start  the line of the opening marker
        @param end    the line of the closing marker
        @param var    the variable the closing marker names
        @param first  the index of the file's first record
        """
        index = len(self.blocks)
        self.blocks.append(InstallerBlock(path, start, end, var))
        for rec in self.records[first:]:
            if rec.file == path and start <= rec.lineno <= end:
                rec.block = index
                if rec.kind == "marker":
                    rec.var = var


def _command_of(code: str) -> str:
    """Return the command through which a line names a path

    @param code  the line, its comment stripped
    @returns     `source`, `.`, `eval` or `other`
    """
    if re.search(r"(?:^|[\s;&|(])source(?=\s)", code):
        return "source"
    if re.search(r"(?:^|[\s;&|(])\.(?=\s)", code):
        return "."
    if re.search(r"(?:^|[\s;&|(])eval(?=\s)", code):
        return "eval"
    return "other"


# Files and order -------------------------------------------------------------------

def zdotdir_from(zshenv: str, env: dict[str, str]) -> str | None:
    """Return the value of the last `export ZDOTDIR=` or `ZDOTDIR=` line of `~/.zshenv`, without running it

    A value that cannot be expanded is ignored.

    @param zshenv  the path of `~/.zshenv`
    @param env     the variables the value expands from
    @returns       the directory, normalised and absolute; None when no line sets one or the file cannot be read
    """
    try:
        with open(zshenv, encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return None
    found = None
    for raw in lines:
        code = strip_comment(raw)
        pos = 0
        while True:
            m = _SH_ASSIGN.search(code, pos)
            if not m:
                break
            value, end = read_word(code, m.end())
            pos = max(end, m.end())
            if m.group(1) == "ZDOTDIR" and m.group(2) == "=":
                expanded = expand(value, env)
                if expanded and os.path.isabs(expanded):
                    found = os.path.normpath(expanded)
    return found


def rc_files(home: str, zdotdir: str | None, env: dict[str, str], etc_dir: str) -> list[tuple[str, str]]:
    """List the shell files the analysis reads, as (path, shell)

    @param home     the user's home
    @param zdotdir  the `ZDOTDIR` zsh reads its other files from; None for the home
    @param env      the variables, for the fish config
    @param etc_dir  the system directory of shell files, `/etc`
    @returns        the user's zsh, sh, bash, tcsh and fish files, then the system ones, each once
    """
    z = zdotdir or home
    out: list[tuple[str, str]] = [(os.path.join(home, ".zshenv"), "zsh")]
    for name in (".zshenv", ".zprofile", ".zshrc", ".zlogin"):
        out.append((os.path.join(z, name), "zsh"))
    out += [(os.path.join(home, ".profile"), "sh"), (os.path.join(home, ".bash_profile"), "bash"),
            (os.path.join(home, ".bash_login"), "bash"), (os.path.join(home, ".bashrc"), "bash"),
            (os.path.join(home, ".tcshrc"), "tcsh"), (os.path.join(home, ".cshrc"), "tcsh"),
            (fish_config(home, env), "fish"),
            (os.path.join(etc_dir, "zprofile"), "zsh"), (os.path.join(etc_dir, "zshrc"), "zsh"),
            (os.path.join(etc_dir, "profile"), "sh"), (os.path.join(etc_dir, "bashrc"), "bash")]
    seen, unique = set(), []
    for path, shell in out:
        if path not in seen:
            seen.add(path)
            unique.append((path, shell))
    return unique


def fish_config(home: str, env: dict[str, str]) -> str:
    """Return the path of fish's `config.fish`, below `XDG_CONFIG_HOME` when that expands to an absolute path

    @param home  the user's home
    @param env   the variables
    @returns     `fish/config.fish` below `XDG_CONFIG_HOME`, else below `~/.config`
    """
    xdg = expand(env.get("XDG_CONFIG_HOME") or "", dict(env, HOME=home))
    base = xdg if xdg and os.path.isabs(xdg) else os.path.join(home, ".config")
    return os.path.join(base, "fish", "config.fish")


def _sources(path: str, target: str, home: str) -> bool:
    """Return whether a file sources a target, spelt with `~` or `$HOME` or in full

    @param path    the file that may source the target
    @param target  the path of the sourced file
    @param home    the user's home
    @returns       True when a line runs `. <target>` or `source <target>` outside a comment
    """
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return False
    names = [re.escape(target)]
    if target.startswith(home + "/"):
        rest = re.escape(target[len(home):])
        names += [r"~" + rest, r"\$HOME" + rest, r"\$\{HOME\}" + rest]
    alternatives = "|".join(names)
    pattern = rf"(?:^|[\s;&|])(?:\.|source)\s+[\"']?(?:{alternatives})(?![\w.])"
    return any(re.search(pattern, strip_comment(line)) for line in text.splitlines())


def read_order(shell_name: str | None, home: str, zdotdir: str | None, env: dict[str, str],
               etc_dir: str) -> list[str]:
    """Return the existing files a login shell of this kind reads, in order

    For bash, `/etc/bashrc` and `~/.bashrc` count only where the file read before them sources them.

    @param shell_name  the login shell's name, such as zsh; None or an unknown shell reads no file
    @param home        the user's home
    @param zdotdir     the `ZDOTDIR` zsh reads its other files from; None for the home
    @param env         the variables, for the fish config
    @param etc_dir     the system directory of shell files, `/etc`
    @returns           the files, each once
    """
    z = zdotdir or home
    order: list[str] = []
    if shell_name == "zsh":
        order = [os.path.join(home, ".zshenv")]
        if z != home:
            order.append(os.path.join(z, ".zshenv"))
        order += [os.path.join(etc_dir, "zprofile"), os.path.join(z, ".zprofile"), os.path.join(etc_dir, "zshrc"),
                  os.path.join(z, ".zshrc"), os.path.join(z, ".zlogin")]
    elif shell_name == "bash":
        profile = os.path.join(etc_dir, "profile")
        order = [profile]
        bashrc = os.path.join(etc_dir, "bashrc")
        if _sources(profile, bashrc, home):
            order.append(bashrc)
        login = next((p for p in (os.path.join(home, n) for n in (".bash_profile", ".bash_login", ".profile"))
                      if os.path.isfile(p)), None)
        if login:
            order.append(login)
            user_rc = os.path.join(home, ".bashrc")
            if _sources(login, user_rc, home):
                order.append(user_rc)
    elif shell_name == "sh":
        order = [os.path.join(etc_dir, "profile"), os.path.join(home, ".profile")]
    elif shell_name in ("tcsh", "csh"):
        tcshrc = os.path.join(home, ".tcshrc")
        order = [tcshrc if os.path.isfile(tcshrc) else os.path.join(home, ".cshrc")]
    elif shell_name == "fish":
        order = [fish_config(home, env)]
    out: list[str] = []
    for path in order:
        if os.path.isfile(path) and path not in out:
            out.append(path)
    return out


def _rc_file(path: str, shell: str) -> RcFile:
    """Return a shell file as the analysis records it before reading it: existence, realpath and owner

    @param path   the file
    @param shell  the shell that reads it
    @returns      the record; a dangling symlink keeps its realpath and does not exist
    """
    if not os.path.lexists(path):
        return RcFile(path, shell, False, None, None)
    real = os.path.realpath(path)
    try:
        uid: int | None = os.stat(real).st_uid
    except OSError:
        uid = None
    return RcFile(path, shell, os.path.isfile(real), real, uid)


# Live environment, /etc/paths, shadowed commands -----------------------------------

def _live(analyser: _Analyser, environ: dict[str, str]) -> tuple[dict[str, list[PathEntry]], dict[str, list[str]]]:
    """Return the entries of the live PATH-like, `DYLD_*` and build variables, and the repeated PATH-like ones

    @param analyser  the analysis, whose index finds each entry's instance
    @param environ   the environment the tool runs with
    @returns         the entries by variable, and by PATH-like variable the texts it holds more than once
    """
    live: dict[str, list[PathEntry]] = {}
    names = [v for v in PATH_VARS if v in environ]
    names += sorted(v for v in environ if v.startswith("DYLD_"))
    names += [v for v in BUILD_VARS if v in environ]
    for var in names:
        value = environ[var]
        texts = _FLAG_PATH.findall(value) if var in FLAG_VARS else [t for t in value.split(":") if t]
        live[var] = [analyser.entry(t) for t in texts]
    duplicates: dict[str, list[str]] = {}
    for var in PATH_VARS:
        counts: dict[str, int] = {}
        for entry in live.get(var, []):
            key = entry.text.rstrip("/") or "/"
            counts[key] = counts.get(key, 0) + 1
        dups = [k for k, c in counts.items() if c > 1]
        if dups:
            duplicates[var] = dups
    return live, duplicates


def _etc_paths(analyser: _Analyser, etc_dir: str) -> list[EtcPathLine]:
    """Read `/etc/paths` and every regular file in `/etc/paths.d` (what path_helper reads)

    @param analyser  the analysis, whose index finds each entry's instance
    @param etc_dir   the system directory, `/etc`
    @returns         one line per non-blank line of those files
    """
    paths_file = os.path.join(etc_dir, "paths")
    files = [paths_file] + sorted(p for p in glob.glob(os.path.join(glob.escape(etc_dir), "paths.d", "*"))
                                  if os.path.isfile(p))
    out = []
    for path in files:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                lines = fh.read().splitlines()
        except OSError:
            continue
        for lineno, raw in enumerate(lines, 1):
            text = raw.strip()
            if text:
                out.append(EtcPathLine(path, lineno, analyser.entry(text),
                                       path == paths_file and text in STOCK_ETC_PATHS))
    return out


def is_command(path: str) -> bool:
    """Return whether `path` is a regular file (through symlinks) with an execute bit, as a PATH lookup needs

    @param path  a candidate command
    @returns     True for an executable regular file; False when `stat` fails
    """
    try:
        st = os.stat(path)
    except OSError:
        return False
    return stat.S_ISREG(st.st_mode) and bool(st.st_mode & 0o111)


def _executables(directory: str) -> list[str]:
    """Return the names of the commands in a directory

    @param directory  a `bin` or `sbin` directory
    @returns          the names `is_command` accepts; empty when the directory cannot be listed
    """
    try:
        names = os.listdir(directory)
    except OSError:
        return []
    return [name for name in names if is_command(os.path.join(directory, name))]


def shadowed_commands(index: PrefixIndex, path_entries: Sequence[PathEntry]) -> list[Shadowed]:
    """Find the basenames the `bin` and `sbin` of two or more instances provide, and the one the live PATH runs

    Only entries each instance owns count, so Go and TeX Live links in `/usr/local/bin` do not.

    @param index         the instances, by the paths they own
    @param path_entries  the live PATH
    @returns             one entry per shadowed command, by name
    """
    providers: dict[str, list[tuple[str, str]]] = {}
    for inst in index.instances:
        seen = set()
        for sub in ("bin", "sbin"):
            directory = os.path.join(inst.prefix, sub)
            for name in _executables(directory):
                full = os.path.join(directory, name)
                if name in seen or index.by_identity(full) is not inst:
                    continue
                seen.add(name)
                providers.setdefault(name, []).append((inst.prefix, full))
    listings: dict[str, set] = {}
    out = []
    for name in sorted(n for n, p in providers.items() if len(p) > 1):
        winner = None
        for entry in path_entries:
            if not entry.path:
                continue
            if entry.path not in listings:
                try:
                    listings[entry.path] = set(os.listdir(entry.path))
                except OSError:
                    listings[entry.path] = set()
            candidate = os.path.join(entry.path, name)
            if name in listings[entry.path] and is_command(candidate):
                winner = candidate
                break
        owner = index.owner(winner) if winner else None
        out.append(Shadowed(name, [p for _, p in providers[name]], [x for x, _ in providers[name]], winner,
                            owner.prefix if owner else None))
    return out


def _gui_path(runner, analyser: _Analyser) -> list[PathEntry] | None:
    """Probe `launchctl getenv PATH`, the PATH of GUI applications

    @param runner    the runner of the probe
    @param analyser  the analysis, whose index finds each entry's instance
    @returns         the entries; None when launchd holds no PATH or the probe fails
    """
    action = system.probe("0.launchd.getenv.PATH", [LAUNCHCTL, "getenv", "PATH"], "GUI PATH")
    try:
        result = runner.run(action)
    except OSError:
        return None
    value = result.stdout().strip() if result.exit == 0 else ""
    if not value:
        return None
    return [analyser.entry(t) for t in value.split(":") if t]


def analyse(runner, home: str, environ: dict[str, str], instances: Sequence[Instance],
            login: str | None, *, etc_dir: str = "/etc") -> ShellAnalysis:
    """Analyse the rc files, `/etc/paths`, the live environment, the GUI PATH, the login shell and shadowed commands

    @param runner     the runner of the GUI PATH probe
    @param home       the user's home
    @param environ    the environment the tool runs with
    @param instances  the instances whose owned roots the entries may name
    @param login      the path of the login shell; None when it is unknown
    @param etc_dir    the system directory of shell files, `/etc`
    @returns          the analysis, its files in the order `rc_files` lists them
    """
    environ = dict(environ)
    analyser = _Analyser(home, environ, instances)
    zshenv = os.path.join(home, ".zshenv")
    zdotdir, source = zdotdir_from(zshenv, analyser.env), None
    if zdotdir:
        source = "~/.zshenv"
    elif environ.get("ZDOTDIR"):
        zdotdir = os.path.normpath(expand(environ["ZDOTDIR"], analyser.env) or environ["ZDOTDIR"])
        source = "environment"
    if zdotdir and os.path.normpath(zdotdir) == os.path.normpath(home):
        zdotdir, source = None, None
    files = []
    for path, shell in rc_files(home, zdotdir, environ, etc_dir):
        rc = _rc_file(path, shell)
        if rc.exists:
            rc.error = analyser.analyse_file(path, shell)
        files.append(rc)
    live, duplicates = _live(analyser, environ)
    login_real = os.path.realpath(login) if login else None
    login_inst = None
    if login:
        login_inst = (analyser.index.by_identity(login) or analyser.index.by_text(login)
                      or analyser.index.by_text(login_real or ""))
    name = os.path.basename(login) if login else None
    return ShellAnalysis(
        home=home, zdotdir=zdotdir, zdotdir_source=source, login_shell=login,
        login_shell_realpath=login_real, login_shell_prefix=login_inst.prefix if login_inst else None,
        read_order=read_order(name, home, zdotdir, environ, etc_dir), files=files, records=analyser.records,
        blocks=analyser.blocks, etc_paths=_etc_paths(analyser, etc_dir), live=live, live_duplicates=duplicates,
        gui_path=_gui_path(runner, analyser), shadowed=shadowed_commands(analyser.index, live.get("PATH", [])))


def path_index(entries: Sequence[PathEntry], directory: str) -> int | None:
    """Return the position of `directory` in a PATH (identity, else text), for the PATH-order findings

    @param entries    the entries of the PATH
    @param directory  the directory sought
    @returns          the index of its first entry; None when the PATH lacks it
    """
    for number, entry in enumerate(entries):
        if entry.path and (system.same_path(entry.path, directory) or
                           os.path.normpath(entry.path) == os.path.normpath(directory)):
            return number
    return None


# The login shell ---------------------------------------------------------------------

def login_shell(runner, user: str) -> str | None:
    """Return the account's login shell: its `UserShell` in the directory service, else its `pw_shell`

    The probe is `dscl . -read /Users/<user> UserShell`; the `pwd` database answers when it fails.

    @param runner  the runner of the probe
    @param user    the account name; empty for the account of the running uid
    @returns       the shell's path; None when neither source gives one
    """
    if user:
        action = system.probe(f"0.account.{slug(user)}.shell", [DSCL, ".", "-read", f"/Users/{user}", "UserShell"],
                              f"login shell of {user}")
        try:
            result = runner.run(action)
        except OSError:
            result = None
        if result is not None and result.exit == 0:
            shell = system.parse_dscl(result.stdout()).get("UserShell")
            if shell:
                return shell
    try:
        entry = pwd.getpwnam(user) if user else pwd.getpwuid(os.getuid())
    except KeyError:
        return None
    return entry.pw_shell or None


def login_path_argv(shell: str) -> list[str]:
    """Build the login shell PATH probe, whose command text is the constant `echo $PATH`

    The shell runs it as `<shell> -l -i -c`, or as `<shell> -c` for tcsh and csh, which read `~/.tcshrc` that way.

    @param shell  the path of the login shell
    @returns      the shell, its flags and the command
    """
    if os.path.basename(shell) in ("tcsh", "csh"):
        return [shell, "-c", "echo $PATH"]
    return [shell, "-l", "-i", "-c", "echo $PATH"]


def parse_login_path(output: str, shell: str) -> list[str] | None:
    """Parse the PATH the login shell probe printed: its last line containing `/usr/bin`

    Terminal control sequences are stripped, and fish's space separators are mapped to `:`.

    @param output  the output of the probe, which rc-file noise may surround
    @param shell   the path of the login shell
    @returns       the entries; None when no line holds `/usr/bin`
    """
    lines = [_ANSI.sub("", line).strip() for line in output.splitlines()]
    candidates = [line for line in lines if "/usr/bin" in line]
    if not candidates:
        return None
    line = candidates[-1]
    if os.path.basename(shell) == "fish":
        line = line.replace(" ", ":")
    return [entry for entry in line.split(":") if entry]


# The syntax check --------------------------------------------------------------------

def syntax_check(runner, shell: str, text: str, *, fish: str | None = None, tmp_dir: str | None = None,
                 subject: str | None = None) -> bool | None:
    """Return whether the shell's parser accepts a rewritten file, reading no startup file

    `/bin/bash -n` reads no startup file because the neutral profile drops `BASH_ENV`; fish needs a surviving `fish`.

    @param runner   the runner of the check
    @param shell    the shell that reads the file: zsh, bash, sh, tcsh, csh or fish
    @param text     the text to check
    @param fish     the path of a `fish` that survives the migration; None when there is none
    @param tmp_dir  the directory of the temporary copy; None for the system's
    @param subject  what the action id and description name, such as the file's path; None for the shell
    @returns        True when the parser accepts the text, False when it refuses it; None when no check ran
    """
    if shell == "fish":
        if not fish:
            return None
        head = [fish, "--no-config", "--no-execute"]
    elif shell in CHECKERS:
        head = list(CHECKERS[shell])
    else:
        return None
    fd, path = tempfile.mkstemp(prefix="brew-ports-syntax-", suffix="." + shell, dir=tmp_dir)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        phase = runner.phase if runner.phase is not None else 0
        name = subject or shell
        action = system.probe(f"{phase}.syntax.{slug(name)}", head + [path], f"syntax check of {name}")
        try:
            result = runner.run(action)
        except OSError:
            return None
    finally:
        with contextlib.suppress(OSError):
            os.unlink(path)
    if result.timed_out or result.exit in (126, 127):
        return None
    return result.exit == 0
