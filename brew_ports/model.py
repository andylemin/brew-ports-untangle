"""The dataclasses every module shares, and their JSON round trip

`from_dict` follows the annotations, so enum members and tuples come back from scan.json, doctor.json and plan.json.
"""

from __future__ import annotations

import dataclasses
import enum
import json
import types
import typing
from dataclasses import dataclass, field
from typing import Any


class Manager(enum.Enum):
    """A package manager, by the name `--target` takes: Homebrew is `brew`, MacPorts `ports`"""

    BREW = "brew"
    PORTS = "ports"


class Confidence(enum.IntEnum):
    """How sure a mapping is that its target is the same software, ordered from none to exact"""

    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    EXACT = 4


class Severity(enum.IntEnum):
    """How serious a doctor finding is, ordered from info to critical"""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class Usability(enum.Enum):
    """Whether a located instance can run its own binary, and what stops it when it cannot"""

    USABLE = "usable"
    NO_REGISTRY = "no-registry"                 # MacPorts: no registry.db, so port fails until a root run makes one
    PLATFORM_MISMATCH = "platform-mismatch"     # base built for another Darwin major, or for Rosetta
    READONLY_REGISTRY = "readonly-registry"     # schema update pending, needs one root run
    MISSING_BINARY = "missing-binary"
    CANNOT_RUN = "cannot-run"                   # binary present but fails (Rosetta absent, no portable Ruby, ...)
    DAMAGED_REGISTRY = "damaged-registry"       # MacPorts: the registry backup fails its integrity check


class OnFailure(enum.Enum):
    """What a failed action does to its phase"""

    STOP = "stop"            # ActionFailed ends the phase
    PROBE = "probe"          # the exit status is data
    SPLIT = "split"          # a batch is retried one name at a time in split_order; removals skip names that are gone
    RETRY_WITH = "retry"     # run `retry_argv` once; a second failure is recorded


class Blocks(enum.Enum):
    """The plan contexts a doctor finding blocks while it holds"""

    ANY = "any"              # every plan and apply on this host
    TARGET = "target"        # plans whose target instance this is
    CASKS = "casks"          # plans that remove casks from this instance
    UNINSTALL = "uninstall"  # plans whose removal set holds any package of this instance
    REMOVE = "remove"        # plans that remove this instance (--remove-manager)


@dataclass
class Instance:
    """One Homebrew or MacPorts installation, known by its prefix"""

    manager: Manager
    prefix: str                      # /opt/homebrew, /usr/local, /opt/local
    identity: tuple[int, int]        # (st_dev, st_ino) of the prefix directory; every prefix comparison uses it
    spellings: tuple[str, ...]       # every spelling met while locating the prefix, for matching text once it is gone
    binary: str | None            # <prefix>/bin/brew or <prefix>/bin/port
    version: str | None           # "7.0.11", "2.12.7"
    arch: str | None              # arm64 or x86_64 of the instance's interpreter (portable Ruby, MacPorts' tclsh)
    usability: Usability
    usability_detail: str | None  # the error text
    drivable: bool                   # usability == USABLE
    inventory_error: str | None   # why the brew inventory probes failed, or why the registry cannot be read
    repository: str | None        # Homebrew: HOMEBREW_REPOSITORY
    cache_dir: str | None         # Homebrew: `brew --cache`, or the default when not drivable
    portdbpath: str | None        # MacPorts only
    applications_dir: str | None  # MacPorts only
    features: tuple[str, ...] = ()   # MacPorts: "migrate", "snapshot" (>= 2.10.0), "snapshot_export" (>= 2.11.0)
    owned_roots: tuple[str, ...] = ()  # the prefix, or Homebrew's own subtrees of /usr/local
    inventory_known: bool = True     # False when the registry cannot be read: the packages are unknown


@dataclass
class Service:
    """A launchd job that runs a manager's program: a package's own service, or a user's job"""

    label: str                       # sh.brew.mariadb, homebrew.mxcl.mysql, org.macports.prometheus
    plist: str
    scope: str                       # "user" (LaunchAgents) or "system" (LaunchDaemons)
    domain: str | None            # "gui/<uid>", "user/<uid>" or "system": where launchctl found the job, if loaded
    loaded: bool                     # from the tool's own launchctl probe
    running: bool                    # from the tool's own launchctl probe
    pid: int | None               # from the same probe, when running
    exit_timeout_s: int              # the plist's ExitTimeOut, 20 when absent
    owned: bool                      # made by a manager for a package, not a user's own job running a manager's binary
    data_dirs: list[str]             # the service's existing directories under <prefix>/var
    package: str | None           # owning formula, cask token or port name
    package_kind: str | None      # "formula", "cask", "port"
    instance_prefix: str             # the prefix whose program the plist runs
    program: str | None = None    # the plist's Program, else ProgramArguments[0], for the launchd findings


@dataclass
class Package:
    """An installed formula, cask or port, as its receipt and its manager's catalogue describe it"""

    instance_prefix: str             # key into ScanResult.instances
    kind: str                        # "formula", "cask", "port"
    name: str
    version: str                     # brew "1.8.2_1"; ports "1.8.2_0+x11"
    epoch: int                       # ports: PortIndex/registry epoch, 0 elsewhere
    spec_args: list[str]             # ports: ["name", "@1.8.2_0+x11"], two argv tokens; brew: [name]
    requested: bool | None        # None when the receipt lacks the field
    requested_variants: list[str]    # ports: the user's "+x11" "-quartz" choices
    active: bool                     # ports: state == "installed"; brew: linked or keg-only
    linked: bool | None
    keg_only: bool
    pinned: bool
    outdated: bool
    deprecated: bool
    disabled: bool
    catalogue_present: bool          # the manager's catalogue still knows the name
    renamed_to: str | None        # brew: formula_renames entry for this name
    origin: str                      # tap or ports tree source
    homepage: str | None
    description: str | None
    deps: list[str]                  # formula/port names; casks: their depends_on formulae
    cask_deps: list[str]             # casks: their depends_on cask tokens
    dependents: list[str]            # formula/port names and cask tokens that need this package
    executables: list[str]           # basenames under bin/ and sbin/ (brew: also opt/<name>/bin for keg-only)
    privileged_install: bool         # casks: installing may make brew call sudo
    privileged_uninstall: bool       # casks: uninstalling may make brew call sudo
    auto_updates: bool               # casks: the app updates itself; adoption skips the bundle check
    caskroom_data: list[str]         # casks: Caskroom/<token> entries other than .metadata and the version directories
    built_locally: bool | None    # brew: not poured_from_bottle; ports: non-default variants
    built_on_os: str | None       # "darwin 22" or "macOS 15.7"
    archs: list[str]
    services: list[Service]
    select_groups: list[str]
    receipt_ok: bool                 # brew receipt present; ports image present
    binaries: list[str] = field(default_factory=list)  # Mach-O paths, computed for the packages the linkage scan reads
    files: list[str] = field(default_factory=list)     # all owned paths, loaded on demand


@dataclass
class Action:
    """One step of a plan phase or a remedy: a command, a copy, a move, a write or a note"""

    action_id: str                   # "<phase>.<subject>.<step>" from what it acts on, so a resumed run finds it again
    kind: str                        # "command", "copy", "move", "write", "note"
    argv: list[str]                  # command: the program and its arguments, without sudo
    sudo: bool
    description: str
    env_profile: str = "neutral"     # "brew", "ports" or "neutral"
    on_failure: OnFailure = OnFailure.STOP
    retry_argv: list[str] = field(default_factory=list)  # RETRY_WITH: the alternative command
    split_order: list[str] = field(default_factory=list) # SPLIT: the names in retry order
    read_only: bool = False          # True: a probe that changes nothing
    timeout_s: int | None = None  # None: 120 when read_only, otherwise no timeout; a sudo command never has one
    manual: bool = False             # printed for the user, never executed
    src: str | None = None        # copy/move: source path
    dst: str | None = None        # copy/move/write: the destination; command: where its stdout goes on success
    content: str | None = None    # write: file content
    mode: str | None = None       # write: not read; a rewritten file keeps its own mode
    instance_prefix: str | None = None  # which brew/port binary runs it
    split_head: int = 0              # SPLIT: argv[:split_head] is the command, the rest are the batch's name groups
    new_session: bool = False        # a read-only probe run in its own session, without a controlling terminal


@dataclass
class Issue:
    """A doctor finding: its evidence, the remedies that clear it and the plans it blocks"""

    code: str                        # "brew-keg-without-receipt", "ports-missing-file": the family, then the name
    severity: Severity
    title: str
    subject: str | None           # package, path or service
    instance_prefix: str | None   # the instance the finding is about, when any
    evidence: list[str]
    remedies: list[Action]           # applied in order
    auto_fix: bool                   # applied by `doctor --fix` without a per-item prompt
    confirm_each: bool               # applied by `doctor --fix` after a per-item prompt
    repairs_install: bool            # applied by apply phase 2 when the subject is a plan target or its dependency
    blocks: tuple[Blocks, ...]       # the plan contexts this finding blocks while it holds


@dataclass
class Mapping:
    """The target package a source package maps to, and how sure the match is"""

    source: Package
    target_kind: str                 # "formula", "cask", "port", "pip", "npm", "gem", "cpan", "manual", "none"
    target_name: str | None
    target_version: str | None    # catalogue version the version gate accepted
    confidence: Confidence
    evidence: list[str]
    companions: list[str]            # extra target packages this mapping needs (py312-pip, clang-19, pipx)
    selections: list[tuple[str, str]]  # port select (group, option) pairs set in phase 7
    variants_note: str | None
    adopt: bool = False              # a source Homebrew cask the brew target adopts


@dataclass
class Phase:
    """One numbered phase of a plan; apply asks once before a phase whose `confirm` is set"""

    number: int
    name: str
    actions: list[Action]
    confirm: bool


@dataclass
class ScanResult:
    """Everything one scan found on the host, as scan.json holds it"""

    created: str
    system: dict[str, Any]
    instances: list[Instance]
    packages: list[Package]
    services: list[Service]
    environment: dict[str, Any]
    linkage: dict[str, Any]
    interpreter_extras: dict[str, Any]
    homebrew: dict[str, Any] = field(default_factory=dict)  # prefix -> raw Homebrew facts beside the packages
    macports: dict[str, Any] = field(default_factory=dict)  # prefix -> raw MacPorts facts beside the packages


@dataclass
class DoctorResult:
    """The doctor findings and the codes that block apply, as doctor.json holds them"""

    created: str
    issues: list[Issue]
    blocks_apply: dict[str, list[str]]  # "brew" / "ports" -> codes that block a plain plan with that target
    notes: list[str] = field(default_factory=list)  # checks skipped or degraded, from the scan and the detectors


@dataclass
class Plan:
    """A migration plan, as plan.json holds it: the package sets, the mappings and the phases"""

    created: str                     # ISO 8601
    run_id: str                      # run directory that holds this plan
    target: Manager
    instances: list[Instance]        # every instance, listed once
    source_prefixes: list[str]
    target_prefix: str
    roots: list[Package]
    kept: list[Package]              # packages the user keeps, with their closure
    left_in_place: list[Package]     # packages of an undrivable source instance that --remove-manager does not name
    mappings: list[Mapping]
    unmigratable: list[Mapping]
    removal_set: dict[str, list[tuple[str, str]]]  # drivable source prefix -> (kind, name) pairs; every version of each
    path_removed: dict[str, list[tuple[str, str]]]  # undrivable source prefix -> pairs phase 6 deletes with the prefix
    manual_casks: list[str]          # cask tokens of a drivable instance whose uninstall needs Homebrew's own sudo
    target_upgrades: list[str]       # target packages the installs will upgrade in place
    phases: list[Phase]
    options: dict[str, str]


PackageKey = tuple[str, str, str]   # (instance prefix, kind, name key)


def name_key(kind: str, name: str) -> str:
    """Return the key a name compares by: lower case for a port, as MacPorts matches them

    @param kind  formula, cask, `cask-adopted` or port
    @param name  a formula name, cask token or port name
    @returns     the name, in lower case for a port
    """
    return name.lower() if kind == "port" else name


def is_recorded_as(instance: Instance, text: str | None) -> bool:
    """Return whether `text` is, character for character, the instance's prefix or one of its recorded spellings

    @param instance  the instance
    @param text      a prefix as the plan or the journal records it, or None
    @returns         False for None or an empty text
    """
    return bool(text) and (text == instance.prefix or text in instance.spellings)


def to_plain(value: Any) -> Any:
    """Turn dataclasses, enums, tuples and sets into JSON-ready values

    @param value  a dataclass, or any value a dataclass field holds
    @returns      the value with enums by value, dataclasses as dicts, tuples as lists, sets as sorted lists
                  and dict keys as strings
    """
    if isinstance(value, enum.Enum):
        return value.value
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {f.name: to_plain(getattr(value, f.name)) for f in dataclasses.fields(value)}
    if isinstance(value, dict):
        return {str(to_plain(k)): to_plain(v) for k, v in value.items()}
    if isinstance(value, (set, frozenset)):
        return sorted(to_plain(v) for v in value)
    if isinstance(value, (list, tuple)):
        return [to_plain(v) for v in value]
    return value


def to_json(obj: Any) -> str:
    """Serialise a value as indented JSON with sorted keys

    @param obj  a dataclass, or any value `to_plain` accepts
    @returns    the JSON text
    """
    return json.dumps(to_plain(obj), indent=2, sort_keys=True)


_HINTS: dict[type, dict[str, Any]] = {}


def _hints(cls: type) -> dict[str, Any]:
    """Return a dataclass's field annotations, resolved from their strings once per class

    @param cls  a dataclass
    @returns    the field names mapped to their types
    """
    hints = _HINTS.get(cls)
    if hints is None:
        hints = typing.get_type_hints(cls)
        _HINTS[cls] = hints
    return hints


def _convert(tp: Any, value: Any) -> Any:
    """Convert a JSON value back to an annotated type

    @param tp     a field annotation, or one of its arguments
    @param value  the value `json.loads` produced
    @returns      the value as `tp` describes it; None stays None
    """
    if value is None or tp is Any:
        return value
    origin = typing.get_origin(tp)
    args = typing.get_args(tp)
    if origin is typing.Union:
        options = [a for a in args if a is not types.NoneType]
        return _convert(options[0], value) if len(options) == 1 else value
    if origin is list:
        item = args[0] if args else Any
        return [_convert(item, v) for v in value]
    if origin is tuple:
        if len(args) == 2 and args[1] is Ellipsis:
            return tuple(_convert(args[0], v) for v in value)
        if args:
            return tuple(_convert(a, v) for a, v in zip(args, value))
        return tuple(value)
    if origin is dict:
        value_type = args[1] if len(args) == 2 else Any
        return {k: _convert(value_type, v) for k, v in value.items()}
    if isinstance(tp, type):
        if issubclass(tp, enum.Enum):
            return value if isinstance(value, tp) else tp(value)
        if dataclasses.is_dataclass(tp):
            return value if isinstance(value, tp) else from_dict(tp, value)
    return value


def from_dict(cls: type, data: dict[str, Any]) -> Any:
    """Build a dataclass from a dict that `to_json` wrote; unknown keys are ignored

    @param cls              the dataclass
    @param data             the decoded JSON object; a key it lacks takes the field's default
    @returns                an instance of `cls`
    @throws TypeError       when `data` lacks a field that has no default, or a value has the wrong shape
    @throws ValueError      when a value names no member of its enum
    @throws AttributeError  when a dict field holds a list or a scalar
    """
    hints = _hints(cls)
    kwargs = {}
    for f in dataclasses.fields(cls):
        if f.name in data:
            kwargs[f.name] = _convert(hints[f.name], data[f.name])
    return cls(**kwargs)


def from_json(cls: type, text: str) -> Any:
    """Build a dataclass from the JSON text `to_json` wrote

    @param cls              the dataclass
    @param text             the JSON text
    @returns                an instance of `cls`
    @throws ValueError      when the text is not JSON, or a value names no member of its enum
    @throws TypeError       when the JSON lacks a field that has no default, or a value has the wrong shape
    @throws AttributeError  when a dict field holds a list or a scalar
    """
    return from_dict(cls, json.loads(text))
