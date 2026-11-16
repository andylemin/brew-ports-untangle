"""The inventory of both managers and the environment, shared by `scan`, `doctor`, `recommend` and `plan`"""

from __future__ import annotations

import functools
import os
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from . import env, model, report, state, system
from .env import (interpreters as env_interpreters, linkage as env_linkage, services as env_services,
                  shell as env_shell)
from .homebrew import inventory as brew_inventory
from .homebrew.catalogue import Catalogue
from .macports import inventory as mp_inventory, locate as mp_locate, portindex as mp_portindex

BrewEntry = tuple[model.Instance, Catalogue | None, brew_inventory.HomebrewInventory]
PortsEntry = tuple[model.Instance, mp_portindex.PortIndex | None, mp_inventory.MacPortsInventory]


@dataclass
class ScanBundle:
    """A `ScanResult` together with the live objects it was built from"""

    result: model.ScanResult
    brew: list[BrewEntry] = field(default_factory=list)
    ports: list[PortsEntry] = field(default_factory=list)
    analysis: Any = None
    notes: list[str] = field(default_factory=list)

    def catalogue(self, prefix: str) -> Catalogue | None:
        """Return the offline catalogue of a Homebrew instance

        @param prefix  the instance's prefix
        @returns       the catalogue, or None when the scan holds none for that prefix
        """
        return next((cat for inst, cat, _ in self.brew if inst.prefix == prefix), None)

    def _homebrew(self, prefix: str) -> brew_inventory.HomebrewInventory | None:
        """Return the inventory of a Homebrew instance

        @param prefix  the instance's prefix, or one of its recorded spellings
        @returns       the inventory, or None when the scan holds none of the instance
        """
        return next((inv for inst, _, inv in self.brew if inv is not None and model.is_recorded_as(inst, prefix)),
                    None)

    def formula_racks(self, prefix: str) -> dict[str, str]:
        """Return the rack each formula of a Homebrew instance sits in, as its inventory matched them

        @param prefix  the instance's prefix, or one of its recorded spellings
        @returns       the rack's name by formula name; empty when the scan holds no inventory of the instance
        """
        inv = self._homebrew(prefix)
        return inv.racks() if inv is not None else {}

    def cask_rooms(self, prefix: str) -> dict[str, str]:
        """Return the Caskroom entry each cask of a Homebrew instance sits in, as its inventory matched them

        @param prefix  the instance's prefix, or one of its recorded spellings
        @returns       the entry's name by cask token; empty when the scan holds no inventory of the instance
        """
        inv = self._homebrew(prefix)
        return inv.rooms() if inv is not None else {}

    def portindex(self, prefix: str) -> mp_portindex.PortIndex | None:
        """Return the PortIndex of a MacPorts instance

        @param prefix  the instance's prefix
        @returns       the index, or None when the scan holds none for that prefix
        """
        return next((idx for inst, idx, _ in self.ports if inst.prefix == prefix), None)

    def macports(self, prefix: str) -> mp_inventory.MacPortsInventory | None:
        """Return the inventory of a MacPorts instance, whose registry copy stays open until `close`

        @param prefix  the instance's prefix
        @returns       the inventory, or None when the scan holds none for that prefix
        """
        return _macports_inventory(self.ports, prefix)

    def owner_of(self, path: str) -> str | None:
        """Return the port that registered a path, in whichever MacPorts instance

        @param path  an absolute path
        @returns     the port's name, or None when no registry lists the path
        """
        return _owner_of(self.ports, path)

    def close(self) -> None:
        """Close and remove the registry copies of the MacPorts inventories"""
        _close(self.ports)


def _macports_inventory(ports: Sequence[PortsEntry], prefix: str) -> mp_inventory.MacPortsInventory | None:
    """Return the inventory of the MacPorts instance at a prefix

    @param ports   the MacPorts entries of a scan
    @param prefix  the instance's prefix
    @returns       the inventory, or None when no entry has that prefix
    """
    return next((inv for inst, _, inv in ports if inst.prefix == prefix), None)


def _owner_of(ports: Sequence[PortsEntry], path: str) -> str | None:
    """Return the port that registered a path, in whichever MacPorts instance

    @param ports  the MacPorts entries of a scan
    @param path   an absolute path
    @returns      the port's name, or None when no registry lists the path
    """
    for _, _, inv in ports:
        owner = inv.owner_of(path)
        if owner:
            return owner
    return None


def _close(ports: Sequence[PortsEntry]) -> None:
    """Close and remove the registry copies of the MacPorts inventories

    @param ports  the MacPorts entries of a scan
    """
    for _, _, inv in ports:
        inv.close()



def _macports(runner, environ: Mapping[str, str], notes: list[str]) -> list[PortsEntry]:
    """Locate every MacPorts instance and take its inventory, with its PortIndex when one loads

    @param runner   the runner the probes go through
    @param environ  the environment the tool runs with
    @param notes    receives a note for each instance whose PortIndex fails to load
    @returns        one `(instance, index, inventory)` triple per instance
    """
    out: list[PortsEntry] = []
    for instance in mp_locate.find_instances(runner, environ, runner.host_arch):
        try:
            index = mp_portindex.load_for(instance, environ)
        except mp_portindex.PortIndexError as exc:
            index = None
            notes.append(f"{instance.prefix}: no PortIndex ({exc})")
        out.append((instance, index, mp_inventory.inventory(runner, instance, index, host_arch=runner.host_arch)))
    return out


def build(runner, environ: Mapping[str, str], deep: bool = False) -> ScanBundle:
    """Inventory every instance of both managers, then the services, shell setup, linkage and interpreter extras

    @param runner   the runner the probes go through
    @param environ  the environment the tool runs with
    @param deep     read the linkage of every formula, bottled ones included
    @returns        the bundle, whose caller closes it
    """
    facts = system.facts(runner)
    home = environ.get("HOME") or os.path.expanduser("~")
    notes: list[str] = []
    brew: list[BrewEntry] = list(brew_inventory.scan(runner, environ, runner.host_arch))
    ports = _macports(runner, environ, notes)
    # The scans below query the MacPorts registry copies, which stay open for the bundle's caller.
    owner_of = functools.partial(_owner_of, ports)
    try:
        instances = [inst for inst, _, _ in brew] + [inst for inst, _, _ in ports]
        packages = [p for _, _, inv in brew for p in inv.packages] + [p for _, _, inv in ports for p in inv.packages]
        labels: dict[str, str] = {}
        for _, catalogue, _ in brew:
            if catalogue is not None:
                labels.update(catalogue.service_labels())

        login = env_shell.login_shell(runner, facts["user"])
        analysis = env_shell.analyse(runner, home, dict(environ), instances, login)
        listings: dict[str, list[Any]] = {}
        for inst, _, _ in brew:
            listing = brew_inventory.services_listing(runner, inst) if inst.drivable else None
            if listing is not None:
                listings[inst.prefix] = listing
        racks = {inst.prefix: {rack: name for name, rack in inv.racks().items()} for inst, _, inv in brew}
        service_scan = env_services.inspect(runner, instances, packages, service_labels=labels, owner_of=owner_of,
                                            home=home, uid=facts["uid"], brew_services=listings, racks=racks)
        services = service_scan.services
        notes += service_scan.notes
        env_services.attach(services, packages)

        scanned = env_linkage.scan_set(packages, deep)
        for pkg in scanned:
            inv = _macports_inventory(ports, pkg.instance_prefix) if pkg.kind == "port" else None
            if inv is not None and not pkg.binaries:
                pkg.binaries = inv.binaries(pkg)
        linkage = env_linkage.scan(runner, env_linkage.binaries_by_package(scanned), instances)
        extras = env_interpreters.extras(instances, packages, home, owner_of=owner_of)

        result = model.ScanResult(
            created=state.now_iso(), system=facts, instances=instances, packages=packages, services=services,
            environment=model.to_plain(analysis), linkage=linkage, interpreter_extras=extras,
            homebrew={inst.prefix: {k: v for k, v in inv.to_plain().items() if k != "packages"}
                      for inst, _, inv in brew},
            macports={inst.prefix: inv.facts() for inst, _, inv in ports})
    except BaseException:   # the caller closes the bundle, unless the scan fails
        _close(ports)
        raise
    return ScanBundle(result=result, brew=brew, ports=ports, analysis=analysis, notes=notes)


REUSE_S = 600   # a scan younger than ten minutes is reused


def reusable_scan(state_dir: state.StateDir, now: float | None = None) -> str | None:
    """Return the newest `scan.json` when it is younger than ten minutes and no command changed the host since

    @param state_dir  the state directory
    @param now        the time in seconds since the epoch; None for the clock
    @returns          the path, or None when no run holds a scan, or the newest is older than ten minutes or than
                      the dirty marker
    """
    for run_id in reversed(state_dir.run_ids()):
        path = os.path.join(state_dir.runs, run_id, "scan.json")
        if not os.path.exists(path):
            continue
        age = (now if now is not None else time.time()) - os.stat(path).st_mtime
        if age < REUSE_S and not state_dir.older_than_dirty(path):
            return path
        return None
    return None


def load(path: str, runner, environ: Mapping[str, str]) -> ScanBundle:
    """Rebuild a bundle around a stored `scan.json`, reading each MacPorts registry again

    The detectors and the planner look up the registry rows, which `scan.json` does not hold.

    @param path     the stored `scan.json`
    @param runner   the runner the MacPorts probes go through
    @param environ  the environment the tool runs with
    @returns        the bundle, its MacPorts packages taken from the fresh inventories; its caller closes it
    """
    with open(path, encoding="utf-8") as fh:
        result = model.from_json(model.ScanResult, fh.read())
    notes: list[str] = []
    brew: list[BrewEntry] = []
    ports: list[PortsEntry] = []
    for inst in result.instances:
        if inst.manager is model.Manager.BREW:
            data = dict(result.homebrew.get(inst.prefix, {}))
            data["packages"] = [model.to_plain(p) for p in result.packages if p.instance_prefix == inst.prefix]
            brew.append((inst, Catalogue.load(inst, environ, runner.host_arch),
                         brew_inventory.HomebrewInventory.from_plain(data)))
    for inst in result.instances:
        if inst.manager is model.Manager.PORTS:
            try:
                index = mp_portindex.load_for(inst, environ)
            except mp_portindex.PortIndexError as exc:
                index = None
                notes.append(f"{inst.prefix}: no PortIndex ({exc})")
            ports.append((inst, index, mp_inventory.inventory(runner, inst, index, host_arch=runner.host_arch)))
    fresh = {inst.prefix for inst, _, _ in ports}
    result.packages = ([p for p in result.packages if p.instance_prefix not in fresh]
                       + [p for _, _, inv in ports for p in inv.packages])
    env_services.attach(result.services, result.packages)
    return ScanBundle(result=result, brew=brew, ports=ports, analysis=None, notes=notes)


def obtain(state_dir: state.StateDir, run_dir: state.RunDir | None, runner, environ: Mapping[str, str], *,
           rescan: bool = False, deep: bool = False) -> tuple[ScanBundle, bool]:
    """Return the scan `doctor`, `recommend` and `plan` work from

    The latest scan serves when it is reusable and `rescan` is false; otherwise a fresh one is written to `run_dir`.

    @param state_dir  the state directory, which holds the latest scan
    @param run_dir    the run directory a fresh scan is written to, or None
    @param runner     the runner the probes go through
    @param environ    the environment the tool runs with
    @param rescan     take a fresh scan even when the latest one is reusable
    @param deep       have a fresh scan read the linkage of every formula, bottled ones included
    @returns          `(bundle, reused)`
    """
    if not rescan:
        path = reusable_scan(state_dir)
        if path is not None:
            return load(path, runner, environ), True
    bundle = build(runner, environ, deep=deep)
    if run_dir is not None:
        write(bundle, run_dir)
    return bundle, False


def render(bundle: ScanBundle) -> list[str]:
    """Return the text output of `scan`

    @param bundle  a scan that `build` or `load` made, which holds a catalogue for every Homebrew instance
    @returns       the text lines
    """
    result = bundle.result
    lines = report.render_system(result.system)
    brew = [(inst, catalogue, inv) for inst, catalogue, inv in bundle.brew if catalogue is not None]
    if len(brew) != len(bundle.brew):
        raise ValueError("the scan holds no offline catalogue for one of its Homebrew instances")
    lines += brew_inventory.summary_lines(brew)
    for _, _, inv in bundle.ports:
        lines += mp_inventory.render_lines(inv)
    lines += env.render(result.environment, result.linkage, result.interpreter_extras, result.services)
    lines += [f"note: {n}" for n in bundle.notes]
    return lines


def write(bundle: ScanBundle, run_dir: state.RunDir) -> str:
    """Write `scan.json` and the requirements files of the interpreter extras

    @param bundle   the scan
    @param run_dir  the run directory that receives the files
    @returns        the path of `scan.json`
    """
    path = run_dir.write_json("scan.json", model.to_json(bundle.result))
    env_interpreters.write_requirements(run_dir.path, bundle.result.interpreter_extras)
    return path
