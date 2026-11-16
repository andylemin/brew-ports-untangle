"""The blocking rule over each plan context, the phase 6 exemption and `blocks_apply`"""

import unittest

from brew_ports import doctor
from brew_ports.model import Blocks, Manager, Severity
from tests.unit.helpers import make_instance, make_package

BREW, INTEL, PORTS = "/opt/homebrew", "/usr/local", "/opt/local"
CLT, UNWRITABLE, DEGRADED = "system-clt-missing", "brew-unwritable-prefix", "brew-degraded-inventory"
DAMAGED, BUSY, VERSIONS = "ports-damaged-registry", "ports-registry-busy", "brew-several-versions"


def blocker(code, prefix, *blocks, severity=Severity.HIGH):
    """Return a finding, titled with its name, that blocks the given plan contexts

    @param code      the finding's name
    @param prefix    the instance it is about, or None
    @param blocks    the plan contexts it blocks
    @param severity  HIGH, or CRITICAL for a finding that blocks every plan
    @returns         the finding
    """
    return doctor._issue(code, severity, code, None, prefix, blocks=blocks)


class BlockingTest(unittest.TestCase):
    """Which findings block each plan context, and what blocks a plain plan per target"""

    def setUp(self):
        self.issues = [
            blocker(CLT, None, Blocks.ANY),
            blocker(UNWRITABLE, INTEL, Blocks.TARGET, Blocks.UNINSTALL),
            blocker(DEGRADED, INTEL, Blocks.TARGET, Blocks.CASKS, Blocks.REMOVE),
            blocker(DAMAGED, PORTS, Blocks.TARGET, Blocks.REMOVE),
            blocker(BUSY, PORTS, severity=Severity.CRITICAL),
            blocker(VERSIONS, BREW, severity=Severity.LOW),
        ]

    def codes(self, **kw):
        """Return the names of the findings that block a plan context

        @param kw  the `PlanContext` fields; the target prefix defaults to None
        @returns   the names, in the order of `issues`
        """
        kw.setdefault("target_prefix", None)
        return [i.code for i in doctor.blocking(self.issues, doctor.PlanContext(**kw))]

    def test_any_and_critical_always(self):
        self.assertEqual(self.codes(), [CLT, BUSY])

    def test_target(self):
        self.assertEqual(self.codes(target_prefix=INTEL), [CLT, UNWRITABLE, DEGRADED, BUSY])
        self.assertEqual(self.codes(target_prefix=PORTS), [CLT, DAMAGED, BUSY])
        self.assertEqual(self.codes(target_prefix=BREW), [CLT, BUSY])

    def test_casks_uninstall_and_remove(self):
        self.assertEqual(self.codes(target_prefix=BREW, cask_prefixes=(INTEL,)), [CLT, DEGRADED, BUSY])
        self.assertEqual(self.codes(target_prefix=BREW, uninstall_prefixes=(INTEL,)), [CLT, UNWRITABLE, BUSY])
        self.assertEqual(self.codes(target_prefix=BREW, remove_prefixes=(INTEL, PORTS)), [CLT, DEGRADED, DAMAGED, BUSY])
        # A context about another instance does not apply.
        self.assertEqual(self.codes(target_prefix=BREW, uninstall_prefixes=(PORTS,)), [CLT, BUSY])

    def test_phase6_exempts_every_issue_of_its_instance(self):
        self.assertEqual(self.codes(target_prefix=BREW, remove_prefixes=(PORTS,), exempt_prefixes=(PORTS,)), [CLT])
        self.assertEqual(self.codes(target_prefix=BREW, remove_prefixes=(INTEL,), exempt_prefixes=(PORTS,)),
                         [CLT, DEGRADED])

    def test_blocks_apply_per_target(self):
        instances = [make_instance(Manager.BREW, BREW), make_instance(Manager.BREW, INTEL),
                     make_instance(Manager.PORTS, PORTS)]
        packages = [make_package("a", prefix=INTEL), make_package("b", kind="port", prefix=PORTS)]
        got = doctor.blocks_apply(self.issues, instances, packages=packages,
                                  targets={"brew": BREW, "ports": PORTS})
        # brew: /usr/local and /opt/local are uninstalled from; ports: /opt/local is the target.
        self.assertEqual(got, {"brew": [CLT, UNWRITABLE, BUSY], "ports": [CLT, UNWRITABLE, DAMAGED, BUSY]})

    def test_blocks_apply_skips_empty_or_undrivable(self):
        instances = [make_instance(Manager.BREW, BREW), make_instance(Manager.BREW, INTEL, drivable=False)]
        got = doctor.blocks_apply(self.issues, instances, packages=[make_package("a", prefix=INTEL)],
                                  targets={"brew": BREW, "ports": None})
        self.assertEqual(got, {"brew": [CLT, BUSY], "ports": [CLT, BUSY]})
        none_held = doctor.blocks_apply(self.issues, instances[:1] + [make_instance(Manager.BREW, INTEL)],
                                        packages=[], targets={"brew": BREW, "ports": None})
        self.assertEqual(none_held["brew"], [CLT, BUSY])


if __name__ == "__main__":
    unittest.main()
