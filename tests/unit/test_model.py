"""Tests of the model's JSON round trip"""

import collections
import json
import unittest

from brew_ports import model
from tests.unit.helpers import make_instance, make_package


def sample_plan() -> model.Plan:
    """Return a one-package plan whose fields hold enums, tuples and nested dataclasses

    @returns  a plan to MacPorts: wget with a service, its mapping and one install action
    """
    pkg = make_package("wget", services=[model.Service(
        label="sh.brew.wget", plist="/x.plist", scope="user", domain="gui/501", loaded=True, running=False,
        pid=None, exit_timeout_s=20, owned=True, data_dirs=[], package="wget", package_kind="formula",
        instance_prefix="/opt/homebrew")])
    mapping = model.Mapping(source=pkg, target_kind="port", target_name="wget", target_version="1.25.0",
                            confidence=model.Confidence.EXACT, evidence=["name"], companions=[],
                            selections=[("python3", "python313")], variants_note=None)
    action = model.Action(action_id="3.wget.install", kind="command", argv=["/opt/local/bin/port", "-N"],
                          sudo=True, description="install", on_failure=model.OnFailure.RETRY_WITH,
                          retry_argv=["x"], split_head=2)
    return model.Plan(
        created="2026-11-12T00:00:00+0000", run_id="20261112-000000-abcdef", target=model.Manager.PORTS,
        instances=[make_instance(features=("migrate",), owned_roots=("/opt/homebrew",))],
        source_prefixes=["/opt/homebrew"], target_prefix="/opt/local", roots=[pkg], kept=[], left_in_place=[],
        mappings=[mapping], unmigratable=[], removal_set={"/opt/homebrew": [("formula", "wget")]},
        path_removed={}, manual_casks=[], target_upgrades=[],
        phases=[model.Phase(number=3, name="install", actions=[action], confirm=True)], options={"casks": "keep"})


class ModelRoundTripTest(unittest.TestCase):
    """Tests of `to_json`, `from_json` and `from_dict` on plans, doctor results and instances"""

    def test_plan_round_trip_keeps_enums_and_tuples(self):
        plan = sample_plan()
        text = model.to_json(plan)
        back = model.from_json(model.Plan, text)
        self.assertEqual(back, plan)
        self.assertIs(back.target, model.Manager.PORTS)
        self.assertIsInstance(back.removal_set["/opt/homebrew"][0], tuple)
        self.assertIsInstance(back.instances[0].identity, tuple)
        self.assertIsInstance(back.instances[0].features, tuple)
        self.assertIsInstance(back.mappings[0].selections[0], tuple)
        self.assertIs(back.mappings[0].confidence, model.Confidence.EXACT)
        self.assertIs(back.phases[0].actions[0].on_failure, model.OnFailure.RETRY_WITH)
        self.assertEqual(back.phases[0].actions[0].split_head, 2)

    def test_issue_blocks_round_trip(self):
        issue = model.Issue(code="brew-unwritable-prefix", severity=model.Severity.HIGH, title="t", subject=None,
                            instance_prefix="/usr/local", evidence=[], remedies=[], auto_fix=False,
                            confirm_each=False, repairs_install=False,
                            blocks=(model.Blocks.TARGET, model.Blocks.UNINSTALL))
        result = model.DoctorResult(created="c", issues=[issue], blocks_apply={"brew": ["brew-unwritable-prefix"]})
        back = model.from_json(model.DoctorResult, model.to_json(result))
        self.assertEqual(back.issues[0].blocks, (model.Blocks.TARGET, model.Blocks.UNINSTALL))
        self.assertIs(back.issues[0].severity, model.Severity.HIGH)

    def test_json_is_sorted_and_plain(self):
        data = json.loads(model.to_json(make_instance()))
        self.assertEqual(data["manager"], "brew")
        self.assertEqual(data["usability"], "usable")
        self.assertEqual(data["identity"], [1, 2])

    def test_dict_subclass_values_serialise(self):
        """dataclasses.asdict fails on a defaultdict; to_json does not."""
        holder = model.ScanResult(created="c", system={}, instances=[], packages=[], services=[],
                                  environment=collections.defaultdict(list, {"a": [1]}), linkage={},
                                  interpreter_extras={})
        self.assertEqual(json.loads(model.to_json(holder))["environment"], {"a": [1]})

    def test_unknown_keys_are_ignored(self):
        data = json.loads(model.to_json(make_instance()))
        data["added_later"] = True
        self.assertEqual(model.from_dict(model.Instance, data).prefix, "/opt/homebrew")


if __name__ == "__main__":
    unittest.main()
