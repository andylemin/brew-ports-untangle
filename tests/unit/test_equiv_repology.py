"""The Repology client, its cache, its pace and its failures, and the Repology stage of the resolver"""

import json
import os
import unittest

from brew_ports import __version__, runner as runner_mod
from brew_ports.equiv import repology
from brew_ports.equiv.repology import Repology, query_url
from brew_ports.equiv.resolver import resolve
from brew_ports.model import Confidence, Manager
from tests.unit.fixtures.equiv.builders import brew_context, cask, formula, port, ports_context, web_runner
from tests.unit.helpers import TempDirTest

DAY = 86400.0
GSED = query_url("macports", "binname", "gsed")
GSED_PROJECT = [
    {"repo": "homebrew", "srcname": "gnu-sed", "binname": "gnu-sed", "visiblename": "gnu-sed", "version": "4.10",
     "status": "newest", "summary": "GNU implementation of the famous stream editor"},
    {"repo": "homebrew", "srcname": "gsed-legacy", "version": "4.2", "status": "legacy"},
    {"repo": "macports", "srcname": "textproc/gsed", "binname": "gsed", "version": "4.9", "status": "outdated"},
    {"repo": "homebrew_casks", "srcname": "sed-gui", "version": "1.0", "status": "unique"},
    {"repo": "homebrew", "srcname": "sed-ignored", "version": "1.0", "status": "ignored"},
]


class Clock:
    """Wall and monotonic time that only the test moves; `sleep` advances the monotonic clock"""

    def __init__(self):
        """Start both clocks at set times, with no sleep recorded"""
        self.now = 1800000000.0
        self.mono = 100.0
        self.slept = []

    def time(self):
        """Return the wall-clock time

        @returns  the seconds since the epoch
        """
        return self.now

    def monotonic(self):
        """Return the monotonic time

        @returns  the seconds
        """
        return self.mono

    def sleep(self, seconds):
        """Record a sleep, rounded to the millisecond, and move the monotonic clock on by it

        @param seconds  the length of the sleep
        """
        self.slept.append(round(seconds, 3))
        self.mono += seconds


class RepologyCase(TempDirTest):
    """The Repology tests' clock, their record of the curl argvs in `seen`, and their client"""

    def setUp(self):
        super().setUp()
        self.clock = Clock()
        self.seen = []

    def client(self, pages):
        """Return a Repology client whose curl reaches only `pages`, on the test's clock

        @param pages  the answers by URL
        @returns      the client
        """
        return Repology(web_runner(self.tmp, pages, self.seen), self.path("state"), self.path("downloads"),
                        clock=self.clock.time, monotonic=self.clock.monotonic, sleep=self.clock.sleep)


class ClientTest(RepologyCase):
    """The client: its requests, the eligible entries, the cache, the failures and the pace"""

    def test_query_runs_curl_with_the_user_agent(self):
        self.assertEqual(GSED, "https://repology.org/tools/project-by?repo=macports&name_type=binname&name=gsed"
                               "&target_page=api_v1_project")
        self.assertTrue(query_url("homebrew", "srcname", "python@3.12").endswith("name=python%403.12"
                                                                                 "&target_page=api_v1_project"))
        self.assertEqual(repology.USER_AGENT,
                         f"brew-ports/{__version__} (+https://github.com/andylemin/brew-ports-untangle)")
        self.client({GSED: GSED_PROJECT}).project("macports", "binname", "gsed")
        argv = self.seen[0]
        self.assertEqual(argv[:2], (runner_mod.CURL, "-q"))
        self.assertEqual(argv[argv.index("--user-agent") + 1], repology.USER_AGENT)
        self.assertEqual(argv[argv.index("--proto") + 1], "=https")
        self.assertIn("--fail", argv)
        self.assertIn("--location", argv)
        self.assertEqual(argv[-1], GSED)

    def test_candidates_are_eligible_target_entries(self):
        entries = self.client({GSED: GSED_PROJECT}).candidates(port("gsed", "4.9"), Manager.BREW)
        self.assertEqual([(e.kind, e.name, e.status) for e in entries],
                         [("formula", "gnu-sed", "newest"), ("cask", "sed-gui", "unique")])
        pages = {query_url("homebrew", "srcname", "gnu-sed"): GSED_PROJECT}
        entries = self.client(pages).candidates(formula("gnu-sed"), Manager.PORTS)
        self.assertEqual([(e.kind, e.name, e.version) for e in entries], [("port", "gsed", "4.9")])

    def test_answers_are_cached_in_the_state_directory(self):
        client = self.client({GSED: GSED_PROJECT})
        first = client.project("macports", "binname", "gsed")
        self.assertEqual(client.project("macports", "binname", "gsed"), first)
        self.assertEqual(len(self.seen), 1)
        with open(self.path("state", "repology-cache.json"), encoding="utf-8") as fh:
            cache = json.load(fh)
        self.assertEqual(cache["version"], 1)
        record = cache["entries"]["macports/binname/gsed"]
        self.assertEqual(record["fetched"], self.clock.now)
        self.assertEqual(set(record["packages"][0]), {"repo", "srcname", "binname", "version", "status"})
        self.assertEqual(self.client({}).project("macports", "binname", "gsed"), first)
        self.assertEqual(len(self.seen), 1)

    def test_the_cache_holds_for_30_days(self):
        client = self.client({GSED: GSED_PROJECT})
        client.project("macports", "binname", "gsed")
        self.clock.now += 29 * DAY
        client.project("macports", "binname", "gsed")
        self.assertEqual(len(self.seen), 1)
        self.clock.now += 2 * DAY
        client.project("macports", "binname", "gsed")
        self.assertEqual(len(self.seen), 2)

    def test_a_404_is_cached_as_no_project(self):
        client = self.client({})
        self.assertEqual(client.project("macports", "binname", "nosuch"), [])
        self.assertEqual(client.project("macports", "binname", "nosuch"), [])
        self.assertEqual((len(self.seen), client.failures), (1, 0))

    def test_three_failures_stop_and_none_is_cached(self):
        down = runner_mod.FakeResponse(exit=6, stderr="curl: (6) Could not resolve host: repology.org\n")
        client = self.client({query_url("macports", "binname", n): down for n in "abcd"})
        for name in "abc":
            self.assertIsNone(client.project("macports", "binname", name))
        self.assertTrue(client.stopped)
        self.assertIsNone(client.project("macports", "binname", "d"))
        self.assertEqual(len(self.seen), 3)
        self.assertEqual(client.error, "lookup of c failed: curl: (6) Could not resolve host: repology.org; "
                                       "no further Repology lookups")
        self.assertFalse(os.path.exists(self.path("state", "repology-cache.json")))

    def test_an_answer_resets_the_failure_count(self):
        down = runner_mod.FakeResponse(exit=7, stderr="curl: (7) Failed to connect\n")
        pages = {query_url("macports", "binname", "a"): down, query_url("macports", "binname", "b"): [],
                 query_url("macports", "binname", "c"): down, query_url("macports", "binname", "d"): down}
        client = self.client(pages)
        for name in "abcd":
            client.project("macports", "binname", name)
        self.assertEqual((client.failures, client.stopped), (2, False))

    def test_an_answer_without_a_list_is_a_failure(self):
        client = self.client({GSED: {"error": "unexpected"}})
        self.assertIsNone(client.project("macports", "binname", "gsed"))
        self.assertEqual(client.failures, 1)
        self.assertIn("not a package list", client.error)

    def test_requests_stay_one_second_apart(self):
        client = self.client({query_url("macports", "binname", n): [] for n in "abc"})
        client.project("macports", "binname", "a")
        self.clock.mono += 0.25
        client.project("macports", "binname", "b")
        self.clock.mono += 3.0
        client.project("macports", "binname", "c")
        client.project("macports", "binname", "a")          # cached: no request, no wait
        self.assertEqual(self.clock.slept, [0.75])
        self.assertEqual(client.requests, 3)


class RepologyStageTest(RepologyCase):
    """The resolver's Repology stage, which runs only under `--repology`"""

    def resolve_brew(self, pkg, pages):
        """Return the mapping of a package into the fixture Homebrew target, with Repology on `pages`

        @param pkg    the source package
        @param pages  Repology's answers by URL
        @returns      the mapping
        """
        return resolve(pkg, brew_context(self.tmp, repology=self.client(pages)))

    def test_repology_maps_what_the_offline_stages_miss(self):
        pages = {query_url("macports", "binname", "sed-gnu"): [
            {"repo": "homebrew", "srcname": "gnu-sed", "version": "4.10", "status": "newest"},
            {"repo": "macports", "srcname": "textproc/sed-gnu", "binname": "sed-gnu", "status": "newest"}]}
        m = self.resolve_brew(port("sed-gnu", "4.9"), pages)
        self.assertEqual((m.target_kind, m.target_name, m.confidence), ("formula", "gnu-sed", Confidence.HIGH))
        self.assertEqual(m.evidence[0], "repology: gnu-sed (newest)")

    def test_several_same_major_packages_are_medium(self):
        pages = {query_url("macports", "binname", "gcc-suite"): [
            {"repo": "homebrew", "srcname": "gcc", "status": "newest"},
            {"repo": "homebrew", "srcname": "gcc-tools", "status": "newest"}]}
        m = self.resolve_brew(port("gcc-suite", "15.1.0"), pages)
        self.assertEqual((m.target_name, m.confidence), ("gcc", Confidence.MEDIUM))
        self.assertTrue(any("gcc and gcc-tools share the source's major" in line for line in m.evidence))

    def test_legacy_entries_never_win(self):
        pages = {query_url("macports", "binname", "sed-gnu"): [
            {"repo": "homebrew", "srcname": "gnu-sed", "version": "4.10", "status": "legacy"}]}
        m = self.resolve_brew(port("sed-gnu", "4.9"), pages)
        self.assertEqual((m.target_name, m.confidence), (None, Confidence.NONE))
        self.assertIn("repology: no Homebrew package of this project in the catalogue", m.evidence)

    def test_a_package_the_catalogue_lacks_is_skipped(self):
        pages = {query_url("macports", "binname", "sed-gnu"): [
            {"repo": "homebrew", "srcname": "gsed-next", "status": "newest"}]}
        m = self.resolve_brew(port("sed-gnu", "4.9"), pages)
        self.assertIn("repology: formula gsed-next is not in the Homebrew catalogue", m.evidence)

    def test_a_failed_lookup_is_noted(self):
        down = runner_mod.FakeResponse(exit=7, stderr="curl: (7) Failed to connect to repology.org\n")
        m = self.resolve_brew(port("sed-gnu", "4.9"), {query_url("macports", "binname", "sed-gnu"): down})
        self.assertEqual(m.confidence, Confidence.NONE)
        self.assertIn("repology: lookup of sed-gnu failed: curl: (7) Failed to connect to repology.org", m.evidence)

    def test_a_cask_maps_to_an_app_port_through_repology(self):
        pages = {query_url("homebrew_casks", "srcname", "thunderbird"): [
            {"repo": "macports", "srcname": "mail/thunderbird-app", "binname": "thunderbird-app", "status": "newest"},
            {"repo": "macports", "srcname": "mail/thunderbird", "binname": "thunderbird", "status": "newest"}]}
        add = [{"name": "thunderbird-app", "version": "145.0"}, {"name": "thunderbird", "version": "145.0"}]
        ctx = ports_context(self.tmp, add=add, repology=self.client(pages))
        m = resolve(cask("thunderbird", "145.0"), ctx)
        self.assertEqual((m.target_kind, m.target_name, m.confidence), ("port", "thunderbird-app", Confidence.HIGH))

    def test_without_repology_nothing_is_fetched(self):
        ctx = brew_context(self.tmp, runner=web_runner(self.tmp, {}, self.seen))
        m = resolve(port("sed-gnu", "4.9"), ctx)
        self.assertEqual((m.confidence, self.seen), (Confidence.NONE, []))


if __name__ == "__main__":
    unittest.main()
