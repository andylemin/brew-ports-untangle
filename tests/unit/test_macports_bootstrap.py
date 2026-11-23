"""`bootstrap-ports`: the release asset, the signature check and the base package procedure against FakeRunner"""

import json
import os
import shutil
import stat
import unittest
from unittest import mock

from brew_ports import __version__, runner as r
from brew_ports.macports import bootstrap, locate
from brew_ports.model import Manager
from tests.unit.fixtures.macports.builders import fake_runner, read_fixture
from tests.unit.helpers import TempDirTest, make_instance, write_file

SIGNER = "Developer ID Installer: Joshua Root (QTA3A3B7F3)"
AGENT = "brew-ports/" + __version__     # how every download names the tool, at whatever version it is
TAHOE = "https://github.com/macports/macports-base/releases/download/v2.12.7/MacPorts-2.12.7-26-Tahoe.pkg"
TAG_PAGE = "https://github.com/macports/macports-base/releases/tag/v2.12.7"


def lstat_as_root(root, linked=()):
    """Return an `os.lstat` stand-in that reports the paths in `root` as owned by root when it is called

    @param root    the paths to report as root's; the set may change between calls
    @param linked  the paths to report with two links
    @returns       the stand-in, which passes every other path to the real `os.lstat`
    """
    real_lstat = os.lstat

    def lstat(target, *args, **kw):
        st = real_lstat(target, *args, **kw)
        path = os.fspath(target)
        if path not in root and path not in linked:
            return st
        fields = list(st[:10])
        fields[4] = 0 if path in root else fields[4]
        fields[3] = 2 if path in linked else fields[3]
        return os.stat_result(fields)
    return lstat


class AssetTest(unittest.TestCase):
    """The base package of the running macOS major, and the major of a version string"""

    def setUp(self):
        self.release = json.loads(read_fixture("release-latest.json"))

    def test_package_for_the_running_major(self):
        asset = bootstrap.choose_asset(self.release, 26)
        self.assertEqual((asset.name, asset.url, asset.version, asset.major),
                         ("MacPorts-2.12.7-26-Tahoe.pkg", TAHOE, "2.12.7", 26))
        self.assertEqual(bootstrap.choose_asset(self.release, 15).name, "MacPorts-2.12.7-15-Sequoia.pkg")

    def test_no_package_for_this_macos(self):
        with self.assertRaises(bootstrap.BootstrapError) as ctx:
            bootstrap.choose_asset(self.release, 14)
        self.assertIn("v2.12.7", str(ctx.exception))
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.choose_asset(self.release, 27)        # hosted outside the macports-base releases

    def test_macos_major(self):
        self.assertEqual(bootstrap.macos_major("15.7.1"), 15)
        self.assertEqual(bootstrap.macos_major("26.0"), 26)
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.macos_major(None)


class SignatureTest(unittest.TestCase):
    """The `pkgutil --check-signature` check against the pinned signers"""

    def setUp(self):
        self.text = read_fixture("pkgutil-check-signature.txt")

    def test_pinned_signer(self):
        self.assertIn(SIGNER, bootstrap.trusted_signers())
        self.assertEqual(bootstrap.check_signature(self.text, bootstrap.trusted_signers()), SIGNER)

    def test_other_signer_is_refused_and_the_chain_printed(self):
        other = self.text.replace("Joshua Root (QTA3A3B7F3)", "Mallory (ZZZZZZZZZZ)")
        with self.assertRaises(bootstrap.SignatureMismatch) as ctx:
            bootstrap.check_signature(other, [SIGNER])
        message = str(ctx.exception)
        self.assertIn("1. Developer ID Installer: Mallory (ZZZZZZZZZZ)", message)
        self.assertIn("3. Apple Root CA", message)
        self.assertIsInstance(ctx.exception, r.PreflightError)

    def test_each_required_line(self):
        for drop in (bootstrap.STATUS_LINE, bootstrap.NOTARY_LINE):
            with self.subTest(drop=drop):
                with self.assertRaises(bootstrap.SignatureMismatch):
                    bootstrap.check_signature(self.text.replace(drop, "Status: no signature"), [SIGNER])

    def test_the_signer_must_be_the_first_chain_line(self):
        reordered = self.text.replace("1. Developer ID Installer: Joshua Root (QTA3A3B7F3)", "1. Somebody Else") \
                             .replace("2. Developer ID Certification Authority", "2. " + SIGNER)
        with self.assertRaises(bootstrap.SignatureMismatch):
            bootstrap.check_signature(reordered, [SIGNER])
        with self.assertRaises(bootstrap.SignatureMismatch):
            bootstrap.check_signature("", [SIGNER])


class FakeRootFiles(r.RootFiles):
    """RootFiles that stage into a plain directory, without `sudo`, and count the staging removals"""

    def __init__(self, runner, directory):
        """Start with nothing staged and nothing removed

        @param runner     the runner, which the staging never uses
        @param directory  the directory that stands for the root staging directory
        """
        super().__init__(runner, "test")
        self.directory = directory
        self.staged = []
        self.removed = 0

    def stage(self, src, name, sha256=None):
        """Copy a file into the staging directory, as `RootFiles.stage` does without `sudo`

        @param src     the file to stage
        @param name    the name of the staged copy
        @param sha256  the digest `RootFiles.stage` verifies, ignored
        @returns       the path of the staged copy
        """
        os.makedirs(self.directory, exist_ok=True)
        dest = os.path.join(self.directory, name)
        shutil.copyfile(src, dest)
        self.staged.append(dest)
        return dest

    def remove_staging(self):
        """Count one removal of the staging directory"""
        self.removed += 1


class ProcedureTest(TempDirTest):
    """The base package procedure and `bootstrap` against FakeRunner, with curl writing its output file"""

    def setUp(self):
        super().setUp()
        self.run_dir = self.state_dir().new_run()
        self.files = FakeRootFiles(fake_runner(self.tmp), self.path("staging"))
        self.staged = os.path.join(self.files.directory, "MacPorts-2.12.7-26-Tahoe.pkg")

    def curl(self, url, payload):
        """Build a curl response that writes `payload` to the `--output` path, as curl does

        @param url      the URL the curl argv must end with
        @param payload  the text curl writes
        @returns        a FakeRunner response function of the argv
        """
        def respond(key):
            output = key[key.index("--output") + 1].replace("<run>", self.run_dir.path)
            with open(output, "w", encoding="utf-8") as fh:
                fh.write(payload)
            self.assertEqual(key[-1], url)
            return r.FakeResponse()
        return respond

    def responses(self, signature=None):
        """Return the FakeRunner responses of the whole procedure: release, download, signature and installer

        @param signature  the `pkgutil --check-signature` output; None reads the fixture
        @returns          the responses, keyed by argv
        """
        downloads = "<run>/downloads"
        base = r.curl_argv(bootstrap.RELEASE_URL, downloads + "/macports-base-release.json", user_agent=AGENT)
        pkg = r.curl_argv(TAHOE, downloads + "/MacPorts-2.12.7-26-Tahoe.pkg", user_agent=AGENT)
        return {
            tuple(base): self.curl(bootstrap.RELEASE_URL, read_fixture("release-latest.json")),
            tuple(pkg): self.curl(TAHOE, "xar! package bytes"),
            (r.SUDO, "-n", "--", "/usr/sbin/pkgutil", "--check-signature", self.staged):
                r.FakeResponse(stdout=signature or read_fixture("pkgutil-check-signature.txt")),
            (r.SUDO, "-n", "--", "/usr/sbin/installer", "-pkg", self.staged, "-target", "/"): r.FakeResponse(),
        }

    def runner(self, responses):
        """Return a FakeRunner in phase 0 with `sudo` ready, which fails every other command with exit 99

        @param responses  the responses, keyed by argv
        @returns          the runner
        """
        fake = fake_runner(self.tmp, responses, run_dir=self.run_dir, default=r.FakeResponse(exit=99))
        fake.phase = 0
        fake.sudo_ready = True
        return fake

    def refused(self, status, effective):
        """Return the procedure's responses with the GitHub API refusing the release read

        @param status     the HTTP status curl reports for the API
        @param effective  the URL curl ends at after the `releases/latest` redirect
        @returns          the responses, keyed by argv
        """
        api = r.curl_argv(bootstrap.RELEASE_URL, "<run>/downloads/macports-base-release.json", user_agent=AGENT)
        latest = r.curl_argv(bootstrap.LATEST_URL, "<run>/downloads/macports-base-latest.html", user_agent=AGENT)

        def page(key):
            output = key[key.index("--output") + 1].replace("<run>", self.run_dir.path)
            with open(output, "w", encoding="utf-8") as fh:
                fh.write("<html></html>\n")
            return r.FakeResponse(stdout=effective + "\n")
        responses = self.responses()
        responses[tuple(api)] = r.FakeResponse(exit=22,
                                               stderr=f"curl: (22) The requested URL returned error: {status}\n")
        responses[tuple(latest[:-1] + ["--write-out", "%{url_effective}", latest[-1]])] = page
        return responses

    def test_a_refused_api_falls_back_to_the_release_page_tag(self):
        for status in ("403", "429"):
            with self.subTest(status=status):
                fake = self.runner(self.refused(status, TAG_PAGE))
                asset = bootstrap.base_package_procedure(fake, self.run_dir, "26.1", files=self.files)
                self.assertEqual((asset.name, asset.url, asset.version, asset.major),
                                 ("MacPorts-2.12.7-26-Tahoe.pkg", TAHOE, "2.12.7", 26))
                self.assertEqual(len([c for c in fake.calls if "/usr/sbin/installer" in c]), 1)

    def test_a_refused_api_without_a_tag_or_a_package_name_stops(self):
        for effective, version, text in (("https://github.com/login", "26.1", "named no release tag"),
                                         (TAG_PAGE, "28.0", "macOS 28")):
            with self.subTest(effective=effective, version=version):
                with self.assertRaises(bootstrap.BootstrapError) as ctx:
                    bootstrap.base_package_procedure(self.runner(self.refused("403", effective)), self.run_dir,
                                                     version, files=self.files)
                self.assertIn(text, str(ctx.exception))
        self.assertEqual((self.files.staged, self.files.removed), ([], 0))

    def test_another_api_error_does_not_fall_back(self):
        fake = self.runner(self.refused("404", TAG_PAGE))
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.base_package_procedure(fake, self.run_dir, "26.1", files=self.files)
        self.assertFalse([c for c in fake.calls if bootstrap.LATEST_URL in c])

    def test_procedure_downloads_stages_checks_and_installs(self):
        fake = self.runner(self.responses())
        asset = bootstrap.base_package_procedure(fake, self.run_dir, "26.1", files=self.files)
        self.assertEqual(asset.name, "MacPorts-2.12.7-26-Tahoe.pkg")
        with open(self.run_dir.sub("downloads", asset.name), encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "xar! package bytes")
        self.assertEqual(self.files.staged, [self.staged])
        self.assertEqual(self.files.removed, 1)
        installer = [c for c in fake.calls if "/usr/sbin/installer" in c]
        check = [i for i, c in enumerate(fake.calls) if "--check-signature" in c]
        self.assertEqual(len(installer), 1)
        self.assertLess(check[0], fake.calls.index(installer[0]))
        self.assertIn(self.staged, installer[0])

    def test_wrong_signer_installs_nothing_and_cleans_up(self):
        bad = read_fixture("pkgutil-check-signature.txt").replace("Joshua Root (QTA3A3B7F3)", "Mallory (ZZZZZZZZZZ)")
        fake = self.runner(self.responses(signature=bad))
        with self.assertRaises(bootstrap.SignatureMismatch):
            bootstrap.base_package_procedure(fake, self.run_dir, "26.1", files=self.files)
        self.assertFalse([c for c in fake.calls if "/usr/sbin/installer" in c])
        self.assertEqual(self.files.removed, 1)

    def test_failed_release_read_stops_before_anything_changes(self):
        fake = self.runner({})
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.base_package_procedure(fake, self.run_dir, "26.1", files=self.files)
        self.assertEqual((self.files.staged, self.files.removed), ([], 0))

    def test_bootstrap_syncs_and_binds_the_new_instance(self):
        prefix = self.path("opt", "local")
        os.makedirs(prefix)
        st = os.stat(prefix)
        new = make_instance(Manager.PORTS, prefix=prefix, identity=(st.st_dev, st.st_ino), arch="arm64",
                            binary=os.path.join(prefix, "bin", "port"))
        responses = self.responses()
        sync = (r.SUDO, "-n", "--", r.ARCH, "-arm64", os.path.join(prefix, "bin", "port"), "-N", "sync")
        responses[sync] = r.FakeResponse()
        fake = self.runner(responses)
        with mock.patch.object(locate, "find_instances", return_value=[new]) as find:
            found = bootstrap.bootstrap(fake, self.run_dir, {"HOME": self.path("home")}, "arm64",
                                        macos_version="26.1", files=self.files, default_prefix=prefix)
        self.assertIs(found, new)
        self.assertEqual(find.call_count, 2)
        self.assertIn(sync, fake.calls)
        with mock.patch.object(locate, "find_instances", return_value=[]):
            with self.assertRaises(bootstrap.BootstrapError) as ctx:
                bootstrap.bootstrap(self.runner(self.responses()), self.run_dir, {}, "arm64", macos_version="26.1",
                                    files=self.files, default_prefix=prefix)
        self.assertIn("no instance was found", str(ctx.exception))

    def test_bootstrap_gives_back_shell_files_left_to_root(self):
        home, prefix = self.path("home"), self.path("opt", "local")
        os.makedirs(prefix)
        st = os.stat(prefix)
        new = make_instance(Manager.PORTS, prefix=prefix, identity=(st.st_dev, st.st_ino), arch="arm64",
                            binary=os.path.join(prefix, "bin", "port"))
        bash, profile, zsh, tcsh = (os.path.join(home, name)
                                    for name in (".bash_profile", ".profile", ".zprofile", ".tcshrc"))
        for path in (bash, profile):
            write_file(path, "export EDITOR=vi\n")
        root = {profile}                 # owned by root before the install
        linked = {tcsh}
        written = {}                     # path -> (inode, text) as the postflight left it

        def postflight(_key):
            """Write the shell files as the installer's postflight does under sudo, leaving them owned by root

            @param _key  the installer's argv
            @returns     a success
            """
            for path in (bash, zsh, tcsh):
                with open(path, "a", encoding="utf-8") as fh:
                    fh.write("export PATH=/opt/local/bin:/opt/local/sbin:$PATH\n")
            os.chmod(bash, 0o640)
            for path in (bash, zsh, tcsh):
                with open(path, encoding="utf-8") as fh:
                    written[path] = (os.stat(path).st_ino, fh.read())
            root.update((bash, zsh, tcsh))
            return r.FakeResponse()
        responses = self.responses()
        responses[(r.SUDO, "-n", "--", "/usr/sbin/installer", "-pkg", self.staged, "-target", "/")] = postflight
        responses[(r.SUDO, "-n", "--", r.ARCH, "-arm64", new.binary, "-N", "sync")] = r.FakeResponse()
        fake = self.runner(responses)
        with mock.patch.object(bootstrap.os, "lstat", side_effect=lstat_as_root(root, linked)), \
                mock.patch.object(locate, "find_instances", return_value=[new]):
            bootstrap.bootstrap(fake, self.run_dir, {"HOME": home, "USER": "alice"}, "arm64", macos_version="26.1",
                                files=self.files, default_prefix=prefix)
        self.assertEqual([c for c in fake.calls if any("chown" in part for part in c)], [])
        text = fake.console.stream.getvalue()
        for path in (bash, zsh):
            inode, content = written[path]
            self.assertNotEqual(os.stat(path).st_ino, inode)          # the user's copy took the name
            with open(path, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), content)
            self.assertIn(f"gave {path} back to alice", text)
        self.assertEqual(stat.S_IMODE(os.stat(bash).st_mode), 0o640)
        self.assertEqual(os.stat(tcsh).st_ino, written[tcsh][0])
        self.assertIn(f"left {tcsh} alone", text)
        self.assertNotIn(profile, text)
        self.assertEqual(sorted(os.listdir(home)), [".bash_profile", ".profile", ".tcshrc", ".zprofile"])

    def test_describe(self):
        steps = bootstrap.describe(26)
        self.assertTrue(any("MacPorts-<version>-26-<name>.pkg" in s for s in steps))
        self.assertTrue(any(SIGNER in s for s in steps))
        self.assertTrue(any(bootstrap.LATEST_URL in s for s in steps))
        self.assertTrue(any("left owned by root" in s for s in steps))
        self.assertFalse(any("chown" in s for s in steps))


if __name__ == "__main__":
    unittest.main()
