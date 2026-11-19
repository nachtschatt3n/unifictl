#!/usr/bin/env python3
"""Offline negative tests for the audit and release publication gates."""
import hashlib
import importlib.util
import os
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True

WORKFLOWS = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("release_contract", WORKFLOWS / "release_contract.py")
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)


class SupplyChainTests(unittest.TestCase):
    def test_audit_fails_closed_on_installation_and_execution_errors(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cargo = root / "cargo"
            cargo.write_text('''#!/usr/bin/env bash
set -euo pipefail
if [ "$INSTALL_EXIT" != 0 ]; then exit "$INSTALL_EXIT"; fi
while [ "$1" != --root ]; do shift; done
mkdir -p "$2/bin"
cat > "$2/bin/cargo-audit" <<'SH'
#!/usr/bin/env bash
if [ "$1" = --version ]; then echo cargo-audit-test; exit 0; fi
exit "$AUDIT_EXIT"
SH
chmod +x "$2/bin/cargo-audit"
''')
            cargo.chmod(0o700)
            for install, audit in [(0, 0), (1, 0), (101, 0), (127, 0), (0, 1), (0, 101), (0, 127)]:
                with self.subTest(install=install, audit=audit):
                    env = dict(os.environ, PATH=f"{root}:{os.environ['PATH']}", RUNNER_TEMP=str(root),
                               INSTALL_EXIT=str(install), AUDIT_EXIT=str(audit))
                    result = subprocess.run(["bash", str(WORKFLOWS / "audit.sh"), str(root / "audit.json")],
                                            env=env, capture_output=True, text=True)
                    self.assertEqual(result.returncode, install or audit, result.stderr)

    def test_all_workflows_run_strict_audit(self):
        for name in ["ci.yml", "test.yml", "release.yml"]:
            source = (WORKFLOWS / name).read_text()
            self.assertIn('run: bash .github/workflows/audit.sh "$RUNNER_TEMP/audit.json"', source)
            self.assertIn("path: ${{ runner.temp }}/audit.json", source)
            self.assertIn("cargo clippy --locked --all-targets --all-features -- -D warnings", source)
            self.assertNotIn("continue-on-error:", source)
        ci = (WORKFLOWS / "ci.yml").read_text()
        self.assertLess(ci.index("run: bash .github/workflows/audit.sh"), ci.index("run: cargo package --locked"))
        source = (WORKFLOWS / "release.yml").read_text()
        self.assertNotIn("if: always() &&", source)
        self.assertIn("needs: [validate, build-release, build-arch-packages, build-deb-packages]", source)
        self.assertIn("needs: [validate, verify-artifacts]", source)
        # GitHub first, crates.io only after the GitHub release succeeded.
        self.assertIn("needs: [validate, create-release]", source)
        self.assertNotIn("publish-crates-io]", source)

    def test_audit_evidence_keeps_package_clean(self):
        real_cargo = shutil.which("cargo")
        self.assertIsNotNone(real_cargo, "Cargo is required for the packaging regression")
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = base / "crate"
            root.mkdir()
            (root / "src").mkdir()
            (root / "src/lib.rs").write_text("pub fn fixture() -> bool { true }\n")
            (root / "Cargo.toml").write_text(
                '[package]\nname = "audit-package-fixture"\nversion = "0.0.0"\n'
                'edition = "2024"\ndescription = "Isolated packaging regression"\n'
                'license = "MIT"\nrepository = "https://example.invalid/fixture"\n'
            )
            (root / ".gitignore").write_text("/target/\n")
            scripts = root / ".github/workflows"
            scripts.mkdir(parents=True)
            shutil.copyfile(WORKFLOWS / "audit.sh", scripts / "audit.sh")
            runtime = base / "runtime"
            runtime.mkdir()
            tools = base / "tools"
            tools.mkdir()
            cargo = tools / "cargo"
            cargo.write_text('''#!/usr/bin/env bash
set -euo pipefail
if [ "$1" != install ]; then exec "$REAL_CARGO" "$@"; fi
while [ "$1" != --root ]; do shift; done
mkdir -p "$2/bin"
cat > "$2/bin/cargo-audit" <<'SH'
#!/usr/bin/env bash
if [ "$1" = --version ]; then echo cargo-audit-fixture; else echo '{"synthetic":true}'; fi
SH
chmod +x "$2/bin/cargo-audit"
''')
            cargo.chmod(0o700)
            env = dict(os.environ, PATH=f"{tools}:{os.environ['PATH']}", REAL_CARGO=real_cargo,
                       RUNNER_TEMP=str(runtime), CARGO_TARGET_DIR=str(root / "target"))

            def run(*args):
                return subprocess.run(args, cwd=root, env=env, capture_output=True, text=True)

            for args in [
                ("git", "init", "-q"),
                ("git", "config", "user.name", "Packaging fixture"),
                ("git", "config", "user.email", "fixture@example.invalid"),
                ("cargo", "generate-lockfile", "--offline"),
                ("git", "add", "."),
                ("git", "-c", "commit.gpgsign=false", "commit", "-qm", "Fixture"),
            ]:
                result = run(*args)
                self.assertEqual(result.returncode, 0, result.stderr)

            for name in ["ci.yml", "test.yml", "release.yml"]:
                command = next(line.split("run: ", 1)[1] for line in
                               (WORKFLOWS / name).read_text().splitlines()
                               if "run: bash .github/workflows/audit.sh" in line)
                result = run("bash", "-e", "-o", "pipefail", "-c", command)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue((runtime / "audit.json").is_file())
                self.assertEqual(run("git", "status", "--porcelain").stdout, "")

            result = run("cargo", "package", "--offline", "--locked")
            self.assertEqual(result.returncode, 0, result.stderr)
            # This control proves the test detects the original release blocker.
            shutil.copyfile(runtime / "audit.json", root / "audit.json")
            result = run("cargo", "package", "--offline", "--locked")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("audit.json", result.stderr)

    def test_reject_invalid_or_mismatched_release_identity(self):
        for tag in ["", "1.2.3", "v1.2", "v01.2.3", "v1.2.3;false", "v1.2.3\nextra=x"]:
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                contract.version_from_tag(tag)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            def git(*args):
                return subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)
            git("init", "-q")
            git("config", "user.name", "Release gate test")
            git("config", "user.email", "test@example.invalid")
            (root / "Cargo.toml").write_text('[package]\nversion = "1.2.3"\n')
            git("add", "Cargo.toml")
            git("commit", "-qm", "Fixture")
            git("tag", "v1.2.3")
            self.assertEqual(contract.validate_identity(root, "v1.2.3")["version"], "1.2.3")
            with self.assertRaises(ValueError):
                contract.validate_identity(root, "v1.2.4")
            git("commit", "--allow-empty", "-qm", "Another commit")
            with self.assertRaises(ValueError):
                contract.validate_identity(root, "v1.2.3")

    def test_asset_manifest_rejects_missing_empty_duplicate_and_extra_files(self):
        for defect in [None, "missing", "empty", "duplicate", "extra", "symlink"]:
            with self.subTest(defect=defect), tempfile.TemporaryDirectory() as temp:
                root = Path(temp); source = root / "artifacts"; source.mkdir()
                names = sorted(contract.expected_assets("1.2.3"))
                for name in names:
                    (source / name).write_bytes(b"synthetic artifact\n")
                first = source / names[0]
                if defect == "missing": first.unlink()
                if defect == "empty": first.write_bytes(b"")
                if defect == "duplicate":
                    (source / "second").mkdir(); (source / "second" / names[0]).write_bytes(b"duplicate")
                if defect == "extra": (source / "unexpected.zip").write_bytes(b"extra")
                if defect == "symlink":
                    first.unlink(); first.symlink_to(source / names[1])
                lock = root / "Cargo.lock"; lock.write_bytes(b"synthetic lockfile\n")
                args = (source, root / "dist", "v1.2.3", "a" * 40, lock)
                if defect:
                    with self.assertRaises(ValueError): contract.assemble_assets(*args)
                    self.assertFalse((root / "dist").exists())
                else:
                    contract.assemble_assets(*args)
                    for line in (root / "dist" / "checksums.txt").read_text().splitlines():
                        digest, name = line.split("  ")
                        self.assertEqual(digest, hashlib.sha256((root / "dist" / name).read_bytes()).hexdigest())
                    with self.assertRaises(FileExistsError): contract.assemble_assets(*args)


    def test_public_release_is_not_overwritten_and_api_failure_blocks(self):
        for draft, blocked in [(True, False), (False, True)]:
            response = ('[[{"tag_name":"v1.2.3","draft":' + str(draft).lower() + '}]]').encode()
            with patch.object(contract.subprocess, "check_output", return_value=response):
                if blocked:
                    with self.assertRaises(ValueError): contract.reject_public_release("owner/repo", "v1.2.3")
                else:
                    contract.reject_public_release("owner/repo", "v1.2.3")
        with patch.object(contract.subprocess, "check_output", side_effect=subprocess.CalledProcessError(1, "gh")):
            with self.assertRaises(subprocess.CalledProcessError):
                contract.reject_public_release("owner/repo", "v1.2.3")

    def test_publication_rejects_partial_or_changed_uploads(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); expected = root / "dist"; uploaded = root / "published"
            expected.mkdir(); uploaded.mkdir()
            (expected / "a.zip").write_bytes(b"verified")
            with self.assertRaises(ValueError): contract.compare_published_assets(expected, uploaded)
            (uploaded / "a.zip").write_bytes(b"corrupted")
            with self.assertRaises(ValueError): contract.compare_published_assets(expected, uploaded)
            (uploaded / "a.zip").write_bytes(b"verified")
            contract.compare_published_assets(expected, uploaded)
            (uploaded / "extra.zip").write_bytes(b"unexpected")
            with self.assertRaises(ValueError): contract.compare_published_assets(expected, uploaded)


if __name__ == "__main__":
    unittest.main()
