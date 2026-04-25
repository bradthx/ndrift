# Copyright (c) 2026 Brad Boegler <bradthx@gmail.com>
# Licensed under the MIT License. See LICENSE.
import configparser
import importlib.util
import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from importlib.machinery import SourceFileLoader
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
NDRIFT_PATH = ROOT / "ndrift"


def load_ndrift_module():
    """Loads ndrift script as a Python module for unit level tests."""
    module_name = "ndrift_module_for_tests"
    loader = SourceFileLoader(module_name, str(NDRIFT_PATH))
    spec = importlib.util.spec_from_loader(module_name, loader)
    if spec is None:
        raise RuntimeError("Failed to build spec for ndrift module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    loader.exec_module(module)
    return module


NDRIFT_MODULE = load_ndrift_module()


def build_config_file(config_path: Path, site_dir: Path, overrides=None):
    """Creates a config file that writes all artifacts into a temp area."""
    state_dir = config_path.parent / "state"
    log_dir = config_path.parent / "log"
    state_dir.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)

    values = {
        "directories": str(site_dir),
        "include_patterns": "*.php,*.js,*.html,*.css",
        "exclude_patterns": "cache/,logs/,uploads/tmp/,.git/",
        "baseline_path": str(state_dir / "ndrift-baseline.json"),
        "signature_path": str(state_dir / "ndrift-baseline.json.sig"),
        "signature_key_path": str(state_dir / "ndrift-baseline.key"),
        "state_path": str(state_dir / "ndrift-state.json"),
        "last_report_path": str(state_dir / "ndrift-report.json"),
        "log_path": str(log_dir / "ndrift.log"),
        "log_max_bytes": "1048576",
        "log_backup_count": "3",
        "follow_symlinks": "false",
        "max_file_size_mb": "50",
        "hash_on_metadata_change_only": "true",
        "throttle_ms": "0",
        "cron_schedule": "*/5 * * * *",
        "email_to": "",
        "smtp_host": "localhost",
        "slack_webhook": "",
        "s3_bucket": "",
        "allow_read_errors": "false",
        "scan_updates_baseline": "false",
    }
    if overrides:
        values.update(overrides)

    parser = configparser.ConfigParser()
    parser["ndrift"] = values
    with open(config_path, "w", encoding="utf-8") as handle:
        parser.write(handle)
    os.chmod(config_path, 0o600)
    return values


def update_config_value(config_path: Path, key: str, value: str):
    """Updates one config setting in place."""
    parser = configparser.ConfigParser()
    parser.read(config_path, encoding="utf-8")
    parser["ndrift"][key] = value
    with open(config_path, "w", encoding="utf-8") as handle:
        parser.write(handle)


def run_ndrift(args, config_path: Path, timeout=20):
    """Runs ndrift subprocess with config argument appended."""
    full_args = [str(item) for item in args]
    if "--config" not in full_args:
        full_args.extend(["--config", str(config_path)])
    cmd = [sys.executable, str(NDRIFT_PATH)] + full_args
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


class NdriftIntegrationTests(unittest.TestCase):
    """End to end tests for command behavior and expected findings."""

    def setUp(self):
        self.temp_dir_ctx = tempfile.TemporaryDirectory(prefix="ndrift_tests_")
        self.temp_dir = Path(self.temp_dir_ctx.name)
        self.site_dir = self.temp_dir / "site"
        self.site_dir.mkdir(parents=True, exist_ok=True)
        self.config_path = self.temp_dir / "ndrift.conf"
        self.config_values = build_config_file(self.config_path, self.site_dir)

    def tearDown(self):
        self.temp_dir_ctx.cleanup()

    def _write(self, relative_path: str, content: str):
        path = self.site_dir / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def _init_baseline(self):
        result = run_ndrift(["init", str(self.site_dir)], self.config_path)
        self.assertEqual(
            result.returncode,
            0,
            msg=f"init failed\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}",
        )
        return result

    def _update_baseline(self, reason: str):
        result = run_ndrift(
            ["update-baseline", str(self.site_dir), "--reason", reason],
            self.config_path,
        )
        self.assertEqual(
            result.returncode,
            0,
            msg=f"update-baseline failed\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}",
        )

    def test_init_creates_expected_artifacts(self):
        self._write("index.php", "<?php echo 1;\n")
        self._init_baseline()

        for key in [
            "baseline_path",
            "signature_path",
            "signature_key_path",
            "state_path",
        ]:
            self.assertTrue(Path(self.config_values[key]).exists(), msg=f"missing {key}")

    def test_scan_detects_added_modified_deleted_and_permission_changes(self):
        index_file = self._write("index.php", "<?php echo 1;\n")
        self._init_baseline()

        self._write("new.php", "<?php echo 2;\n")
        added = run_ndrift(["scan", str(self.site_dir)], self.config_path)
        self.assertEqual(added.returncode, 1)
        self.assertIn("[ADDED]", added.stdout)
        self._update_baseline("accept added file")

        index_file.write_text("<?php echo 3;\n", encoding="utf-8")
        modified = run_ndrift(["scan", str(self.site_dir)], self.config_path)
        self.assertEqual(modified.returncode, 1)
        self.assertIn("[MODIFIED]", modified.stdout)
        self._update_baseline("accept modified file")

        os.chmod(index_file, 0o600)
        perms = run_ndrift(["scan", str(self.site_dir)], self.config_path)
        self.assertEqual(perms.returncode, 1)
        self.assertIn("[MOD_PERMS]", perms.stdout)
        self._update_baseline("accept permission change")

        index_file.unlink()
        deleted = run_ndrift(["scan", str(self.site_dir)], self.config_path)
        self.assertEqual(deleted.returncode, 1)
        self.assertIn("[DELETED]", deleted.stdout)

    def test_scan_json_and_report_json_outputs(self):
        self._write("index.php", "<?php echo 1;\n")
        self._init_baseline()
        self._write("new.php", "<?php echo 2;\n")

        scan = run_ndrift(["scan", str(self.site_dir), "--json"], self.config_path)
        self.assertEqual(scan.returncode, 1)
        scan_json = json.loads(scan.stdout)
        self.assertIn("findings", scan_json)
        self.assertIn("summary", scan_json)
        self.assertTrue(any(item.get("type") == "ADDED" for item in scan_json["findings"]))

        report = run_ndrift(["report", "--json"], self.config_path)
        self.assertEqual(report.returncode, 0)
        report_json = json.loads(report.stdout)
        self.assertIn("findings", report_json)

    def test_scan_detects_timestamp_only_change(self):
        index = self._write("index.php", "<?php echo 1;\n")
        self._init_baseline()

        time.sleep(0.02)
        os.utime(index, None)
        scan = run_ndrift(["scan", str(self.site_dir)], self.config_path)
        self.assertEqual(scan.returncode, 1)
        self.assertIn("[MOD_TIME]", scan.stdout)

    def test_scan_detects_config_drift(self):
        self._write("index.php", "<?php echo 1;\n")
        self._init_baseline()

        update_config_value(self.config_path, "throttle_ms", "1")
        scan = run_ndrift(["scan", str(self.site_dir)], self.config_path)
        self.assertEqual(scan.returncode, 1)
        self.assertIn("[MOD_CONFIG]", scan.stdout)

    def test_scan_fails_on_tampered_baseline_signature(self):
        self._write("index.php", "<?php echo 1;\n")
        self._init_baseline()

        baseline_path = Path(self.config_values["baseline_path"])
        baseline_path.write_text(baseline_path.read_text(encoding="utf-8") + " ", encoding="utf-8")

        scan = run_ndrift(["scan", str(self.site_dir)], self.config_path)
        self.assertEqual(scan.returncode, 2)
        self.assertIn("Cannot verify signature", scan.stderr)

    def test_update_baseline_require_signature_fails_on_tamper(self):
        self._write("index.php", "<?php echo 1;\n")
        self._init_baseline()

        baseline_path = Path(self.config_values["baseline_path"])
        baseline_path.write_text(baseline_path.read_text(encoding="utf-8") + " ", encoding="utf-8")
        result = run_ndrift(
            [
                "update-baseline",
                str(self.site_dir),
                "--reason",
                "tamper check",
                "--require-signature",
            ],
            self.config_path,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("Cannot verify signature", result.stderr)

    def test_deploy_mode_requires_approval_for_baseline_update(self):
        self._write("index.php", "<?php echo 1;\n")
        self._init_baseline()
        self._write("new.php", "<?php echo 2;\n")

        start = run_ndrift(["deploy-start"], self.config_path)
        self.assertEqual(start.returncode, 0)

        blocked = run_ndrift(
            ["update-baseline", str(self.site_dir), "--reason", "pending deploy"],
            self.config_path,
        )
        self.assertEqual(blocked.returncode, 2)
        self.assertIn("requires approval", blocked.stderr)

        approve = run_ndrift(["approve", "--reason", "approved deploy"], self.config_path)
        self.assertEqual(approve.returncode, 0)

        allowed = run_ndrift(
            ["update-baseline", str(self.site_dir), "--reason", "approved update"],
            self.config_path,
        )
        self.assertEqual(allowed.returncode, 0)

        end = run_ndrift(["deploy-end"], self.config_path)
        self.assertEqual(end.returncode, 0)

    def test_include_and_exclude_rules(self):
        self._write("index.php", "<?php echo 1;\n")
        self._init_baseline()

        self._write("new.txt", "ignored\n")
        self._write("new.php", "<?php echo 2;\n")
        self._write("logs/skip.php", "<?php echo 3;\n")
        scan = run_ndrift(["scan", str(self.site_dir)], self.config_path)

        self.assertEqual(scan.returncode, 1)
        self.assertIn("new.php", scan.stdout)
        self.assertNotIn("new.txt", scan.stdout)
        self.assertNotIn("logs/skip.php", scan.stdout)

    def test_allow_read_errors_controls_scan_exit_behavior(self):
        self._write("index.php", "<?php echo 1;\n")
        self._init_baseline()

        unreadable = self._write("unreadable.php", "<?php echo 2;\n")
        os.chmod(unreadable, 0)
        try:
            strict_scan = run_ndrift(["scan", str(self.site_dir)], self.config_path)
            self.assertEqual(strict_scan.returncode, 2)
        finally:
            os.chmod(unreadable, stat.S_IRUSR | stat.S_IWUSR)

        with tempfile.TemporaryDirectory(prefix="ndrift_allow_read_errors_") as td:
            temp_dir = Path(td)
            site_dir = temp_dir / "site"
            site_dir.mkdir(parents=True, exist_ok=True)
            config_path = temp_dir / "ndrift.conf"
            build_config_file(
                config_path,
                site_dir,
                overrides={"allow_read_errors": "true"},
            )

            (site_dir / "index.php").write_text("<?php echo 1;\n", encoding="utf-8")
            init = run_ndrift(["init", str(site_dir)], config_path)
            self.assertEqual(init.returncode, 0)

            unreadable_permissive = site_dir / "unreadable.php"
            unreadable_permissive.write_text("<?php echo 2;\n", encoding="utf-8")
            os.chmod(unreadable_permissive, 0)
            try:
                permissive_scan = run_ndrift(["scan", str(site_dir)], config_path)
                self.assertEqual(permissive_scan.returncode, 0)
                self.assertIn("[ERROR] Permission denied", permissive_scan.stdout)
            finally:
                os.chmod(unreadable_permissive, stat.S_IRUSR | stat.S_IWUSR)

    def test_max_file_size_limit_warning(self):
        update_config_value(self.config_path, "max_file_size_mb", "1")
        update_config_value(self.config_path, "hash_on_metadata_change_only", "false")
        big_file = self._write("large.php", "a" * (2 * 1024 * 1024))
        self.assertTrue(big_file.exists())
        self._init_baseline()

        scan = run_ndrift(["scan", str(self.site_dir)], self.config_path)
        self.assertEqual(scan.returncode, 0)
        self.assertIn("Files above max size limit: 1", scan.stdout)

    def test_scan_updates_baseline_reports_change_once(self):
        update_config_value(self.config_path, "scan_updates_baseline", "true")
        self._write("index.php", "<?php echo 1;\n")
        self._init_baseline()

        self._write("test.html", "<html></html>\n")
        first = run_ndrift(["scan", str(self.site_dir)], self.config_path)
        second = run_ndrift(["scan", str(self.site_dir)], self.config_path)

        self.assertEqual(first.returncode, 1)
        self.assertIn("[ADDED]", first.stdout)
        self.assertEqual(second.returncode, 0)
        self.assertNotIn("[ADDED]", second.stdout)

    def test_cron_output_uses_config_schedule(self):
        update_config_value(self.config_path, "cron_schedule", "*/7 * * * *")
        cron = run_ndrift(["cron"], self.config_path)

        self.assertEqual(cron.returncode, 0)
        self.assertTrue(cron.stdout.strip().startswith("*/7 * * * *"))
        self.assertIn(str(self.config_path), cron.stdout)

    def test_watch_mode_runs_and_stops(self):
        self._write("index.php", "<?php echo 1;\n")
        self._init_baseline()

        command = [
            sys.executable,
            str(NDRIFT_PATH),
            "watch",
            str(self.site_dir),
            "--interval",
            "1",
            "--config",
            str(self.config_path),
        ]
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            time.sleep(1.5)
            proc.send_signal(signal.SIGINT)
            stdout, stderr = proc.communicate(timeout=8)
        finally:
            if proc.poll() is None:
                proc.kill()

        self.assertEqual(
            proc.returncode,
            0,
            msg=f"watch returned {proc.returncode}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        )


class NdriftUnitLogicTests(unittest.TestCase):
    """Logic tests for snapshot comparison helpers."""

    def test_compare_snapshots_covers_all_main_finding_types(self):
        baseline = {
            "/root/old.php": {
                "size": 10,
                "mtime_ns": 10,
                "sha256": "oldhash",
                "mode": "0644",
                "owner": "user",
                "group": "group",
                "attrs": "----------------",
            },
            "/root/time.php": {
                "size": 10,
                "mtime_ns": 10,
                "sha256": "samehash",
                "mode": "0644",
                "owner": "user",
                "group": "group",
                "attrs": "----------------",
            },
            "/root/deleted.php": {
                "size": 1,
                "mtime_ns": 1,
                "sha256": "x",
                "mode": "0644",
                "owner": "user",
                "group": "group",
                "attrs": "----------------",
            },
        }

        current = {
            "/root/old.php": {
                "size": 10,
                "mtime_ns": 11,
                "sha256": "newhash",
                "mode": "0600",
                "owner": "other",
                "group": "other",
                "attrs": "----i-----------",
            },
            "/root/time.php": {
                "size": 10,
                "mtime_ns": 12,
                "sha256": "samehash",
                "mode": "0644",
                "owner": "user",
                "group": "group",
                "attrs": "----------------",
            },
            "/root/added.php": {
                "size": 1,
                "mtime_ns": 1,
                "sha256": "z",
                "mode": "0644",
                "owner": "user",
                "group": "group",
                "attrs": "----------------",
            },
        }

        findings = NDRIFT_MODULE.compare_snapshots(baseline, current)
        kinds = {item["type"] for item in findings}

        expected = {
            "ADDED",
            "DELETED",
            "MOD_PERMS",
            "MOD_OWNER",
            "MOD_ATTR",
            "MODIFIED",
            "MOD_TIME",
        }
        self.assertTrue(expected.issubset(kinds), msg=f"missing kinds: {expected - kinds}")

    def test_should_include_and_exclude_helpers(self):
        self.assertTrue(NDRIFT_MODULE.should_include("a/b/c.php", ["*.php"]))
        self.assertFalse(NDRIFT_MODULE.should_include("a/b/c.txt", ["*.php"]))
        self.assertTrue(NDRIFT_MODULE.should_exclude("logs/app.php", ["logs/"]))
        self.assertTrue(NDRIFT_MODULE.should_exclude("tmp.cache", ["*.cache"]))
        self.assertFalse(NDRIFT_MODULE.should_exclude("app/index.php", ["logs/"]))

    def test_program_hash_finding_can_be_detected(self):
        with tempfile.TemporaryDirectory(prefix="ndrift_prog_hash_") as td:
            temp_dir = Path(td)
            site_dir = temp_dir / "site"
            site_dir.mkdir(parents=True, exist_ok=True)
            config_path = temp_dir / "ndrift.conf"
            values = build_config_file(config_path, site_dir)
            (site_dir / "index.php").write_text("<?php echo 1;\n", encoding="utf-8")

            init = run_ndrift(["init", str(site_dir)], config_path)
            self.assertEqual(init.returncode, 0)

            baseline_path = Path(values["baseline_path"])
            signature_path = Path(values["signature_path"])
            key_path = Path(values["signature_key_path"])

            baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
            baseline["program_hash"] = "0" * 64
            payload = NDRIFT_MODULE.baseline_to_bytes(baseline)
            signature = NDRIFT_MODULE.sign_payload(payload, key_path.read_bytes())

            baseline_path.write_text(payload.decode("utf-8"), encoding="utf-8")
            signature_path.write_text(signature + "\n", encoding="utf-8")

            scan = run_ndrift(["scan", str(site_dir)], config_path)
            self.assertEqual(scan.returncode, 1)
            self.assertIn("[MOD_PROGRAM]", scan.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)