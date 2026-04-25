# ndrift

ndrift is a lightweight Linux file integrity monitor.

It builds a trusted baseline of file metadata and content hashes, then compares future scans to detect drift such as modified files, added files, deleted files, permission changes, ownership changes, timestamp only changes, and filesystem attribute changes.

## What ndrift does

1. Recursively scans one or more monitored directories.
2. Applies include rules and exclude rules to control scan scope.
3. Stores a signed baseline in local JSON files.
4. Detects drift on each scan with both console output and JSON output.
5. Writes logs with rotation.
6. Supports periodic scan mode with an interval loop.
7. Supports deployment approval workflow for safe baseline updates.
8. Returns script friendly exit codes.

## How ndrift works

### 1. Baseline creation

On init or baseline update, ndrift records per file data:

1. absolute path
2. size
3. mtime in nanoseconds
4. SHA256 content hash
5. mode bits
6. uid and gid
7. owner and group names
8. lsattr flags when available

The baseline file includes additional integrity data:

1. baseline schema version
2. monitored directory list
3. configuration file hash
4. ndrift program hash
5. creation timestamp
6. baseline reason text

### 2. Baseline signing and verification

ndrift signs the canonical baseline JSON payload with HMAC SHA256 and writes a detached signature file.

1. Baseline JSON path default: /var/lib/ndrift/ndrift-baseline.json
2. Detached signature path default: /var/lib/ndrift/ndrift-baseline.json.sig
3. Secret signing key path default: /var/lib/ndrift/ndrift-baseline.key

On scan, signature verification runs before drift detection. If verification fails, ndrift returns exit code 2.

### 3. Scan process

Each scan executes these phases:

1. Load configuration.
2. Validate monitored paths.
3. Verify baseline signature.
4. Recalculate config hash and program hash, compare with baseline.
5. Build current snapshot.
6. Compare current snapshot to baseline.
7. Emit findings, warnings, errors, and summary.
8. Persist latest report JSON.
9. Trigger optional integrations.

### 4. Drift types emitted

1. ADDED
2. DELETED
3. MODIFIED
4. MOD_PERMS
5. MOD_OWNER
6. MOD_ATTR
7. MOD_TIME
8. MOD_CONFIG
9. MOD_PROGRAM

### 5. Performance behavior

ndrift includes simple, effective optimizations:

1. If hash on metadata change only is true, hash reuse occurs when size and mtime are unchanged.
2. If file size exceeds max file size mb, ndrift records a size limit sentinel instead of hashing content.
3. throttle ms can slow scan pace to reduce host impact.

### 6. Optional rolling baseline mode

If scan_updates_baseline is true, ndrift updates baseline after each scan.

1. New changes are typically reported once.
2. Later scans compare against the most recent scan state.
3. This mode is useful for low noise monitoring workflows.
4. This mode is less strict than fixed baseline monitoring.

## Installation

### Requirements

1. Linux
2. Python 3
3. optional: lsattr for filesystem attribute checks
4. optional: AWS CLI for object storage report upload

### Local install in project directory

~~~bash
chmod +x ./ndrift
./ndrift init /path/to/monitor --config ./ndrift-config.conf
~~~

### Optional system wide install

~~~bash
sudo install -o root -g root -m 0755 ./ndrift /usr/local/bin/ndrift
sudo install -d -o root -g root -m 0700 /var/lib/ndrift
sudo install -d -o root -g root -m 0750 /var/log/ndrift
sudo install -d -o root -g root -m 0755 /etc/ndrift
sudo install -o root -g root -m 0600 ./ndrift-config.conf /etc/ndrift/ndrift.conf
~~~

### Default runtime paths on single tenant hosts

1. executable: /usr/local/bin/ndrift
2. config: /etc/ndrift/ndrift.conf
3. baseline: /var/lib/ndrift/ndrift-baseline.json
4. signature: /var/lib/ndrift/ndrift-baseline.json.sig
5. signing key: /var/lib/ndrift/ndrift-baseline.key
6. state: /var/lib/ndrift/ndrift-state.json
7. last report: /var/lib/ndrift/ndrift-report.json
8. log: /var/log/ndrift/ndrift.log

## Quick start

### Create baseline

~~~bash
/usr/local/bin/ndrift init /path/to/monitor --config /etc/ndrift/ndrift.conf
~~~

### Run scan

~~~bash
/usr/local/bin/ndrift scan --config /etc/ndrift/ndrift.conf
~~~

### Run scan with JSON output

~~~bash
/usr/local/bin/ndrift scan --json --config /etc/ndrift/ndrift.conf
~~~

### Run continuous watch mode

~~~bash
/usr/local/bin/ndrift watch --interval 60 --config /etc/ndrift/ndrift.conf
~~~

### Print latest report

~~~bash
/usr/local/bin/ndrift report --config /etc/ndrift/ndrift.conf
~~~

## Command reference

1. init: creates baseline and signature, also writes state audit event
2. scan: verifies signature and compares current state with baseline
3. update-baseline: rebuilds baseline with required reason text
4. report: prints the latest saved report
5. watch: runs periodic scans in loop
6. deploy-start: opens deployment window
7. approve: records deployment approval reason
8. deploy-end: closes deployment window
9. cron: prints a cron entry using the configured schedule

## Configuration documentation

System default config path: /etc/ndrift/ndrift.conf.

Template in this repository: [ndrift-config.conf](ndrift-config.conf).

### Core path settings

1. directories: comma separated monitored roots
2. baseline_path: trusted baseline JSON path
3. signature_path: detached signature path
4. signature_key_path: HMAC key path
5. state_path: deployment and audit state path
6. last_report_path: latest scan report path
7. log_path: rotating log file path

### Scan scope and behavior settings

1. include_patterns: comma separated glob rules for files to scan
2. exclude_patterns: comma separated rules for content to skip
3. follow_symlinks: true or false
4. max_file_size_mb: hash size ceiling in MB
5. hash_on_metadata_change_only: true or false
6. throttle_ms: delay per file in milliseconds

### Scheduler and alert settings

1. cron_schedule: schedule expression for cron helper output
2. email_to: alert mailbox
3. smtp_host: SMTP relay
4. slack_webhook: webhook URL
5. s3_bucket: object storage destination for report upload

### Error policy

1. allow_read_errors false: treat file read failures as exit code 2
2. allow_read_errors true: continue scan and include errors in report

### Baseline refresh policy

1. scan_updates_baseline false: keep a fixed baseline until init or update-baseline
2. scan_updates_baseline true: write a new baseline after each scan so repeated ADDED alerts are reduced

## Exit codes

1. 0: scan completed with no findings
2. 1: scan completed and findings were detected
3. 2: runtime error, integrity verification failure, or strict read error condition

## Report format

Each scan writes a JSON report to last report path with:

1. time
2. directories
3. summary
4. findings
5. warnings
6. errors
7. stats

Example console style output:

~~~text
[MODIFIED] /path/to/file.php hash changed
[MOD_PERMS] /path/to/file.php 0644 -> 0666
{"MODIFIED": 1, "MOD_PERMS": 1}
~~~

## Deployment approval workflow

Use this workflow to allow expected changes while preserving auditability.

~~~bash
/usr/local/bin/ndrift deploy-start --config /etc/ndrift/ndrift.conf
/usr/local/bin/ndrift approve --reason "planned release" --config /etc/ndrift/ndrift.conf
/usr/local/bin/ndrift update-baseline --reason "post release baseline" --require-signature --config /etc/ndrift/ndrift.conf
/usr/local/bin/ndrift deploy-end --config /etc/ndrift/ndrift.conf
~~~

During active deployment mode, baseline update requires at least one approval after deployment start.

## Cron integration

Generate a schedule line:

~~~bash
/usr/local/bin/ndrift cron --config /etc/ndrift/ndrift.conf
~~~

Then place the output into the desired cron context.

## Security details

### Built in safeguards

1. baseline signature verification before scan comparison
2. baseline write operations use atomic replace
3. baseline, signature, and key files are written with mode 600
4. baseline location warning if placed inside monitored roots
5. symlink following disabled by default
6. configuration file hash drift detection
7. program hash drift detection
8. install posture warnings if program is not root owned or writable by group or others
9. strict exit codes for automation and alert pipelines

### Recommended hardening for operators

1. run ndrift using a dedicated low privilege account
2. grant read access to monitored files only as needed
3. deny write access to baseline, signature, and key for non root users
4. install ndrift in a root owned read only location
5. store config and state in protected directories
6. ship logs and reports to central monitoring
7. test alert channels and error paths routinely

### Security caveats

1. Baseline signing currently uses a local symmetric key. If key material is compromised, signature trust is compromised.
2. Program hash checks can detect drift, but do not replace package signature verification.
3. Email, Slack, and object storage integrations depend on network and external credential security.
4. scan_updates_baseline true reduces repeated alerts, but also reduces strict persistence of change evidence across scans.

## Project files

1. [ndrift](ndrift): executable CLI program
2. [ndrift-config.conf](ndrift-config.conf): default configuration template
