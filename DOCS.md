# Clockwork — Documentation

In-depth reference for `clockwork.py`. For a quick overview and install steps, see the [README](README.md).

> **Authorized use only.** Clockwork is a security-testing tool. Only run it against systems you own or have explicit, written permission to test. Unauthorized access to computer systems is illegal in most jurisdictions.

---

## Table of contents

- [Overview](#overview)
- [Requirements & installation](#requirements--installation)
- [Execution model](#execution-model)
- [Command-line reference](#command-line-reference)
- [Targets file format](#targets-file-format)
- [Authentication](#authentication)
- [Running a command (`-c`)](#running-a-command--c)
- [Enumeration (`--enum`)](#enumeration---enum)
- [Privilege-escalation checks (`--privesc`)](#privilege-escalation-checks---privesc)
- [OS detection & non-Linux hosts](#os-detection--non-linux-hosts)
- [Looting files (`--loot-dir`)](#looting-files---loot-dir)
- [Severity model & finding catalog](#severity-model--finding-catalog)
- [The report file](#the-report-file)
- [Console output](#console-output)
- [Exit codes](#exit-codes)
- [Performance & tuning](#performance--tuning)
- [Security & operational considerations](#security--operational-considerations)
- [Limitations & known trade-offs](#limitations--known-trade-offs)
- [Troubleshooting](#troubleshooting)

---

## Overview

Clockwork takes **one username** plus **one secret** (a password *or* a private key) and tries it against a **list of hosts**, concurrently. For every host that authenticates, it can optionally:

1. run an arbitrary command,
2. check for passwordless sudo,
3. enumerate high-value files (`--enum`),
4. run lightweight privilege-escalation checks (`--privesc`),
5. download the flagged files over SFTP (`--loot-dir`).

All results are streamed to the console and written to a single plain-text report, with the most important findings ("quick wins") summarized at the top.

Clockwork is a single self-contained script with one dependency (`paramiko`). It does not use an external configuration file — everything is driven by command-line flags.

---

## Requirements & installation

- **Python 3.7+**
- **paramiko** (`pip install paramiko`)

```bash
pip install paramiko
python3 clockwork.py -h
```

If `paramiko` is missing, Clockwork exits immediately with an install hint rather than a traceback.

---

## Execution model

Understanding the order of operations helps interpret the output.

**Per host, inside one worker thread (`try_host`):**

1. **Connect & authenticate** — `paramiko.SSHClient.connect()` with `timeout`, `banner_timeout`, and `auth_timeout` all set to `--timeout`. `look_for_keys` and `allow_agent` are disabled so *only* the credential you supplied is used (no accidental fallback to your local SSH agent or `~/.ssh` keys). Unknown host keys are auto-accepted (see [security notes](#security--operational-considerations)).
2. **Command** (`-c`) — run if supplied; failures here are isolated and never abort the following steps.
3. **Sudo check** (`--check-sudo`) — `sudo -n -l`.
4. **Enumeration** (`--enum` / `--privesc`) — a single bundled payload (see below).

**Concurrency:** hosts are dispatched to a `ThreadPoolExecutor` with `--workers` threads. Results are collected in the main thread as each host finishes, so console lines never interleave. The final report re-sorts results back into the original targets-file order.

**Enumeration payload:** when `--enum` and/or `--privesc` is set, all checks are assembled into **one read-only POSIX-sh script**, executed in a single SSH `exec`, and its output is split on random-token section markers (`###<token>:SECTION###`). The random token makes an accidental collision with real file or command output effectively impossible. Findings are derived and severity-tagged locally in Python. **Nothing is written to the target.**

---

## Command-line reference

Synopsis:

```
python3 clockwork.py -t TARGETS -u USER (-p PASSWORD | -k KEYFILE) [options]
```

### Targets & authentication

| Flag | Type / default | Description |
|------|----------------|-------------|
| `-t`, `--targets FILE` | path, **required** | File of target hosts, one per line. |
| `-u`, `--username USER` | string, **required** | The single SSH username tried against every target. |
| `-p`, `--password PASS` | string | Password authentication. Mutually exclusive with `-k`. |
| `-k`, `--keyfile PATH` | path | Private-key authentication. Mutually exclusive with `-p`. |
| `--key-passphrase PASS` | string | Passphrase to decrypt an encrypted `--keyfile`. |

Exactly one of `-p` / `-k` is required.

### Post-login actions

| Flag | Type / default | Description |
|------|----------------|-------------|
| `-c`, `--command CMD` | string | Command run on each successful login; stdout/stderr captured in the report. |
| `--check-sudo` | flag | Detect passwordless (NOPASSWD) sudo via `sudo -n -l`. |
| `--enum` | flag | Read-only host-context + high-value file enumeration. |
| `--privesc` | flag | Read-only lightweight privilege-escalation checks. |
| `--loot-dir DIR` | path | SFTP-download flagged files into `DIR/<host>/`. Implies `--enum`. |
| `--loot-max-bytes N` | int, `5000000` | Skip loot files larger than `N` bytes. |

### Connection & output

| Flag | Type / default | Description |
|------|----------------|-------------|
| `--port N` | int, `22` | SSH port used for every target. |
| `--timeout N` | int, `10` | Per-host connect/auth timeout, seconds. Enumeration gets a longer internal budget automatically. |
| `--workers N` | int, `20` | Maximum hosts checked concurrently. |
| `-o`, `--output FILE` | path | Report path. Default `clockwork_<timestamp>.txt` in the current directory. |
| `--no-color` | flag | Disable ANSI colors. Also auto-disabled when output is not a TTY or `NO_COLOR` is set. |

`--workers`, `--timeout`, and `--loot-max-bytes` must be ≥ 1 or Clockwork exits with a usage error.

---

## Targets file format

- One host (IP or hostname) per line.
- Leading/trailing whitespace is stripped.
- Blank lines are ignored.
- Lines beginning with `#` are treated as comments and ignored.
- Duplicate entries are removed while preserving first-seen order.

The port is **not** taken per-line; it is global via `--port`. Inline comments (`10.0.0.5 # note`) are **not** supported — only whole-line comments.

```
# production web tier
10.0.0.11
10.0.0.12
app-01.internal
```

---

## Authentication

**Password** (`-p`) and **key** (`-k`) are mutually exclusive.

**Key types** are auto-detected by trying, in order: Ed25519, RSA, ECDSA, DSA. If the key is encrypted, supply `--key-passphrase`; Clockwork reports a clear "key is encrypted" message rather than a misleading parse error. A missing key file is reported before any connection is attempted.

**Host keys** are accepted automatically (`AutoAddPolicy`) so runs never block on an interactive fingerprint prompt. This means Clockwork does **not** verify host identity and will not detect a man-in-the-middle — acceptable for controlled testing, but worth knowing.

**Isolation:** `look_for_keys=False` and `allow_agent=False` guarantee the result reflects *only* the credential you passed — no silent fallback to local agent keys.

---

## Running a command (`-c`)

When `-c "…"` is supplied, the command runs on every host that logs in successfully. Its stdout and stderr are captured verbatim into the per-host report block. The command runs in the target's default shell via a single SSH `exec`.

Command execution is wrapped defensively: if the command errors at the transport level, that failure is recorded as the command's stderr and does **not** prevent `--check-sudo` or enumeration from running, nor is it counted as a login failure.

---

## Enumeration (`--enum`)

`--enum` collects host context and hunts for high-value files. It is **read-only**.

**Context collected:**

- `uname -a` and `/etc/os-release` (`PRETTY_NAME`, `VERSION_ID`)
- `id` (uid/gid/groups)
- Listening sockets (`ss -tlnH`, falling back to `netstat -tln`), first 30 lines

**High-value files probed** (existence + size reported; `$HOME` is expanded on the target):

| Category | Paths |
|----------|-------|
| SSH | `~/.ssh/id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519`, `config`, `known_hosts`, `authorized_keys` |
| Cloud / orchestration | `~/.aws/credentials`, `~/.config/gcloud/credentials.db`, `~/.azure/accessTokens.json`, `~/.kube/config`, `~/.docker/config.json` |
| Shell / DB history | `~/.bash_history`, `~/.zsh_history`, `~/.mysql_history`, `~/.psql_history`, `~/.python_history` |
| Dotfile secrets | `~/.netrc`, `~/.git-credentials`, `~/.pgpass`, `~/.my.cnf`, `~/.npmrc`, `~/.pypirc`, `~/.env` |
| Password store | `~/.password-store` (directory) |
| Browser credentials | Firefox `logins.json` & `key4.db`, Chrome/Chromium `Login Data` (found under `~/.mozilla`, `~/.config/google-chrome`, `~/.config/chromium`, depth ≤ 4) |

Each discovered file is reported with its byte size (directories are noted as such). Files are **not** downloaded unless `--loot-dir` is set.

---

## Privilege-escalation checks (`--privesc`)

A lightweight, read-only "mini-LinPEAS." Each check that finds something produces a severity-tagged finding.

| Check | What it runs | Flags when… | Severity |
|-------|--------------|-------------|----------|
| Already root | parses `id` | `uid=0` | HIGH |
| Dangerous groups | parses `id` groups | member of `docker`/`lxd`/`lxc`/`disk`/`shadow` | HIGH |
| | | member of `adm`/`sudo`/`wheel` | INTERESTING |
| Passwordless sudo | `sudo -n -l` | any output (no password needed) | HIGH |
| Sudo version | `sudo -V` | version in CVE-2021-3156 (Baron Samedit) range | INTERESTING |
| SUID binaries | `find / -perm -4000 -type f` | basename matches the GTFOBins set | HIGH |
| | | (all SUID binaries also listed) | INFO |
| File capabilities | `getcap -r /` | `cap_setuid`/`setgid`/`dac_override`/`dac_read_search`/`sys_admin`/`sys_ptrace`/`sys_module` | HIGH |
| Writable system files | `[ -w /etc/passwd ]`, `-r`/`-w /etc/shadow`, `-w /etc/sudoers` | any writable/readable | HIGH |
| Writable cron | scans `/etc/crontab`, `/etc/cron.d`, `cron.hourly`, `cron.daily` | any writable file | HIGH |
| NFS root squash | `/etc/exports` | contains `no_root_squash` | INTERESTING |
| Docker socket | `/var/run/docker.sock` | socket is writable | HIGH |
| pkexec | `command -v pkexec` | present (PwnKit / CVE-2021-4034 candidate) | INFO |

**GTFOBins SUID set** (basenames flagged as HIGH when found SUID-root):

```
arp awk base64 bash busybox cat chmod chown chroot cp cpulimit curl cut dd
dmesg docker ed emacs env expect find flock gawk gdb git grep head ionice
journalctl less make mawk more mount mv nano nmap node nohup openssl perl php
pico pkexec python python2 python3 rsync ruby rvim sed setarch sh socat sort
start-stop-daemon strace systemctl tail tar taskset tee vi view vim watch
wget xargs zip
```

Notes:
- The SUID scan is `-perm -4000` (SUID) only; SGID is not scanned.
- The sudo version comparison ignores patch letters, so a fixed release at the boundary (e.g. `1.9.5p2`) may still be flagged — the finding text says to verify the exact patch level.
- Heavy scans (`find`, `getcap`) are wrapped in `timeout 15` on the target when the `timeout` binary is available, so a huge filesystem yields a partial (rather than hung) result.

---

## OS detection & non-Linux hosts

Before running the enumeration payload, Clockwork fingerprints the target:

1. `uname -s` → `Linux`, `Darwin` (→ macOS), or another Unix name (FreeBSD, SunOS, …); Cygwin/MSYS/Git-Bash strings map to Windows.
2. If `uname` produces nothing (the typical Windows cmd.exe/PowerShell case), it falls back to `cmd /c ver` to positively identify **Windows** and capture its version.

Only targets identified as **Linux** run the enumeration payload. Everything else is skipped with a report line such as:

```
Enumeration skipped: Windows 10.0.17763.107 host (enumeration is Linux-only)
```

Credential checking, `-c`, and `--check-sudo` still run on every platform — only the Linux-specific enumeration is gated.

---

## Looting files (`--loot-dir`)

`--loot-dir DIR` downloads the high-value files discovered by `--enum` over SFTP. It **implies `--enum`** (enabling it automatically if you only passed `--privesc`).

- Files are saved to `DIR/<host>/<original absolute path>`, e.g. `loot/10.0.0.11/home/admin/.ssh/id_rsa`.
- In a host directory name, `:` is replaced with `_` (so IPv6 literals are filesystem-safe).
- Files larger than `--loot-max-bytes` (default 5 MB) are **skipped**, with a note in the report.
- Directories in the loot list (e.g. `~/.password-store`) are flagged but not recursively downloaded.
- Download failures (permissions, races) are recorded per file and never abort the run.
- `DIR` is created up front; if it can't be created, Clockwork exits before connecting to anything.

---

## Severity model & finding catalog

Every enumeration finding carries one of three severities:

| Severity | Meaning |
|----------|---------|
| **HIGH** | Directly actionable — likely a privesc or a credential you can use now. |
| **INTERESTING** | Worth a look — conditional or context-dependent value. |
| **INFO** | Context only — inventory, versions, identity. |

In the report, per-host findings are sorted HIGH → INTERESTING → INFO, and **every HIGH finding across all hosts is rolled up into the top-level "QUICK WINS" section** so you can triage at a glance. The console also appends `[N HIGH]` to each successful host and prints a HIGH total in the summary.

---

## The report file

Written to `--output` or `clockwork_<timestamp>.txt`, UTF-8 encoded. Structure:

```
CLOCKWORK REPORT           # run metadata: time, user, auth method, port,
                           # command, flags enabled, target/success/fail counts

QUICK WINS — HIGH FINDINGS # every HIGH finding, prefixed with its host
                           # (only present when --enum/--privesc is used)

SUCCESSFUL LOGINS          # one block per host:
  --- <host> ---           #   - command stdout/stderr (if -c)
  ...                      #   - passwordless-sudo verdict (if --check-sudo)
                           #   - Enumeration: findings by severity
                           #   - Loot downloaded: paths + sizes (if --loot-dir)

FAILED LOGINS              # host + reason (auth failure, connection error, …)
```

If a run is interrupted with `Ctrl+C`, the report is still written and includes an `Interrupted` line noting how many targets were not checked.

---

## Console output

- A banner and per-host progress lines: `[done/total] host STATUS`.
- `STATUS` is `SUCCESS` (green) or `FAILED (<reason>)` (red), with optional `[passwordless sudo]` and `[N HIGH]` tags.
- Progress appears in completion order (fastest hosts first); the **report** is always in targets-file order.
- Colors follow the [TTY rules](#security--operational-considerations); pipe the output or set `NO_COLOR` for plain text.

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Completed normally. |
| `130` | Interrupted with `Ctrl+C` (partial report written). |
| `1` | Fatal startup/runtime error (targets file missing, no usable targets, key load failure, loot dir not creatable, report not writable). |
| `2` | Command-line usage error (missing/invalid flags, mutually exclusive violation). |

Note: individual login *failures* are a normal result and do **not** change the exit code — check the report/summary for per-host outcomes.

---

## Performance & tuning

- **`--workers`** governs parallelism. Higher values check more hosts at once; the practical ceiling depends on your network, file-descriptor limits, and how aggressive you want to be. 20 is a sane default.
- **`--timeout`** bounds the connect/auth phase. On networks with many dead hosts, a lower timeout finishes faster (at the risk of prematurely failing slow-but-alive hosts).
- **Enumeration timeout** is internal and automatic: the channel budget for the enum payload is `max(--timeout, 60)` seconds, comfortably above the worst-case sum of the on-target `timeout 15` scans.
- Enumeration adds 1–2 extra round-trips per host (an OS probe, then the payload); on non-Linux hosts it's just the cheap probe.

---

## Security & operational considerations

- **Authorization.** Only use against systems you are permitted to test.
- **Not stealthy.** Enumeration spawns many processes and touches many files on the target — loud on any host with auditing or EDR. It is designed for authorized assessments, not evasion.
- **Read-only enumeration.** The payload only reads; it never modifies the target. `--loot-dir` copies files *from* the target to your machine.
- **Credentials on the command line.** A password passed with `-p` is visible in your shell history and in the target-side process list of anything that inspects your local process table. Prefer key auth where practical, and be mindful of where the report and any looted files are stored (they may contain secrets).
- **Host-key trust.** Unknown host keys are auto-accepted; host identity is not verified.
- **Color/TTY behavior.** ANSI colors are emitted only when stdout is a TTY and `NO_COLOR` is unset; on Windows, virtual-terminal processing is enabled so colors render instead of leaking escape codes. Redirecting to a file yields clean plain text.

---

## Limitations & known trade-offs

- **Single credential per run.** One username + one secret; there is no built-in spray over lists yet.
- **Linux-focused enumeration.** Non-Linux hosts are fingerprinted and skipped (credential checking still works).
- **SUID only** (no SGID) in the privesc scan; the GTFOBins list is a curated subset, not exhaustive.
- **Truncation.** The SUID list is capped at 200 entries and capabilities at 100; listening sockets at 30.
- **`--check-sudo` + `--privesc`** both run `sudo -n -l` (a harmless double-run).
- **`Ctrl+C` latency.** After an interrupt, in-flight worker threads finish their current host (bounded by the enum timeout) before the process exits — threads cannot be force-killed.

---

## Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `The 'paramiko' package is required…` | `pip install paramiko`. |
| `Key '<file>' is encrypted; supply --key-passphrase.` | The private key needs a passphrase — pass `--key-passphrase`. |
| `Key file not found: <file>` | Wrong `--keyfile` path. |
| `Could not load key … with any known type` | Not a supported/valid key file. |
| Host shows `FAILED (Authentication failed)` | Credentials rejected by that host. |
| Host shows `FAILED (Connection error: …)` | Network/SSH-layer issue (timeout, refused, protocol). Consider adjusting `--timeout`/`--port`. |
| `Enumeration skipped: … host (enumeration is Linux-only)` | Target isn't Linux; expected behavior. |
| Report shows `Enum: enum failed: …` | The enum payload couldn't complete (e.g., non-POSIX shell or a very slow host); the login still succeeded. |
| Garbled escape codes in a saved file | You forced colors; use `--no-color` or rely on the automatic TTY detection. |
