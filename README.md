<div align="center">

# 🕰️ Clockwork

**Bulk SSH credential validation + lightweight post-login enumeration — in one file.**

[![Python](https://img.shields.io/badge/python-3.7%2B-blue.svg)](https://www.python.org/)
[![Dependencies](https://img.shields.io/badge/deps-paramiko-informational.svg)](https://www.paramiko.org/)
[![Platform](https://img.shields.io/badge/runs%20on-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)]()
[![Authorized use only](https://img.shields.io/badge/use-authorized%20testing%20only-critical.svg)](#-legal--authorized-use-only)

</div>

---

> ## ⚠️ Legal — authorized use only
> Clockwork is a security-testing tool. **Only run it against systems you own or have explicit, written permission to test.** Unauthorized access to computer systems is illegal in most jurisdictions. You are solely responsible for how you use it.

---

## What it does

Point Clockwork at a list of hosts and a single set of credentials. It concurrently checks which hosts you can log into, and — on the ones that accept the login — can optionally run a command, hunt for high-value files, and perform a set of quick privilege-escalation checks. Everything lands in a clean, readable report.

Think of it as **credential spray-check + a mini-LinPEAS triage**, small enough to read in one sitting.

```
[1/6] 10.0.0.11         SUCCESS [passwordless sudo] [3 HIGH]
[2/6] 10.0.0.12         SUCCESS [1 HIGH]
[3/6] 10.0.0.13         FAILED (Authentication failed)
[4/6] 10.0.0.21         SUCCESS
[5/6] 10.0.0.22         FAILED (Connection error: timed out)
[6/6] 10.0.0.23         SUCCESS [2 HIGH]

Summary: 4 succeeded, 2 failed out of 6 targets.
6 HIGH finding(s) across successful logins.
Full report written to: clockwork_20260702_120000.txt
```

## Features

- 🔑 **Password *or* key auth** — auto-detects Ed25519 / RSA / ECDSA / DSA keys, with passphrase support.
- ⚡ **Concurrent** — checks many hosts at once (`--workers`, default 20).
- 🧾 **Clean report** — a "quick wins" summary of HIGH findings up top, then per-host detail.
- 🕵️ **Loot hunting** (`--enum`) — SSH & cloud keys, shell/DB history, `.env` / `.netrc` / `.git-credentials`, browser credential stores, and more.
- 🪜 **Mini-LinPEAS** (`--privesc`) — passwordless sudo, GTFOBins-exploitable SUID, file capabilities, writable `/etc/passwd|shadow|sudoers`, writable cron, NFS `no_root_squash`, writable docker socket, dangerous group membership, and sudo/pkexec CVE flags.
- 📥 **Auto-loot** (`--loot-dir`) — pull the flagged files back over SFTP, size-capped.
- 🪟 **OS-aware** — fingerprints the target and cleanly skips enumeration on non-Linux hosts (Windows/macOS/BSD) instead of running garbage. Credential checking still works everywhere.
- 🎨 **Nice terminal output** — colored, TTY-aware (honors `NO_COLOR`, enables ANSI on Windows), read-only enumeration, graceful `Ctrl+C` with a partial report.

## Install

```bash
git clone https://github.com/didyoureally/clockwork.git
cd clockwork
pip install paramiko
```

Requires **Python 3.7+** and [`paramiko`](https://www.paramiko.org/). That's the only dependency.

## Quick start

Create a `targets.txt` (one host per line; blank lines and `#` comments are ignored):

```
10.0.0.11
10.0.0.12
# staging box, skip for now
# 10.0.0.99
10.0.0.13
```

Then:

```bash
# Just check who we can log into
python3 clockwork.py -t targets.txt -u admin -p 'SuperSecret123'

# Key auth + run a command on every host that accepts the login
python3 clockwork.py -t targets.txt -u admin -k ./id_ed25519 -c "hostname; id"

# The full triage: loot hunt + privesc checks + pull loot back locally
python3 clockwork.py -t targets.txt -u admin -p 'SuperSecret123' \
    --enum --privesc --loot-dir ./loot
```

## Usage

```
python3 clockwork.py -t TARGETS -u USER (-p PASSWORD | -k KEYFILE) [options]
```

### Targets & authentication
| Flag | Description |
|------|-------------|
| `-t`, `--targets FILE` | File of hosts, one IP/hostname per line (`#` comments ok). **Required.** |
| `-u`, `--username USER` | The single SSH username to try everywhere. **Required.** |
| `-p`, `--password PASS` | Password auth. Mutually exclusive with `--keyfile`. |
| `-k`, `--keyfile PATH` | Private-key auth (type auto-detected). Mutually exclusive with `--password`. |
| `--key-passphrase PASS` | Passphrase for an encrypted key. |

### Post-login actions
| Flag | Description |
|------|-------------|
| `-c`, `--command CMD` | Run a command on each successful login; output captured in the report. |
| `--check-sudo` | Detect passwordless (NOPASSWD) sudo via `sudo -n -l`. |
| `--enum` | Read-only enumeration: host context + high-value file hunt. |
| `--privesc` | Read-only lightweight privilege-escalation checks (mini-LinPEAS). |
| `--loot-dir DIR` | SFTP-download flagged files into `DIR/<host>/`. Implies `--enum`. |
| `--loot-max-bytes N` | Skip loot files larger than `N` bytes (default `5000000`). |

### Connection & output
| Flag | Description |
|------|-------------|
| `--port N` | SSH port for every target (default `22`). |
| `--timeout N` | Per-host connect/auth timeout in seconds (default `10`). |
| `--workers N` | Max hosts checked concurrently (default `20`). |
| `-o`, `--output FILE` | Report path (default `clockwork_<timestamp>.txt`). |
| `--no-color` | Disable ANSI colors (also auto-disabled when piped or `NO_COLOR` is set). |

Run `python3 clockwork.py -h` for the full, detailed help.

## What the report looks like

```
================
CLOCKWORK REPORT
================
Run time      : 2026-07-02 12:00:00
Username      : admin
Auth method   : password
...
Succeeded     : 4
Failed        : 2

==============================
QUICK WINS — HIGH FINDINGS (6)
==============================

[10.0.0.11] Passwordless sudo (sudo -n -l) — Can run sudo without a password.
[10.0.0.11] 2 exploitable SUID binary/ies (GTFOBins) — SUID-root binaries with a known GTFOBins privesc.
[10.0.0.23] In 'docker' group — member of 'docker' -> mount host FS in a container = root
...

--- 10.0.0.11 ---
Enumeration:
  [HIGH] Passwordless sudo (sudo -n -l) — Can run sudo without a password.
  [HIGH] 2 exploitable SUID binary/ies (GTFOBins) — ...
  [INTERESTING] 4 high-value file(s)/dir(s) — Credentials / keys / history ...
  [INFO] Identity — uid=1000(admin) gid=1000(admin) groups=1000(admin),27(sudo)
Loot downloaded:
  /home/admin/.ssh/id_rsa -> loot/10.0.0.11/home/admin/.ssh/id_rsa (2610 bytes)
```

Findings are ranked **HIGH → INTERESTING → INFO**, and every HIGH is rolled up into the "quick wins" block at the top so you know where to look first.

## 🧪 Try it safely (local lab)

The repo ships with `create-ssh-boxes.sh`, which spins up three throwaway Docker SSH servers (user `testuser` / password `testpassword`, plus a generated keypair) so you can exercise Clockwork end-to-end without touching anything real:

```bash
./create-ssh-boxes.sh                 # build + start 3 boxes on ports 2201-2203
printf 'localhost\n' > targets.txt

python3 clockwork.py -t targets.txt -u testuser -p testpassword \
    --port 2201 --enum --privesc

./create-ssh-boxes.sh clean           # tear everything down
```

## How enumeration works

To stay fast and quiet-ish, Clockwork bundles all checks into **one read-only POSIX-sh payload per host**, runs it in a single SSH exec, and splits the output on random-token section markers. Findings are derived and tagged by severity locally. Nothing is written to the target.

> **Heads up:** the enumeration is **Linux-oriented and not stealthy** — it spawns many processes and touches many files, which is loud on any host with auditing/EDR. Non-Linux targets are auto-skipped (credential checking still runs).

## Roadmap ideas

- Credential spray mode (`--userlist` / `--passlist`) with lockout-aware throttling
- JSON / CSV report output for piping into other tooling
- CIDR / range expansion in the targets file
- A native Windows enumeration profile (PowerShell one-liners)
