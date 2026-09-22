import os
import sys
import re
import json
import stat
import pwd
import grp
import shutil
import socket
import platform
import subprocess
import argparse
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Tuple

VERSION = "1.0.0"
TOOL_NAME = "nexSSH"

SSHD_CANDIDATES = ["sshd", "/usr/sbin/sshd", "/usr/local/sbin/sshd"]
SSHD_CONFIG = Path("/etc/ssh/sshd_config")
SSHD_CONFIG_D = Path("/etc/ssh/sshd_config.d")
SERVICE_CANDIDATES = ["ssh", "sshd"]
DEFAULT_SSH_PORT = 22

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_PENALTY = {"CRITICAL": 25, "HIGH": 12, "MEDIUM": 6, "LOW": 2, "INFO": 0}
SEVERITY_COLOR = {
    "CRITICAL": "\033[1;97;41m",
    "HIGH":     "\033[1;31m",
    "MEDIUM":   "\033[1;33m",
    "LOW":      "\033[1;36m",
    "INFO":     "\033[1;34m",
}
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
FG_GRN = "\033[1;32m"
FG_YEL = "\033[1;33m"
FG_RED = "\033[1;31m"

BANNER = r"""
   _  _ ___ __  __ ___ ___ _  _
  | \| | __|\ \/ / __/ __| || |
  | .` | _|  >  <\__ \__ \ __ |
  |_|\_|___|/_/\_\___/___/_||_|
      Linux SSH Security Auditor
              v1.0.0

   GitHub   : github.com/7hekasra
   Telegram : t.me/linuxfarci
   Website  : linuxfarci.ir
"""


class Finding:
    __slots__ = ("id", "title", "category", "severity", "description",
                 "current_value", "recommendation")

    def __init__(self, id: str, title: str, category: str, severity: str,
                 description: str, current_value: str, recommendation: str):
        self.id = id
        self.title = title
        self.category = category
        self.severity = severity.upper()
        self.description = description
        self.current_value = current_value
        self.recommendation = recommendation

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category,
            "severity": self.severity,
            "description": self.description,
            "current_value": self.current_value,
            "recommendation": self.recommendation,
        }


def run_cmd(cmd: List[str], timeout: int = 5) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout, check=False)
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError:
        return 127, "", f"not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout: {' '.join(cmd)}"
    except Exception as e:
        return 1, "", f"error: {e}"


def which_sshd() -> Optional[str]:
    for cand in SSHD_CANDIDATES:
        if os.path.isabs(cand) and os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
        found = shutil.which(cand)
        if found:
            return found
    return None


def is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def have_systemctl() -> bool:
    return shutil.which("systemctl") is not None


def octal_mode(mode: int) -> str:
    return oct(stat.S_IMODE(mode))[2:].zfill(4)


def safe_stat(path: Path) -> Optional[os.stat_result]:
    try:
        return path.stat()
    except (FileNotFoundError, PermissionError, OSError):
        return None


def _uid_exists(uid: int) -> bool:
    try:
        pwd.getpwuid(uid)
        return True
    except KeyError:
        return False


def _gid_exists(gid: int) -> bool:
    try:
        grp.getgrgid(gid)
        return True
    except KeyError:
        return False


def _support_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def _color(text: str, sev: str, use_color: bool) -> str:
    if not use_color:
        return text
    return f"{SEVERITY_COLOR.get(sev, '')}{text}{RESET}"


class SSHConfig:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.sshd_path: Optional[str] = None
        self.effective: Dict[str, str] = {}
        self.raw: Dict[str, str] = {}
        self.source = "none"
        self.errors: List[str] = []

    def discover(self) -> None:
        self.sshd_path = which_sshd()
        if self.sshd_path:
            self._try_sshd_t()
        if not self.effective:
            self._parse_config_files()

    def _try_sshd_t(self) -> None:
        assert self.sshd_path
        rc, out, err = run_cmd([self.sshd_path, "-T"], timeout=8)
        if rc != 0 or not out.strip():
            self.errors.append(f"sshd -T failed (rc={rc}): {err.strip()[:120]}")
            return
        parsed: Dict[str, str] = {}
        for line in out.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) == 2:
                parsed[parts[0].lower()] = parts[1].strip()
        if parsed:
            self.effective = parsed
            self.source = "sshd -T"

    def _parse_config_files(self) -> None:
        files: List[Path] = []
        if SSHD_CONFIG.is_file():
            files.append(SSHD_CONFIG)
        if SSHD_CONFIG_D.is_dir():
            try:
                for p in sorted(SSHD_CONFIG_D.iterdir()):
                    if p.suffix == ".conf" and p.is_file():
                        files.append(p)
            except PermissionError:
                self.errors.append(f"permission denied: {SSHD_CONFIG_D}")
        for f in files:
            self._parse_one(f)
        if self.raw:
            self.source = "config file parse"

    def _parse_one(self, path: Path) -> None:
        try:
            text = path.read_text(errors="replace")
        except (PermissionError, OSError) as e:
            self.errors.append(f"cannot read {path}: {e}")
            return
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) == 2:
                k = parts[0].lower()
                v = parts[1].strip().strip('"')
                self.raw[k] = v
                self.effective.setdefault(k, v)

    def get(self, key: str, default: str = "") -> str:
        return self.effective.get(key.lower(), default)

    def get_int(self, key: str, default: int = -1) -> int:
        v = self.get(key)
        if not v:
            return default
        try:
            return int(v.split()[0])
        except (ValueError, IndexError):
            return default

    def is_yes(self, key: str, default: bool = False) -> bool:
        v = self.get(key).lower()
        if not v:
            return default
        return v in ("yes", "true", "on", "1")


def get_os_pretty() -> str:
    try:
        with open("/etc/os-release", "r", errors="replace") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return platform.system() or "Unknown"


def get_kernel() -> str:
    try:
        return platform.release()
    except Exception:
        return "Unknown"


def get_ssh_version(sshd_path: Optional[str]) -> str:
    if not sshd_path:
        return "not installed"
    rc, out, err = run_cmd([sshd_path, "-V"], timeout=3)
    text = (err or out).strip()
    m = re.search(r"(OpenSSH[_\s][\w.\-]+)", text)
    if m:
        return m.group(1).replace("_", " ")
    return "OpenSSH (unknown)"


def get_service_status() -> Dict[str, str]:
    result = {"name": "unknown", "active": "unknown", "enabled": "unknown"}
    if not have_systemctl():
        return result
    for name in SERVICE_CANDIDATES:
        rc_a, out_a, _ = run_cmd(["systemctl", "is-active", name], timeout=3)
        if rc_a == 0 and out_a.strip():
            result["name"] = name
            result["active"] = out_a.strip()
            rc_e, out_e, _ = run_cmd(["systemctl", "is-enabled", name], timeout=3)
            result["enabled"] = out_e.strip() if rc_e == 0 else "unknown"
            return result
        if out_a.strip() in ("inactive", "failed", "activating", "deactivating"):
            result["name"] = name
            result["active"] = out_a.strip()
            rc_e, out_e, _ = run_cmd(["systemctl", "is-enabled", name], timeout=3)
            result["enabled"] = out_e.strip() if rc_e == 0 else "unknown"
            return result
    return result


def _port_open(host: str, port: int, timeout: float = 0.3) -> bool:
    try:
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((host, port)) == 0
    except OSError:
        return False


def get_ssh_ports(config: SSHConfig) -> List[int]:
    ports: List[int] = []
    port_str = config.get("port", "")
    if port_str:
        for token in re.split(r"[\s,]+", port_str):
            try:
                p = int(token)
                if 1 <= p <= 65535 and p not in ports:
                    ports.append(p)
            except ValueError:
                continue
    if not ports:
        if _port_open("127.0.0.1", DEFAULT_SSH_PORT) or _port_open("::1", DEFAULT_SSH_PORT):
            ports = [DEFAULT_SSH_PORT]
    if not ports:
        ports = [DEFAULT_SSH_PORT]
    return ports
def check_001_root_login(cfg: SSHConfig) -> Finding:
    val = cfg.get("permitrootlogin", "yes")
    low = val.lower()
    if low in ("no", "prohibit-password", "forced-commands-only"):
        sev = "INFO"
        desc = "Direct root login is restricted."
        rec = "Keep PermitRootLogin no or prohibit-password."
    else:
        sev = "HIGH"
        desc = "Root login via SSH is enabled. Direct root access increases impact of credential compromise."
        rec = "Set 'PermitRootLogin no' and use sudo for privileged operations."
    return Finding("SSH-001", "PermitRootLogin", "Authentication", sev,
                   desc, f"PermitRootLogin {val}", rec)


def check_002_password_auth(cfg: SSHConfig) -> Finding:
    val = cfg.get("passwordauthentication", "yes")
    if val.lower() == "no":
        sev, desc = "INFO", "Password authentication is disabled. Key-based auth enforced."
        rec = "Keep PasswordAuthentication no."
    else:
        sev = "HIGH"
        desc = "Password authentication is enabled. Passwords are vulnerable to brute-force and reuse."
        rec = "Disable PasswordAuthentication and enforce key-based authentication."
    return Finding("SSH-002", "PasswordAuthentication", "Authentication", sev,
                   desc, f"PasswordAuthentication {val}", rec)


def check_003_empty_passwords(cfg: SSHConfig) -> Finding:
    val = cfg.get("permitemptypasswords", "no")
    if val.lower() == "yes":
        sev, desc = "CRITICAL", "Empty passwords are permitted. Any account with an empty password is instantly compromised."
        rec = "Set 'PermitEmptyPasswords no'."
    else:
        sev, desc = "INFO", "Empty passwords are not permitted."
        rec = "Keep PermitEmptyPasswords no."
    return Finding("SSH-003", "PermitEmptyPasswords", "Authentication", sev,
                   desc, f"PermitEmptyPasswords {val}", rec)


def check_004_pubkey_auth(cfg: SSHConfig) -> Finding:
    val = cfg.get("pubkeyauthentication", "yes")
    if val.lower() == "yes":
        sev, desc = "INFO", "Public key authentication is enabled."
        rec = "Keep PubkeyAuthentication yes."
    else:
        sev = "MEDIUM"
        desc = "Public key authentication is disabled. This forces less secure alternatives."
        rec = "Enable PubkeyAuthentication yes."
    return Finding("SSH-004", "PubkeyAuthentication", "Authentication", sev,
                   desc, f"PubkeyAuthentication {val}", rec)


def check_005_max_auth_tries(cfg: SSHConfig) -> Finding:
    val = cfg.get_int("maxauthtries", 6)
    if val < 0:
        sev = "INFO"
        desc = "MaxAuthTries not specified; using default."
        rec = "Set MaxAuthTries 3."
    elif val > 6:
        sev = "HIGH"
        desc = f"MaxAuthTries is high ({val}). Allows many password attempts per connection."
        rec = "Set MaxAuthTries to 3 or lower."
    elif val > 4:
        sev = "MEDIUM"
        desc = f"MaxAuthTries is above recommended ({val})."
        rec = "Set MaxAuthTries to 3."
    else:
        sev = "INFO"
        desc = f"MaxAuthTries is within recommended range ({val})."
        rec = "Keep MaxAuthTries at 3."
    return Finding("SSH-005", "MaxAuthTries", "Authentication", sev,
                   desc, f"MaxAuthTries {val}", rec)


def check_006_login_grace_time(cfg: SSHConfig) -> Finding:
    raw = cfg.get("logingracetime", "")
    val = 120
    if raw:
        m = re.match(r"(\d+)", raw)
        if m:
            val = int(m.group(1))
    if val > 120:
        sev = "MEDIUM"
        desc = f"LoginGraceTime is long ({val}s). Increases exposure window for unauthenticated connections."
        rec = "Set LoginGraceTime to 60 or less."
    elif val > 60:
        sev = "LOW"
        desc = f"LoginGraceTime above recommended ({val}s)."
        rec = "Set LoginGraceTime to 60."
    else:
        sev = "INFO"
        desc = f"LoginGraceTime within recommended range ({val}s)."
        rec = "Keep LoginGraceTime at 60 or lower."
    return Finding("SSH-006", "LoginGraceTime", "Authentication", sev,
                   desc, f"LoginGraceTime {val}", rec)


def check_007_x11_forwarding(cfg: SSHConfig) -> Finding:
    val = cfg.get("x11forwarding", "no")
    if val.lower() == "yes":
        sev = "MEDIUM"
        desc = "X11Forwarding is enabled. Can expose local X server and increase attack surface."
        rec = "Set X11Forwarding no unless explicitly required."
    else:
        sev = "INFO"
        desc = "X11Forwarding is disabled."
        rec = "Keep X11Forwarding no."
    return Finding("SSH-007", "X11Forwarding", "Access", sev,
                   desc, f"X11Forwarding {val}", rec)


def check_008_tcp_forwarding(cfg: SSHConfig) -> Finding:
    val = cfg.get("allowtcpforwarding", "yes")
    low = val.lower()
    if low == "no":
        sev, desc = "INFO", "TCP forwarding is disabled."
        rec = "Keep AllowTcpForwarding no."
    elif low == "local":
        sev, desc = "LOW", "Only local TCP forwarding is allowed."
        rec = "Restrict to 'no' if tunneling not required."
    elif low == "remote":
        sev, desc = "MEDIUM", "Remote TCP forwarding is allowed."
        rec = "Restrict to 'no' if tunneling not required."
    else:
        sev = "MEDIUM"
        desc = "TCP forwarding is enabled. Can be abused for tunneling and pivoting."
        rec = "Set AllowTcpForwarding no unless required."
    return Finding("SSH-008", "AllowTcpForwarding", "Access", sev,
                   desc, f"AllowTcpForwarding {val}", rec)


def check_009_permit_tunnel(cfg: SSHConfig) -> Finding:
    val = cfg.get("permittunnel", "no")
    if val.lower() in ("yes", "point-to-point", "ethernet"):
        sev = "HIGH"
        desc = "PermitTunnel is enabled. Allows layer 2/3 tunnel interfaces via SSH."
        rec = "Set PermitTunnel no."
    else:
        sev = "INFO"
        desc = "PermitTunnel is disabled."
        rec = "Keep PermitTunnel no."
    return Finding("SSH-009", "PermitTunnel", "Access", sev,
                   desc, f"PermitTunnel {val}", rec)


def check_010_access_control(cfg: SSHConfig) -> Finding:
    keys = ["allowusers", "allowgroups", "denyusers", "denygroups"]
    found = {k: cfg.get(k, "") for k in keys if cfg.get(k, "")}
    if found:
        val = "; ".join(f"{k}={v}" for k, v in found.items())
        sev = "INFO"
        desc = "Access control directives are configured."
        rec = "Keep Allow/Deny directives and review periodically."
    else:
        val = "none configured"
        sev = "LOW"
        desc = "No AllowUsers/AllowGroups/DenyUsers/DenyGroups configured. All users may attempt login."
        rec = "Restrict login with AllowUsers or AllowGroups."
    return Finding("SSH-010", "Access Control", "Access", sev, desc, val, rec)


def check_011_sshd_config_permissions() -> Finding:
    st = safe_stat(SSHD_CONFIG)
    if st is None:
        return Finding("SSH-011", "sshd_config permissions", "Permissions", "INFO",
                       "sshd_config not found or not readable.",
                       "not present",
                       "Ensure /etc/ssh/sshd_config is owned by root:root with mode 0600.")
    mode = stat.S_IMODE(st.st_mode)
    owner = pwd.getpwuid(st.st_uid).pw_name if _uid_exists(st.st_uid) else str(st.st_uid)
    group = grp.getgrgid(st.st_gid).gr_name if _gid_exists(st.st_gid) else str(st.st_gid)
    bad = []
    if owner != "root":
        bad.append(f"owner={owner}")
    if group != "root":
        bad.append(f"group={group}")
    if mode & 0o077:
        bad.append(f"mode={octal_mode(st.st_mode)}")
    if bad:
        sev = "HIGH"
        desc = "sshd_config permissions are too permissive. " + ", ".join(bad)
        rec = "chown root:root /etc/ssh/sshd_config && chmod 600 /etc/ssh/sshd_config"
    else:
        sev = "INFO"
        desc = "sshd_config permissions are correct."
        rec = "Keep owner root:root, mode 0600."
    return Finding("SSH-011", "sshd_config permissions", "Permissions", sev,
                   desc, f"{owner}:{group} {octal_mode(st.st_mode)}", rec)


def check_012_user_ssh_permissions() -> List[Finding]:
    findings: List[Finding] = []
    targets = [
        (".ssh", 0o700, True),
        (".ssh/authorized_keys", 0o600, False),
        (".ssh/id_rsa", 0o600, False),
        (".ssh/id_ed25519", 0o600, False),
    ]
    try:
        users = pwd.getpwall()
    except Exception:
        return findings
    for u in users:
        if u.pw_uid < 1000 and u.pw_uid != 0:
            continue
        home = Path(u.pw_dir)
        if not home.is_dir():
            continue
        for rel, max_mode, is_dir in targets:
            p = home / rel
            st = safe_stat(p)
            if st is None:
                continue
            mode = stat.S_IMODE(st.st_mode)
            owner = pwd.getpwuid(st.st_uid).pw_name if _uid_exists(st.st_uid) else str(st.st_uid)
            bad_mode = (mode & ~max_mode) != 0
            bad_owner = (owner != u.pw_name and owner != "root")
            if bad_mode or bad_owner:
                findings.append(Finding(
                    "SSH-012", f"Insecure permissions: {p}", "Permissions", "HIGH",
                    f"File/dir has insecure permissions or owner for user {u.pw_name}.",
                    f"owner={owner} mode={octal_mode(st.st_mode)}",
                    f"chmod {'700' if is_dir else '600'} {p} && chown {u.pw_name} {p}"
                ))
    return findings


def check_013_service_status() -> Finding:
    status = get_service_status()
    if status["name"] == "unknown":
        sev = "INFO"
        desc = "SSH service could not be detected via systemctl."
        val = "unknown"
        rec = "Verify SSH service is running and enabled."
    elif status["active"] != "active":
        sev = "MEDIUM"
        desc = f"SSH service '{status['name']}' is not active ({status['active']})."
        val = f"{status['name']}: {status['active']}"
        rec = "Enable SSH if remote access is required, or confirm it should be off."
    elif status["enabled"] not in ("enabled", "static", "indirect"):
        sev = "LOW"
        desc = f"SSH service '{status['name']}' is active but enabled='{status['enabled']}'."
        val = f"{status['name']}: active, enabled={status['enabled']}"
        rec = "Decide whether SSH should start at boot and set 'systemctl enable' accordingly."
    else:
        sev = "INFO"
        desc = f"SSH service '{status['name']}' is active and enabled."
        val = f"{status['name']}: active, enabled={status['enabled']}"
        rec = "Keep service running as needed."
    return Finding("SSH-013", "SSH Service Status", "Service", sev, desc, val, rec)


def check_014_port(cfg: SSHConfig) -> Finding:
    ports = get_ssh_ports(cfg)
    val = ", ".join(str(p) for p in ports)
    if DEFAULT_SSH_PORT in ports:
        sev = "LOW"
        desc = "SSH is listening on the default port 22. Automated scans routinely target port 22."
        rec = "Consider moving SSH to a non-default port and restrict via firewall."
    else:
        sev = "INFO"
        desc = "SSH is not listening on the default port 22."
        rec = "Keep using a non-default port with firewall restrictions."
    return Finding("SSH-014", "SSH Port", "Network", sev, desc, f"Port {val}", rec)


def check_015_crypto(cfg: SSHConfig) -> List[Finding]:
    findings: List[Finding] = []
    weak_ciphers = {"3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc",
                    "blowfish-cbc", "cast128-cbc", "arcfour", "arcfour128",
                    "arcfour256", "rijndael-cbc@lysator.liu.se"}
    weak_macs = {"hmac-md5", "hmac-md5-96", "hmac-sha1-96", "hmac-ripemd160",
                 "umac-64@openssh.com", "hmac-md5-etm@openssh.com",
                 "hmac-md5-96-etm@openssh.com", "hmac-sha1-96-etm@openssh.com"}
    weak_kex = {"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1",
                "diffie-hellman-group-exchange-sha1"}

    ciphers = cfg.get("ciphers", "")
    if ciphers:
        bad = [c for c in re.split(r"[,\s]+", ciphers) if c.lower() in weak_ciphers]
        if bad:
            findings.append(Finding(
                "SSH-015", "Weak Ciphers", "Cryptography", "HIGH",
                "Weak or deprecated ciphers are allowed.",
                f"Ciphers: {', '.join(bad)}",
                "Remove CBC and arcfour ciphers; prefer chacha20-poly1305 and aes-gcm."
            ))

    macs = cfg.get("macs", "")
    if macs:
        bad = [m for m in re.split(r"[,\s]+", macs) if m.lower() in weak_macs]
        if bad:
            findings.append(Finding(
                "SSH-015", "Weak MACs", "Cryptography", "HIGH",
                "Weak or deprecated MAC algorithms are allowed.",
                f"MACs: {', '.join(bad)}",
                "Remove MD5/SHA1-based MACs; prefer ETM and SHA2 variants."
            ))

    kex = cfg.get("kexalgorithms", "")
    if kex:
        bad = [k for k in re.split(r"[,\s]+", kex) if k.lower() in weak_kex]
        if bad:
            findings.append(Finding(
                "SSH-015", "Weak KEX", "Cryptography", "HIGH",
                "Weak key exchange algorithms are allowed.",
                f"KexAlgorithms: {', '.join(bad)}",
                "Remove SHA1-based KEX; prefer curve25519-sha256 and group16+."
            ))

    if not findings:
        findings.append(Finding(
            "SSH-015", "Cryptography", "Cryptography", "INFO",
            "No weak cipher, MAC, or KEX detected in effective config.",
            "no weak algorithms detected",
            "Keep current strong algorithm set; review after OpenSSH upgrades."
        ))
    return findings


def check_016_protocol(cfg: SSHConfig) -> Finding:
    proto = cfg.get("protocol", "")
    if proto and "1" in re.split(r"[,\s]+", proto):
        return Finding(
            "SSH-016", "SSH Protocol Version", "Cryptography", "CRITICAL",
            "SSH protocol 1 is enabled. It is fundamentally broken and must never be used.",
            f"Protocol {proto}",
            "Set 'Protocol 2' (OpenSSH 7.6+ only supports 2 by default)."
        )
    return Finding(
        "SSH-016", "SSH Protocol Version", "Cryptography", "INFO",
        "Only SSH protocol 2 is in use.",
        "Protocol 2",
        "Keep SSH protocol 2."
    )


def compute_score(findings: List[Finding]) -> int:
    score = 100
    for f in findings:
        score -= SEVERITY_PENALTY.get(f.severity, 0)
    return max(0, min(100, score))


def count_by_severity(findings: List[Finding]) -> Dict[str, int]:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def sort_findings(findings: List[Finding]) -> List[Finding]:
    return sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.id))


def run_all_checks(cfg: SSHConfig, verbose: bool = False,
                   enabled: Optional[List[str]] = None) -> List[Finding]:
    findings: List[Finding] = []

    def want(name: str) -> bool:
        return enabled is None or name in enabled

    if want("auth"):
        findings.append(check_001_root_login(cfg))
        findings.append(check_002_password_auth(cfg))
        findings.append(check_003_empty_passwords(cfg))
        findings.append(check_004_pubkey_auth(cfg))
        findings.append(check_005_max_auth_tries(cfg))
        findings.append(check_006_login_grace_time(cfg))

    if want("access"):
        findings.append(check_007_x11_forwarding(cfg))
        findings.append(check_008_tcp_forwarding(cfg))
        findings.append(check_009_permit_tunnel(cfg))
        findings.append(check_010_access_control(cfg))

    if want("permissions"):
        findings.append(check_011_sshd_config_permissions())
        findings.extend(check_012_user_ssh_permissions())

    if want("service"):
        findings.append(check_013_service_status())

    if want("network"):
        findings.append(check_014_port(cfg))

    if want("crypto"):
        findings.extend(check_015_crypto(cfg))
        findings.append(check_016_protocol(cfg))

    return findings
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>nexSSH Report — {timestamp}</title>
<style>
:root {{
  --bg:#0d1117; --fg:#e6edf3; --muted:#8b949e; --card:#161b22;
  --border:#30363d; --critical:#f85149; --high:#ff7b72;
  --medium:#d29922; --low:#58a6ff; --info:#8b949e; --accent:#3fb950;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
  background: var(--bg); color: var(--fg);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Helvetica Neue", Arial, sans-serif;
  line-height: 1.55; padding: 40px 20px;
}}
.wrap {{ max-width: 960px; margin: 0 auto; }}
h1 {{
  font-size: 28px; margin-bottom: 4px;
  background: linear-gradient(90deg, #3fb950, #58a6ff);
  -webkit-background-clip: text; -webkit-text-fill-color: transparent;
  background-clip: text;
}}
.sub {{ color: var(--muted); font-size: 13px; margin-bottom: 32px; }}
.card {{
  background: var(--card); border: 1px solid var(--border);
  border-radius: 10px; padding: 20px 24px; margin-bottom: 20px;
}}
.card h2 {{
  font-size: 14px; text-transform: uppercase; letter-spacing: 0.8px;
  color: var(--muted); margin-bottom: 14px; font-weight: 600;
}}
.grid {{ display: grid; grid-template-columns: 160px 1fr; gap: 8px 20px; font-size: 14px; }}
.grid .k {{ color: var(--muted); }}
.grid .v {{ color: var(--fg); }}
.score-wrap {{ display: flex; align-items: center; gap: 24px; }}
.score {{ font-size: 52px; font-weight: 700; letter-spacing: -1px; }}
.score-bar {{ flex: 1; height: 10px; background: #21262d; border-radius: 5px; overflow: hidden; }}
.score-bar > div {{ height: 100%; }}
.score-ok {{ color: var(--accent); }}
.score-mid {{ color: var(--medium); }}
.score-bad {{ color: var(--critical); }}
.bar-ok {{ background: var(--accent); }}
.bar-mid {{ background: var(--medium); }}
.bar-bad {{ background: var(--critical); }}
.summary {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; }}
.summary .item {{
  background: #0d1117; border: 1px solid var(--border);
  border-radius: 8px; padding: 12px 14px; text-align: center;
}}
.summary .num {{ font-size: 26px; font-weight: 700; }}
.summary .lbl {{ font-size: 11px; text-transform: uppercase; letter-spacing: 0.6px; color: var(--muted); }}
.num-critical {{ color: var(--critical); }}
.num-high {{ color: var(--high); }}
.num-medium {{ color: var(--medium); }}
.num-low {{ color: var(--low); }}
.num-info {{ color: var(--info); }}
.finding {{
  background: var(--card); border: 1px solid var(--border);
  border-left-width: 4px; border-radius: 8px;
  padding: 18px 22px; margin-bottom: 14px;
}}
.finding.critical {{ border-left-color: var(--critical); }}
.finding.high {{ border-left-color: var(--high); }}
.finding.medium {{ border-left-color: var(--medium); }}
.finding.low {{ border-left-color: var(--low); }}
.finding.info {{ border-left-color: var(--info); }}
.f-header {{ display: flex; align-items: center; gap: 12px; margin-bottom: 8px; flex-wrap: wrap; }}
.badge {{
  font-size: 11px; font-weight: 700; text-transform: uppercase;
  letter-spacing: 0.6px; padding: 3px 8px; border-radius: 4px;
}}
.badge.critical {{ background: rgba(248,81,73,0.15); color: var(--critical); }}
.badge.high {{ background: rgba(255,123,114,0.15); color: var(--high); }}
.badge.medium {{ background: rgba(210,153,34,0.15); color: var(--medium); }}
.badge.low {{ background: rgba(88,166,255,0.15); color: var(--low); }}
.badge.info {{ background: rgba(139,148,158,0.15); color: var(--info); }}
.f-id {{ font-family: "SF Mono", Consolas, monospace; font-size: 12px; color: var(--muted); }}
.f-title {{ font-size: 16px; font-weight: 600; }}
.f-desc {{ color: #c9d1d9; font-size: 14px; margin-bottom: 14px; }}
.f-block {{ margin-top: 10px; }}
.f-block .label {{
  font-size: 11px; text-transform: uppercase; letter-spacing: 0.6px;
  color: var(--muted); margin-bottom: 4px; font-weight: 600;
}}
.f-block .value {{
  font-family: "SF Mono", Consolas, monospace; font-size: 13px;
  background: #0d1117; border: 1px solid var(--border);
  border-radius: 6px; padding: 10px 12px; color: #c9d1d9;
  word-break: break-word; white-space: pre-wrap;
}}
.f-block .rec {{ color: #7ee787; }}
.footer {{
  text-align: center; color: var(--muted); font-size: 12px;
  margin-top: 40px; padding-top: 20px; border-top: 1px solid var(--border);
}}
@media (max-width: 600px) {{
  .summary {{ grid-template-columns: repeat(2, 1fr); }}
  .grid {{ grid-template-columns: 1fr; }}
  .score {{ font-size: 40px; }}
}}
</style>
</head>
<body>
<div class="wrap">
  <h1>nexSSH Security Report</h1>
  <div class="sub">Generated {timestamp} &middot; nexSSH v{version} &middot; Linux SSH Security Auditor</div>

  <div class="card">
    <h2>System</h2>
    <div class="grid">
      <div class="k">OS</div><div class="v">{os_name}</div>
      <div class="k">Kernel</div><div class="v">{kernel}</div>
      <div class="k">SSH</div><div class="v">{ssh_version}</div>
      <div class="k">Port</div><div class="v">{ssh_port}</div>
      <div class="k">Service</div><div class="v">{service_status}</div>
      <div class="k">Config Source</div><div class="v">{config_source}</div>
    </div>
  </div>

  <div class="card">
    <h2>Security Score</h2>
    <div class="score-wrap">
      <div class="score {score_class}">{score}<span style="font-size:20px;color:var(--muted)">/100</span></div>
      <div class="score-bar"><div class="{bar_class}" style="width:{score}%"></div></div>
    </div>
  </div>

  <div class="card">
    <h2>Summary</h2>
    <div class="summary">
      <div class="item"><div class="num num-critical">{c_critical}</div><div class="lbl">Critical</div></div>
      <div class="item"><div class="num num-high">{c_high}</div><div class="lbl">High</div></div>
      <div class="item"><div class="num num-medium">{c_medium}</div><div class="lbl">Medium</div></div>
      <div class="item"><div class="num num-low">{c_low}</div><div class="lbl">Low</div></div>
      <div class="item"><div class="num num-info">{c_info}</div><div class="lbl">Info</div></div>
    </div>
  </div>

  <h2 style="font-size:16px;color:var(--muted);text-transform:uppercase;letter-spacing:0.8px;margin:28px 0 16px;">Findings</h2>
  {findings_html}

  <div class="footer">
    nexSSH v{version} &middot; Read-only SSH audit &middot; {timestamp}
  </div>
</div>
</body>
</html>
"""

FINDING_TEMPLATE = """
<div class="finding {sev_lower}">
  <div class="f-header">
    <span class="badge {sev_lower}">{severity}</span>
    <span class="f-id">{fid}</span>
    <span class="f-title">{title}</span>
  </div>
  <div class="f-desc">{description}</div>
  <div class="f-block">
    <div class="label">Current Value</div>
    <div class="value">{current_value}</div>
  </div>
  <div class="f-block">
    <div class="label">Recommendation</div>
    <div class="value rec">{recommendation}</div>
  </div>
</div>
"""


def _html_escape(s: str) -> str:
    return (str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;"))


def render_html(system_info: Dict[str, Any], ssh_info: Dict[str, Any],
                findings: List[Finding], score: int) -> str:
    findings_sorted = sort_findings(findings)
    counts = count_by_severity(findings_sorted)

    parts: List[str] = []
    for f in findings_sorted:
        parts.append(FINDING_TEMPLATE.format(
            sev_lower=f.severity.lower(),
            severity=f.severity,
            fid=_html_escape(f.id),
            title=_html_escape(f.title),
            description=_html_escape(f.description),
            current_value=_html_escape(f.current_value),
            recommendation=_html_escape(f.recommendation),
        ))

    if score >= 80:
        score_class, bar_class = "score-ok", "bar-ok"
    elif score >= 60:
        score_class, bar_class = "score-mid", "bar-mid"
    else:
        score_class, bar_class = "score-bad", "bar-bad"

    return HTML_TEMPLATE.format(
        version=VERSION,
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        os_name=_html_escape(system_info.get("os", "Unknown")),
        kernel=_html_escape(system_info.get("kernel", "Unknown")),
        ssh_version=_html_escape(ssh_info.get("version", "unknown")),
        ssh_port=_html_escape(str(ssh_info.get("port", "unknown"))),
        service_status=_html_escape(ssh_info.get("service", "unknown")),
        config_source=_html_escape(ssh_info.get("config_source", "unknown")),
        score=score,
        score_class=score_class,
        bar_class=bar_class,
        c_critical=counts.get("CRITICAL", 0),
        c_high=counts.get("HIGH", 0),
        c_medium=counts.get("MEDIUM", 0),
        c_low=counts.get("LOW", 0),
        c_info=counts.get("INFO", 0),
        findings_html="\n".join(parts) if parts else "<div class='card'>No findings.</div>",
    )


def _build_ssh_info(cfg: SSHConfig) -> Dict[str, Any]:
    ports = get_ssh_ports(cfg)
    svc = get_service_status()
    return {
        "version": get_ssh_version(cfg.sshd_path),
        "port": ", ".join(str(p) for p in ports),
        "service": f"{svc['name']} ({svc['active']})" if svc["name"] != "unknown" else "unknown",
        "config_source": cfg.source,
    }


def render_terminal(system_info: Dict[str, Any], ssh_info: Dict[str, Any],
                    findings: List[Finding], score: int, duration: float,
                    report_path: Optional[str] = None) -> None:
    color = _support_color()
    findings_sorted = sort_findings(findings)
    counts = count_by_severity(findings_sorted)

    print(BANNER.format(VERSION=VERSION))

    if score >= 80:
        sc = FG_GRN
    elif score >= 60:
        sc = FG_YEL
    else:
        sc = FG_RED

    score_str = f"{sc}{score}/100{RESET}" if color else f"{score}/100"

    print(f"  {DIM if color else ''}Target{RESET if color else ''}    {system_info.get('os', 'Unknown')} / {system_info.get('kernel', 'Unknown')}")
    print(f"  {DIM if color else ''}SSH{RESET if color else ''}       {ssh_info.get('version', 'unknown')}")
    print(f"  {DIM if color else ''}Port{RESET if color else ''}      {ssh_info.get('port', 'unknown')}")
    print(f"  {DIM if color else ''}Service{RESET if color else ''}   {ssh_info.get('service', 'unknown')}")
    print()
    print(f"  {BOLD if color else ''}Score{RESET if color else ''}     {score_str}")
    print()

    sev_line = "  "
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        n = counts.get(sev, 0)
        label = f"{sev[0]}:{n}"
        if color and sev in ("CRITICAL", "HIGH", "MEDIUM") and n > 0:
            sev_line += f"{SEVERITY_COLOR[sev]}{label}{RESET}  "
        else:
            sev_line += f"{label}  "
    print(sev_line)
    print()

    if report_path:
        print(f"  {DIM if color else ''}Report{RESET if color else ''}    {report_path}")
    print(f"  {DIM if color else ''}Duration{RESET if color else ''}  {duration:.2f}s")
    print()


def render_json(system_info: Dict[str, Any], ssh_info: Dict[str, Any],
                findings: List[Finding], score: int) -> str:
    findings_sorted = sort_findings(findings)
    payload = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "system": {
            "os": system_info.get("os", "Unknown"),
            "kernel": system_info.get("kernel", "Unknown"),
        },
        "ssh": {
            "version": ssh_info.get("version", "unknown"),
            "port": ssh_info.get("port", "unknown"),
            "service": ssh_info.get("service", "unknown"),
            "config_source": ssh_info.get("config_source", "unknown"),
        },
        "score": score,
        "summary": count_by_severity(findings_sorted),
        "findings": [f.to_dict() for f in findings_sorted],
    }
    return json.dumps(payload, indent=4, ensure_ascii=False)


def write_report(path: Path, content: str) -> bool:
    try:
        if path.exists():
            path.unlink()
        path.write_text(content, encoding="utf-8")
        return True
    except OSError:
        return False


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="nexSSH — Linux SSH Security Auditor (read-only)",
        epilog="Audits SSH configuration, permissions, and service state. Never modifies anything.",
    )
    parser.add_argument("--all", action="store_true", help="Run all checks (default).")
    parser.add_argument("--auth", action="store_true", help="Authentication checks only.")
    parser.add_argument("--access", action="store_true", help="Access control checks only.")
    parser.add_argument("--permissions", action="store_true", help="File permission checks only.")
    parser.add_argument("--network", action="store_true", help="Network/port checks only.")
    parser.add_argument("--service", action="store_true", help="Service checks only.")
    parser.add_argument("--crypto", action="store_true", help="Cryptography checks only.")
    parser.add_argument("--json", action="store_true", help="Output JSON (no terminal, no report).")
    parser.add_argument("--no-report", action="store_true", help="Do not write HTML report.")
    parser.add_argument("--report", metavar="FILE",
                        help="HTML report path (default: nexssh_report.html).")
    parser.add_argument("--quiet", action="store_true", help="Suppress terminal output.")
    parser.add_argument("--verbose", action="store_true", help="Verbose output.")
    parser.add_argument("--no-banner", action="store_true", help="Hide the ASCII banner.")
    parser.add_argument("--version", action="version", version=f"{TOOL_NAME} v{VERSION}")
    return parser.parse_args(argv)


def _enabled_groups(args: argparse.Namespace) -> Optional[List[str]]:
    groups: List[str] = []
    if args.auth:
        groups.append("auth")
    if args.access:
        groups.append("access")
    if args.permissions:
        groups.append("permissions")
    if args.network:
        groups.append("network")
    if args.service:
        groups.append("service")
    if args.crypto:
        groups.append("crypto")
    if args.all or not groups:
        return None
    return groups


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    start = datetime.now()

    if args.verbose:
        print(f"[{TOOL_NAME}] starting audit...", file=sys.stderr)

    if not is_root() and not args.quiet and not args.json:
        print(f"[{TOOL_NAME}] note: not running as root. Some checks may be incomplete.",
              file=sys.stderr)

    cfg = SSHConfig(verbose=args.verbose)
    cfg.discover()

    if args.verbose:
        print(f"[{TOOL_NAME}] config source: {cfg.source}", file=sys.stderr)
        for err in cfg.errors:
            print(f"[{TOOL_NAME}] {err}", file=sys.stderr)

    enabled = _enabled_groups(args)
    findings = run_all_checks(cfg, verbose=args.verbose, enabled=enabled)
    score = compute_score(findings)
    duration = (datetime.now() - start).total_seconds()

    system_info = {
        "os": get_os_pretty(),
        "kernel": get_kernel(),
    }
    ssh_info = _build_ssh_info(cfg)

    if args.json:
        print(render_json(system_info, ssh_info, findings, score))
        return 0

    report_path: Optional[str] = None
    if not args.no_report:
        target = Path(args.report) if args.report else Path.cwd() / "nexssh_report.html"
        html = render_html(system_info, ssh_info, findings, score)
        if write_report(target, html):
            report_path = str(target)
            if args.verbose:
                print(f"[{TOOL_NAME}] report written: {target}", file=sys.stderr)
        else:
            print(f"[{TOOL_NAME}] warning: could not write report to {target}",
                  file=sys.stderr)

    if not args.quiet:
        if args.no_banner:
            print(f"{TOOL_NAME} v{VERSION}")
        else:
            render_terminal(system_info, ssh_info, findings, score, duration, report_path)

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n[{TOOL_NAME}] interrupted.", file=sys.stderr)
        sys.exit(130)