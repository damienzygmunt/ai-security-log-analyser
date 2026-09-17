#!/usr/bin/env python3
"""AI Security Log Analyser

Sends the last N lines of a Linux auth.log to a locally-hosted LLM
(via Ollama) and prints the model's security assessment.

Usage:
    v1 (plain prompt, free-text answer):
        python analyser.py auth.log --prompt prompts/v1.txt

    v2 (system prompt, structured JSON answer):
        python analyser.py auth.log --system prompts/v2_system.txt --prompt prompts/v2_user.txt --json

    v4 (parser facts, used when the prompt contains {facts}):
        python analyser.py auth.log --system prompts/v4_system.txt --prompt prompts/v4_user.txt --json

    v5 (risk-ranked facts, used when the prompt contains {risk_facts}):
        python analyser.py auth.log --system prompts/v5_system.txt --prompt prompts/v5_user.txt --json

    Add --check to run the parser checks and guardrail on any JSON run, e.g.
        python analyser.py auth.log --system prompts/v2_system.txt --prompt prompts/v2_user.txt --json --check
"""

import argparse
import ipaddress
import json
import re
import sys
import urllib.error
import urllib.request
from collections import deque
from pathlib import Path

OLLAMA_URL = "http://localhost:11434/api/generate"
DEFAULT_MODEL = "llama3.1:8b"
DEFAULT_PROMPT = Path(__file__).parent / "prompts" / "v1.txt"

# Fields the model must return in JSON mode. Passed to Ollama so the
# output is constrained to this shape, then checked again in Python.
VERDICT_SCHEMA = {
    "type": "object",
    "properties": {
        "suspicious": {"type": "boolean"},
        "attack_type": {"type": "string"},
        "source_ips": {"type": "array", "items": {"type": "string"}},
        "targeted_users": {"type": "array", "items": {"type": "string"}},
        "failed_attempts": {"type": "integer"},
        "summary": {"type": "string"},
        "first_action": {"type": "string"},
    },
    "required": [
        "suspicious", "attack_type", "source_ips", "targeted_users",
        "failed_attempts", "summary", "first_action",
    ],
}


def read_last_lines(log_path: Path, n: int) -> str:
    """Return the last n lines of the log as one string."""
    with log_path.open("r", encoding="utf-8", errors="replace") as f:
        return "".join(deque(f, maxlen=n))


# --- Log parsing -----------------------------------------------------------

# The username in sshd lines is chosen by whoever connects, so it is attacker-
# controlled text. Patterns are therefore:
#   - anchored to the start of the line (timestamp, host, program), so text
#     inside a username can't be mistaken for a separate log entry
#   - greedy on the username, so the LAST "from <ip> port <n>" in the line is
#     used and a username can't spoof a different source IP
PREFIX = r"^(?P<ts>\d{4}-\d{2}-\d{2}T\S+|\w{3}\s+\d+\s[\d:]+) \S+ "
SSHD = r"sshd(?:-session)?\[\d+\]: "
IP = r"(?P<ip>[0-9A-Fa-f:.]+)"
USER = r"(?:invalid user )?(?P<user>.*)"
FAILED_RE = re.compile(rf"{PREFIX}{SSHD}Failed password for {USER} from {IP} port \d+")
REPEATED_RE = re.compile(rf"{PREFIX}{SSHD}message repeated (?P<n>\d+) times: \[ Failed password for {USER} from {IP} port \d+")
ACCEPTED_RE = re.compile(rf"{PREFIX}{SSHD}Accepted \S+ for {USER} from {IP} port \d+")
SUDO_RE = re.compile(rf"{PREFIX}sudo(?:\[\d+\])?:\s+(?P<user>\S+) : .*COMMAND=(?P<cmd>.+)$")

# Valid Linux usernames: no spaces, max 32 characters. Anything else in a
# username field is treated as possibly injected text and never passed to the
# model through the facts.
VALID_USERNAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9._-]{0,31}\$?$")

# Internal address ranges. Checked explicitly because Python's is_private
# also covers documentation ranges (e.g. 203.0.113.0/24), which test logs use
# to stand in for public attackers.
INTERNAL_NETWORKS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",   # RFC 1918
    "127.0.0.0/8", "169.254.0.0/16",                    # loopback, link-local
    "::1/128", "fc00::/7", "fe80::/10",                 # IPv6 equivalents
)]

# Risk rules (v5). Kept as constants so they are easy to find and tune.
COMPROMISE_MIN_FAILURES = 3      # failures before a success that count as a compromise indicator
REPEATED_FAILURES = 5            # failures that count as persistent
MANY_USERS = 3                   # distinct usernames that suggest username guessing
SENSITIVE_COMMANDS = ("/etc/shadow", "/etc/passwd", "/etc/sudoers", "useradd", "usermod",
                      "passwd", "chmod", "chown", "crontab", "wget", "curl", "nc ", "authorized_keys")


def is_internal(ip) -> bool:
    """True if the address is in a private, loopback or link-local range."""
    return any(ip.version == net.version and ip in net for net in INTERNAL_NETWORKS)


def safe_username(name: str) -> tuple[str, bool]:
    """Return (name to show, is_valid). Invalid names are replaced by a placeholder."""
    if VALID_USERNAME_RE.match(name):
        return name, True
    return f"[invalid username, {len(name)} chars]", False


def extract_facts(logs: str) -> dict:
    """Parse SSH logins per source IP, plus sudo commands after suspicious logins.

    A 'message repeated N times: [ Failed password ... ]' line stands for
    N further failures. Other lines that describe the same attempts again
    (PAM summaries, connection resets) are deliberately not counted.
    """
    per_ip = {}
    sudo_events = []   # (line number, user, command)

    def record(ip_text, user, lineno, timestamp, failed=0, accepted=0):
        try:
            ip = ipaddress.ip_address(ip_text)
        except ValueError:
            return
        entry = per_ip.setdefault(str(ip), {
            "ip": str(ip),
            "private": is_internal(ip),
            "failed_attempts": 0,
            "successful_logins": 0,
            "users": set(),
            "first_seen": timestamp,
            "last_seen": timestamp,
            "success_after_failures": [],   # (line number, user, failures before it)
            "invalid_usernames": 0,
        })
        user, valid = safe_username(user)
        if not valid:
            entry["invalid_usernames"] += 1
        if accepted and entry["failed_attempts"] >= COMPROMISE_MIN_FAILURES:
            entry["success_after_failures"].append((lineno, user, entry["failed_attempts"]))
        entry["failed_attempts"] += failed
        entry["successful_logins"] += accepted
        entry["users"].add(user)
        if timestamp:
            entry["first_seen"] = entry["first_seen"] or timestamp
            entry["last_seen"] = timestamp

    for lineno, line in enumerate(logs.splitlines()):
        if m := REPEATED_RE.match(line):
            record(m["ip"], m["user"], lineno, m["ts"], failed=int(m["n"]))
        elif m := FAILED_RE.match(line):
            record(m["ip"], m["user"], lineno, m["ts"], failed=1)
        elif m := ACCEPTED_RE.match(line):
            record(m["ip"], m["user"], lineno, m["ts"], accepted=1)
        elif m := SUDO_RE.match(line):
            sudo_events.append((lineno, m["user"], m["cmd"].strip()))

    ips = list(per_ip.values())
    for entry in ips:
        entry["users"] = sorted(entry["users"])
        # sudo commands run by a user after they logged in following failures
        entry["sudo_after_suspicious_login"] = [
            cmd for s_line, s_user, cmd in sudo_events
            if any(s_line > l_line and s_user == l_user
                   for l_line, l_user, _ in entry["success_after_failures"])
        ]
        score_risk(entry)

    ips.sort(key=lambda e: e["failed_attempts"], reverse=True)
    return {
        "total_failed_attempts": sum(e["failed_attempts"] for e in ips),
        "total_successful_logins": sum(e["successful_logins"] for e in ips),
        "source_ips": ips,
    }


def score_risk(entry: dict) -> None:
    """Add a risk score, level and list of reasons to a source IP entry."""
    score, reasons = 0, []
    if entry["success_after_failures"]:
        _, user, n = entry["success_after_failures"][0]
        score += 50
        reasons.append(f"successful login as {user} after {n} failed attempts (possible compromise)")
    sensitive = [c for c in entry["sudo_after_suspicious_login"]
                 if any(s in c for s in SENSITIVE_COMMANDS)]
    if sensitive:
        score += 30
        reasons.append("sensitive sudo commands after that login: " + "; ".join(sensitive))
    elif entry["sudo_after_suspicious_login"]:
        score += 10
        reasons.append("sudo commands after that login: " + "; ".join(entry["sudo_after_suspicious_login"]))
    if entry["failed_attempts"]:
        score += min(entry["failed_attempts"], 20)
    if entry["failed_attempts"] >= REPEATED_FAILURES:
        score += 10
        reasons.append(f"{entry['failed_attempts']} failed attempts")
    if len(entry["users"]) >= MANY_USERS and entry["failed_attempts"]:
        score += 10
        reasons.append(f"{len(entry['users'])} different usernames tried")
    if entry["invalid_usernames"]:
        score += 20
        reasons.append(f"{entry['invalid_usernames']} login attempts with invalid usernames "
                       "(text that is not a real username, possible log/prompt injection)")
    if not entry["private"] and entry["failed_attempts"]:
        score += 10
        reasons.append("public source address")

    if score >= 50:
        level = "critical"
    elif score >= 25:
        level = "high"
    elif score >= 10:
        level = "medium"
    elif score > 0:
        level = "low"
    else:
        level = "none"
    entry["risk_score"], entry["risk_level"], entry["risk_reasons"] = score, level, reasons


def format_facts(facts: dict) -> str:
    """v4 fact lines: counts per IP, ordered by failed attempts."""
    if not facts["source_ips"]:
        return "- No SSH login attempts found."
    lines = [
        f"- {e['ip']} ({'private' if e['private'] else 'public'} address): "
        f"{e['failed_attempts']} failed attempts, {e['successful_logins']} successful logins, "
        f"users: {', '.join(e['users'])}, first seen {e['first_seen']}, last seen {e['last_seen']}"
        for e in facts["source_ips"]
    ]
    lines.append(f"- Total failed attempts: {facts['total_failed_attempts']}")
    lines.append(f"- Total successful logins: {facts['total_successful_logins']}")
    return "\n".join(lines)


def format_risk_facts(facts: dict) -> str:
    """v5 fact lines: sources ranked by risk, with the reasons for each rank."""
    if not facts["source_ips"]:
        return "- No SSH login attempts found."
    ranked = sorted(facts["source_ips"], key=lambda e: e["risk_score"], reverse=True)
    lines = []
    for rank, e in enumerate(ranked, 1):
        lines.append(
            f"{rank}. {e['ip']} - risk {e['risk_level'].upper()} (score {e['risk_score']}) - "
            f"{'private' if e['private'] else 'public'} address, "
            f"{e['failed_attempts']} failed, {e['successful_logins']} successful, "
            f"users: {', '.join(e['users'])}"
        )
        for reason in e["risk_reasons"]:
            lines.append(f"   - {reason}")
    lines.append(f"Total failed attempts: {facts['total_failed_attempts']}")
    lines.append(f"Total successful logins: {facts['total_successful_logins']}")
    return "\n".join(lines)


# --- Prompting ---------------------------------------------------------------

PLACEHOLDER_RE = re.compile(r"\{(logs|facts|risk_facts)\}")


def build_prompt(template: str, values: dict) -> str:
    """Fill {logs}, {facts} and {risk_facts} placeholders in the template."""
    if "{logs}" not in template:
        raise ValueError("prompt template has no {logs} placeholder")
    # Single pass, so text inside the logs can never be treated as a placeholder
    return PLACEHOLDER_RE.sub(lambda m: values.get(m.group(1), ""), template)


def ask_ollama(prompt: str, model: str, num_ctx: int,
               system: str | None = None, json_mode: bool = False) -> str:
    """Send the prompt to the local Ollama API and return the reply text."""
    body = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0,     # repeatable output, so prompt versions can be compared fairly
            "num_ctx": num_ctx,   # Ollama's default context is small and silently truncates long logs
        },
    }
    if system:
        body["system"] = system
    if json_mode:
        body["format"] = VERDICT_SCHEMA

    request = urllib.request.Request(
        OLLAMA_URL,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=600) as response:
        reply = json.loads(response.read().decode("utf-8"))
    return reply["response"]


def parse_verdict(text: str) -> dict:
    """Parse the model's JSON reply and check every required field is present."""
    verdict = json.loads(text)
    missing = [k for k in VERDICT_SCHEMA["required"] if k not in verdict]
    if missing:
        raise ValueError(f"model reply is missing fields: {', '.join(missing)}")
    return verdict


# --- Checks on the model's verdict ---------------------------------------------

def check_against_facts(verdict: dict, facts: dict) -> None:
    """Compare the model's verdict with the parser's exact results."""
    expected = facts["total_failed_attempts"]
    got = verdict.get("failed_attempts")
    status = "OK" if got == expected else "MISMATCH"
    print(f"Check failed_attempts: model {got}, parser {expected} -> {status}")

    got_ips = set(verdict.get("source_ips", []))
    missing = [e for e in facts["source_ips"] if e["failed_attempts"] and e["ip"] not in got_ips]
    if not missing:
        print("Check source_ips with failures: OK (all listed)")
    else:
        details = ", ".join(f"{e['ip']} ({e['failed_attempts']} failed)" for e in missing)
        print(f"Check source_ips with failures: not listed by model: {details}")


def guardrail(verdict: dict, facts: dict) -> None:
    """Warn when the recommended action looks unsafe or misses the top risk (v5)."""
    action = verdict.get("first_action", "")
    warnings = []

    risky = [e for e in facts["source_ips"] if e["risk_level"] in ("critical", "high")]
    if risky and verdict.get("suspicious") is False:
        warnings.append("model says nothing is suspicious, but the parser rates "
                        + ", ".join(f"{e['ip']} {e['risk_level']}" for e in risky))

    for e in facts["source_ips"]:
        if e["private"] and e["ip"] in action and re.search(r"\bblock", action, re.I):
            warnings.append(f"first_action blocks internal address {e['ip']}; "
                            "identify and check that host before blocking")

    top = max(facts["source_ips"], key=lambda e: e["risk_score"], default=None)
    if top and top["risk_level"] in ("critical", "high") and top["ip"] not in action:
        warnings.append(f"first_action does not mention the highest-risk source {top['ip']} "
                        f"({top['risk_level']}: {'; '.join(top['risk_reasons']) or 'see facts'})")

    if not warnings:
        print("Guardrail: OK")
    for w in warnings:
        print(f"Guardrail WARNING: {w}")


def main() -> int:
    parser = argparse.ArgumentParser(description="LLM-assisted triage of Linux auth logs")
    parser.add_argument("logfile", type=Path, help="path to auth.log")
    parser.add_argument("--lines", type=int, default=100, help="number of lines from the end to analyse (default: 100)")
    parser.add_argument("--model", default=DEFAULT_MODEL, help=f"Ollama model (default: {DEFAULT_MODEL})")
    parser.add_argument("--prompt", type=Path, default=DEFAULT_PROMPT, help="prompt template file containing {logs}")
    parser.add_argument("--system", type=Path, help="optional system prompt file")
    parser.add_argument("--json", action="store_true", help="require structured JSON output")
    parser.add_argument("--ctx", type=int, default=8192, help="model context size in tokens (default: 8192)")
    parser.add_argument("--check", action="store_true",
                        help="with --json: run the parser checks and guardrail even if the prompt has no facts")
    args = parser.parse_args()

    for label, path in [("log file", args.logfile), ("prompt file", args.prompt), ("system prompt file", args.system)]:
        if path is not None and not path.is_file():
            print(f"Error: {label} not found: {path}", file=sys.stderr)
            return 1

    logs = read_last_lines(args.logfile, args.lines)
    if not logs.strip():
        print("Error: log file is empty", file=sys.stderr)
        return 1

    template = args.prompt.read_text(encoding="utf-8")
    uses_facts = "{facts}" in template
    uses_risk = "{risk_facts}" in template
    run_checks = args.json and (uses_facts or uses_risk or args.check)
    facts = extract_facts(logs) if (uses_facts or uses_risk or run_checks) else None
    values = {"logs": logs}
    if uses_facts:
        values["facts"] = format_facts(facts)
    if uses_risk:
        values["risk_facts"] = format_risk_facts(facts)

    try:
        prompt = build_prompt(template, values)
    except ValueError as e:
        print(f"Error: {args.prompt}: {e}", file=sys.stderr)
        return 1
    system = args.system.read_text(encoding="utf-8") if args.system else None

    print(f"Model:  {args.model}")
    print(f"Prompt: {args.prompt.name}" + (f" + system {args.system.name}" if args.system else ""))
    print(f"Output: {'JSON' if args.json else 'free text'}")
    print(f"Lines:  {logs.count(chr(10))} from {args.logfile}")
    if uses_risk:
        print("Parser facts (ranked by risk):")
        print(values["risk_facts"])
    elif uses_facts:
        print("Parser facts:")
        print(values["facts"])
    print("Analysing... (this can take a minute on a local model)\n")

    try:
        reply = ask_ollama(prompt, args.model, args.ctx, system, args.json)
    except urllib.error.HTTPError as e:
        print(f"Ollama returned an error: {e.code} {e.read().decode(errors='replace')}", file=sys.stderr)
        return 1
    except urllib.error.URLError as e:
        print(f"Could not reach Ollama at {OLLAMA_URL} ({e.reason}).", file=sys.stderr)
        print("Is Ollama running? Try: ollama serve", file=sys.stderr)
        return 1

    print("=" * 60)
    if args.json:
        try:
            verdict = parse_verdict(reply)
        except (json.JSONDecodeError, ValueError) as e:
            print(f"Invalid JSON from model: {e}\nRaw reply:\n{reply}", file=sys.stderr)
            return 1
        print(json.dumps(verdict, indent=2))
        if run_checks:
            print("-" * 60)
            check_against_facts(verdict, facts)
            if uses_risk or args.check:
                guardrail(verdict, facts)
    else:
        print(reply.strip())
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
