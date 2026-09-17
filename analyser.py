#!/usr/bin/env python3
"""AI Security Log Analyser

Sends the last N lines of a Linux auth.log to a locally-hosted LLM
(via Ollama) and prints the model's security assessment.

Usage:
    v1 (plain prompt, free-text answer):
        python analyser.py auth.log --prompt prompts/v1.txt

    v2 (system prompt, structured JSON answer):
        python analyser.py auth.log --system prompts/v2_system.txt --prompt prompts/v2_user.txt --json

    v4 (parser facts passed to the model; used automatically when the
        prompt template contains {facts}):
        python analyser.py auth.log --system prompts/v4_system.txt --prompt prompts/v4_user.txt --json
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

IP = r"(?P<ip>[0-9A-Fa-f:.]+)"
USER = r"(?:invalid user )?(?P<user>\S+)"
FAILED_RE = re.compile(rf"(?<!\[ )Failed password for {USER} from {IP} port")
REPEATED_RE = re.compile(rf"message repeated (?P<n>\d+) times: \[ Failed password for {USER} from {IP} port")
ACCEPTED_RE = re.compile(rf"Accepted \S+ for {USER} from {IP} port")
TIMESTAMP_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T[\d:.]+\S*|\w{3}\s+\d+\s[\d:]+)")


# Internal address ranges. Checked explicitly because Python's is_private
# also covers documentation ranges (e.g. 203.0.113.0/24), which test logs use
# to stand in for public attackers.
INTERNAL_NETWORKS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",   # RFC 1918
    "127.0.0.0/8", "169.254.0.0/16",                    # loopback, link-local
    "::1/128", "fc00::/7", "fe80::/10",                 # IPv6 equivalents
)]


def is_internal(ip) -> bool:
    """True if the address is in a private, loopback or link-local range."""
    return any(ip.version == net.version and ip in net for net in INTERNAL_NETWORKS)


def extract_facts(logs: str) -> dict:
    """Count failed and successful SSH logins per source IP.

    A 'message repeated N times: [ Failed password ... ]' line stands for
    N further failures. Other lines that describe the same attempts again
    (PAM summaries, connection resets) are deliberately not counted.
    """
    per_ip = {}

    def record(ip_text, user, failed=0, accepted=0, timestamp=None):
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
        })
        entry["failed_attempts"] += failed
        entry["successful_logins"] += accepted
        entry["users"].add(user)
        if timestamp:
            entry["first_seen"] = entry["first_seen"] or timestamp
            entry["last_seen"] = timestamp

    for line in logs.splitlines():
        ts_match = TIMESTAMP_RE.match(line)
        ts = ts_match.group(1) if ts_match else None
        if m := REPEATED_RE.search(line):
            record(m["ip"], m["user"], failed=int(m["n"]), timestamp=ts)
        elif m := FAILED_RE.search(line):
            record(m["ip"], m["user"], failed=1, timestamp=ts)
        elif m := ACCEPTED_RE.search(line):
            record(m["ip"], m["user"], accepted=1, timestamp=ts)

    ips = sorted(per_ip.values(), key=lambda e: e["failed_attempts"], reverse=True)
    for entry in ips:
        entry["users"] = sorted(entry["users"])
    return {
        "total_failed_attempts": sum(e["failed_attempts"] for e in ips),
        "total_successful_logins": sum(e["successful_logins"] for e in ips),
        "source_ips": ips,
    }


def format_facts(facts: dict) -> str:
    """Turn the parsed facts into plain lines for the prompt."""
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


# --- Prompting ---------------------------------------------------------------

def build_prompt(template_path: Path, logs: str, facts_text: str | None = None) -> str:
    """Fill the {logs} (and optional {facts}) placeholders in the template."""
    template = template_path.read_text(encoding="utf-8")
    if "{logs}" not in template:
        raise ValueError(f"{template_path} has no {{logs}} placeholder")
    values = {"logs": logs, "facts": facts_text or ""}
    # Single pass, so text inside the logs can never be treated as a placeholder
    return re.sub(r"\{(logs|facts)\}", lambda m: values[m.group(1)], template)


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


def main() -> int:
    parser = argparse.ArgumentParser(description="LLM-assisted triage of Linux auth logs")
    parser.add_argument("logfile", type=Path, help="path to auth.log")
    parser.add_argument("--lines", type=int, default=100, help="number of lines from the end to analyse (default: 100)")
    parser.add_argument("--model", default=DEFAULT_MODEL, help=f"Ollama model (default: {DEFAULT_MODEL})")
    parser.add_argument("--prompt", type=Path, default=DEFAULT_PROMPT, help="prompt template file containing {logs}")
    parser.add_argument("--system", type=Path, help="optional system prompt file")
    parser.add_argument("--json", action="store_true", help="require structured JSON output")
    parser.add_argument("--ctx", type=int, default=8192, help="model context size in tokens (default: 8192)")
    args = parser.parse_args()

    for label, path in [("log file", args.logfile), ("prompt file", args.prompt), ("system prompt file", args.system)]:
        if path is not None and not path.is_file():
            print(f"Error: {label} not found: {path}", file=sys.stderr)
            return 1

    logs = read_last_lines(args.logfile, args.lines)
    if not logs.strip():
        print("Error: log file is empty", file=sys.stderr)
        return 1

    template_text = args.prompt.read_text(encoding="utf-8")
    facts = extract_facts(logs) if "{facts}" in template_text else None
    facts_text = format_facts(facts) if facts else None
    prompt = build_prompt(args.prompt, logs, facts_text)
    system = args.system.read_text(encoding="utf-8") if args.system else None

    print(f"Model:  {args.model}")
    print(f"Prompt: {args.prompt.name}" + (f" + system {args.system.name}" if args.system else ""))
    print(f"Output: {'JSON' if args.json else 'free text'}")
    print(f"Lines:  {logs.count(chr(10))} from {args.logfile}")
    if facts_text:
        print("Parser facts:")
        print(facts_text)
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
        if facts:
            print("-" * 60)
            check_against_facts(verdict, facts)
    else:
        print(reply.strip())
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
