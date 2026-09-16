#!/usr/bin/env python3
"""AI Security Log Analyser

Sends the last N lines of a Linux auth.log to a locally-hosted LLM
(via Ollama) and prints the model's security assessment.

Usage:
    v1 (plain prompt, free-text answer):
        python analyser.py auth.log --prompt prompts/v1.txt

    v2 (system prompt, structured JSON answer):
        python analyser.py auth.log --system prompts/v2_system.txt --prompt prompts/v2_user.txt --json
"""

import argparse
import json
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


def build_prompt(template_path: Path, logs: str) -> str:
    """Insert the log lines into the prompt template at {logs}."""
    template = template_path.read_text(encoding="utf-8")
    if "{logs}" not in template:
        raise ValueError(f"{template_path} has no {{logs}} placeholder")
    # str.replace rather than str.format: log lines can contain braces
    return template.replace("{logs}", logs)


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

    prompt = build_prompt(args.prompt, logs)
    system = args.system.read_text(encoding="utf-8") if args.system else None

    print(f"Model:  {args.model}")
    print(f"Prompt: {args.prompt.name}" + (f" + system {args.system.name}" if args.system else ""))
    print(f"Output: {'JSON' if args.json else 'free text'}")
    print(f"Lines:  {logs.count(chr(10))} from {args.logfile}")
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
    else:
        print(reply.strip())
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
