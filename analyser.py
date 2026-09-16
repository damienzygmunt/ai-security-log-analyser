#!/usr/bin/env python3
"""AI Security Log Analyser - v1

Sends the last N lines of a Linux auth.log to a locally-hosted LLM
(via Ollama) and prints the model's security assessment.

Usage:
    python analyser.py auth.log
    python analyser.py auth.log --lines 50 --prompt prompts/v1.txt
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


def ask_ollama(prompt: str, model: str, num_ctx: int) -> str:
    """Send the prompt to the local Ollama API and return the reply text."""
    payload = json.dumps({
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0,     # repeatable output, so prompt versions can be compared fairly
            "num_ctx": num_ctx,   # Ollama's default context is small and silently truncates long logs
        },
    }).encode("utf-8")

    request = urllib.request.Request(
        OLLAMA_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=600) as response:
        body = json.loads(response.read().decode("utf-8"))
    return body["response"]


def main() -> int:
    parser = argparse.ArgumentParser(description="LLM-assisted triage of Linux auth logs")
    parser.add_argument("logfile", type=Path, help="path to auth.log")
    parser.add_argument("--lines", type=int, default=100, help="number of lines from the end to analyse (default: 100)")
    parser.add_argument("--model", default=DEFAULT_MODEL, help=f"Ollama model (default: {DEFAULT_MODEL})")
    parser.add_argument("--prompt", type=Path, default=DEFAULT_PROMPT, help="prompt template file")
    parser.add_argument("--ctx", type=int, default=8192, help="model context size in tokens (default: 8192)")
    args = parser.parse_args()

    if not args.logfile.is_file():
        print(f"Error: log file not found: {args.logfile}", file=sys.stderr)
        return 1
    if not args.prompt.is_file():
        print(f"Error: prompt file not found: {args.prompt}", file=sys.stderr)
        return 1

    logs = read_last_lines(args.logfile, args.lines)
    if not logs.strip():
        print("Error: log file is empty", file=sys.stderr)
        return 1

    prompt = build_prompt(args.prompt, logs)
    line_count = logs.count("\n")

    print(f"Model:  {args.model}")
    print(f"Prompt: {args.prompt.name}")
    print(f"Lines:  {line_count} from {args.logfile}")
    print("Analysing... (this can take a minute on a local model)\n")

    try:
        verdict = ask_ollama(prompt, args.model, args.ctx)
    except urllib.error.HTTPError as e:
        print(f"Ollama returned an error: {e.code} {e.read().decode(errors='replace')}", file=sys.stderr)
        return 1
    except urllib.error.URLError as e:
        print(f"Could not reach Ollama at {OLLAMA_URL} ({e.reason}).", file=sys.stderr)
        print("Is Ollama running? Try: ollama serve", file=sys.stderr)
        return 1

    print("=" * 60)
    print(verdict.strip())
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
