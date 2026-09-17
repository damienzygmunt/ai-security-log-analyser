# AI Security Log Analyser

A Python tool that performs first-pass triage of Linux authentication logs (`auth.log`) using a locally hosted LLM (Llama 3.1 8B via Ollama). It flags brute-force SSH activity, identifies source IPs and targeted accounts, and summarises findings for an analyst.

**Status:** in progress. See [PROMPT_NOTES.md](PROMPT_NOTES.md) for results from each prompt version.

## Why a local model?

Authentication logs contain usernames, IP addresses and hostnames. Sending them to a cloud AI API means shipping security data to a third party. Running the model locally through Ollama keeps the data on the machine: no external API, no cost per request, and it works offline.

## How it works

1. **Input** – reads the last N lines of `auth.log` (default 100).
2. **Parser** (v4) – Python counts failed and successful SSH logins per source IP, records users and first/last seen times, and classifies each IP as private or public using the `ipaddress` module.
3. **Prompt** – inserts the log lines (and, from v4, the parser facts) into a prompt template. Optionally adds a system prompt that sets the analyst role and rules.
4. **Model** – sends the request to Ollama's local API (`localhost:11434`).
5. **Output** – prints either a free-text answer (v1) or a JSON verdict (v2+) that is validated in Python.
6. **Cross-check** (v4) – compares the model's `failed_attempts` and `source_ips` with the parser's results and prints OK or MISMATCH.

Design choices:

- `temperature: 0` so output is repeatable and prompt versions can be compared fairly.
- `num_ctx: 8192` because Ollama's default context window is small and can silently truncate long logs, dropping the instructions.
- Prompts live in separate files under `prompts/`, so each version is tracked in Git.
- Placeholders are filled in a single regex pass rather than with `str.format`, so braces or placeholder-like text inside log lines can't alter the prompt.
- Counting and IP classification are done in code, not by the model, because the model got the count wrong in v2 and v3.

## Requirements

- Python 3.10+ (no third-party packages)
- [Ollama](https://ollama.com) (a recent version, for structured JSON output)
- The model: `ollama pull llama3.1:8b`

## Usage

v1 – plain prompt, free-text answer:

```
python analyser.py auth.log --prompt prompts/v1.txt
```

v2 – system prompt, structured JSON answer:

```
python analyser.py auth.log --system prompts/v2_system.txt --prompt prompts/v2_user.txt --json
```

v3 – adds a counting rule and few-shot examples (user prompt unchanged from v2):

```
python analyser.py auth.log --system prompts/v3_system.txt --prompt prompts/v2_user.txt --json
```

v4 – passes parser facts to the model and cross-checks the verdict (used automatically when the prompt contains `{facts}`):

```
python analyser.py auth.log --system prompts/v4_system.txt --prompt prompts/v4_user.txt --json
```

Options:

| Option | Default | Description |
|---|---|---|
| `--lines` | 100 | Number of lines from the end of the log to analyse |
| `--model` | `llama3.1:8b` | Ollama model to use |
| `--prompt` | `prompts/v1.txt` | Prompt template containing `{logs}` (and optionally `{facts}`) |
| `--system` | none | Optional system prompt file |
| `--json` | off | Require JSON output matching the verdict schema |
| `--ctx` | 8192 | Model context size in tokens |

Example v2 output:

```json
{
  "suspicious": true,
  "attack_type": "brute force SSH login attempt",
  "source_ips": ["10.0.3.2"],
  "targeted_users": ["sysadmin"],
  "failed_attempts": 8,
  "summary": "...",
  "first_action": "..."
}
```

## Test data

Logs come from my own Ubuntu Server VM. I generated repeated failed SSH logins against the `sysadmin` account, so the correct answer is known: SSH brute force from one source (10.0.3.2, the VirtualBox NAT address for the host), 12 failed attempts in the last 100 lines, followed by 1 successful login (my own, later). Log files are excluded from the repo via `.gitignore`.

## Results so far

| Version | Detected brute force | Source IP | Private IP noted | Failed attempts (actual: 12) | Machine-readable |
|---|---|---|---|---|---|
| v1 – plain prompt | Yes | Correct | No | Not reported | No |
| v2 – system prompt + JSON | Yes | Correct | Yes | 8 (wrong) | Yes |
| v3 – counting rule + few-shot | Yes | Correct | No (called it external) | 10 (wrong) | Yes |
| v4 – parser facts + cross-check | Yes | Correct | Yes | 12 (correct) | Yes |

v4 also flagged the successful login after the failures as a sign of possible compromise. Its recommended action was still to block the private IP, which the system prompt told it not to do first.

Full notes in [PROMPT_NOTES.md](PROMPT_NOTES.md).

## Known limitations

- Only the last N lines are analysed, so earlier activity can be missed.
- Without parser facts (v1–v3), the model miscounts failed attempts, particularly `message repeated N times` lines. v4 fixes this by counting in code.
- The model doesn't reliably follow reasoning rules: even in v4 it recommended blocking a private IP.
- The parser only recognises `Failed password`, `message repeated` and `Accepted` lines. Other auth events (e.g. `Invalid user` without a password attempt) aren't counted.
- Python's `is_private` also treats reserved and documentation ranges (e.g. 192.0.2.0/24) as private.
- With few-shot examples, the model copies example wording instead of applying the reasoning (v3 repeated Example 1's "block at the firewall" action for a private IP).
- Test data so far has a single source IP, so multi-source detection and false positives aren't yet tested.
- Only `auth.log` format is supported.
- Log content is passed to the model, so crafted log lines could attempt prompt injection. Not yet tested.

## Roadmap

- [x] v1: plain prompt
- [x] v2: system prompt and structured JSON output
- [x] v3: few-shot examples
- [x] v4: compute exact counts per IP in Python and pass them to the model
- [x] v4: classify private vs public IPs in Python (`ipaddress` module)
- [x] v4: cross-check the model's verdict against the parser
- [ ] Test logs with multiple IPs (public and private) and normal logins mixed in
- [ ] Python guardrail for unsafe recommended actions (e.g. blocking a private IP)
- [ ] Prompt-injection testing and defences

## Licence

MIT – see [LICENSE](LICENSE).
