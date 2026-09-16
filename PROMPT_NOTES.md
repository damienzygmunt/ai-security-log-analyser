\# Prompt Design Notes



Tracks each prompt version, what changed, and how detection quality compared.



\## Test setup

\- Log: auth.log from my own Ubuntu Server VM (ns1)

\- Test data: repeated failed SSH password logins I generated myself against the `sysadmin` account

\- Known answer: SSH brute-force pattern, single source 10.0.3.2 (VirtualBox NAT address for the host laptop)

\- Model: Llama 3.1 8B via Ollama, temperature 0, 8192-token context

\- Input: last 100 lines of auth.log



\## v1 – plain prompt (prompts/v1.txt)

Instructions and log lines sent as a single prompt, asking four questions:

suspicious yes/no, attack type, source IPs, summary.



\### What worked

\- Correctly flagged the activity as suspicious

\- Identified it as an SSH brute-force attempt

\- Named the targeted account (sysadmin)

\- Found the single source IP (10.0.3.2)



\### What didn't

\- Treated 10.0.3.2 as a possible external attacker; missed that it is a private

&#x20; (RFC 1918) address, which points to an internal source

\- Recommendations were generic (rate limiting, IP blocking) rather than based on the log

\- Output is free text with Markdown, so another program can't parse it



\### Next (v2)

\- Move the analyst role into a system prompt

\- Require structured JSON output with fixed fields

## v2 – system prompt + JSON output (prompts/v2_system.txt, prompts/v2_user.txt)
Analyst role and rules moved into a system prompt. Output constrained to a JSON
schema (suspicious, attack_type, source_ips, targeted_users, failed_attempts,
summary, first_action) and validated in Python.

### What improved
- Output is valid, machine-readable JSON; every required field present
- Still correctly flagged SSH brute force against sysadmin from 10.0.3.2
- Now states that 10.0.3.2 is a private address (v1 missed this)

### What didn't
- failed_attempts: model said 8, actual is 12 (checked with awk on the same 100 lines).
  Likely cause: each "message repeated 2 times: [Failed password ...]" line
  represents two failures, but the model counted it as one
- Noted the IP is private but didn't act on it: first_action was "block 10.0.3.2",
  which is the VirtualBox NAT address for my own host and would cut off legitimate
  access. A better action would be to identify the internal host behind it

### Takeaway
LLMs are unreliable at counting. Exact counts should be computed in Python and
passed to the model, leaving the model to interpret the pattern.

### Next (v3)
- Add few-shot examples, including a "message repeated" line with its correct count
- Test whether examples improve the count and the first_action

