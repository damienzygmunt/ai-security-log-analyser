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

