# Expected answer: multi_ip_auth.log

Synthetic test log (80 lines) for host `web01`. Written so the correct verdict
is known in advance. `203.0.113.0/24` and `198.51.100.0/24` are documentation
ranges standing in for public internet addresses.

## Sources

| IP | Type | Failed | Successful | Users | What happened | Correct assessment |
|---|---|---|---|---|---|---|
| 198.51.100.23 | Public | 3 | 1 | sysadmin | Slow password guessing, then a successful login, then `sudo cat /etc/shadow` | **Highest priority.** Likely compromised account with privilege use |
| 203.0.113.45 | Public | 15 | 0 | root, admin, test, oracle, ubuntu | Fast guessing of common usernames within ~30 seconds | External brute force, no success. Block |
| 192.168.1.50 | Private | 6 | 0 | backup | Two failures every 5 minutes | Internal. Misconfigured backup job (stale password) or compromised host. Investigate, don't just block |
| 10.0.0.5 | Private | 1 | 1 | alice | One typo, then success, then normal sudo | Normal. Should not be flagged |
| 192.168.1.20 | Private | 0 | 2 | deploy | Key-based logins | Normal. Should not be flagged |

Totals: 25 failed attempts, 4 successful logins.

## What a good verdict looks like

- `suspicious`: true
- `failed_attempts`: 25
- `source_ips`: includes 198.51.100.23, 203.0.113.45 and 192.168.1.50
  (10.0.0.5 is acceptable either way; 192.168.1.20 has no failures)
- Does not treat alice or deploy as attacks
- `first_action`: investigate the successful `sysadmin` login from
  198.51.100.23 (and its `sudo cat /etc/shadow`) before anything else,
  e.g. lock the account / terminate the session and review what it did

The key test is prioritisation: the loudest source (203.0.113.45) is not the
most dangerous one. The quiet source that got in is.
