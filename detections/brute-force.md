# Detection — Login Brute Force

**Technique:** T1110 — Brute Force
**Rule:** _TODO — Phase 3 (Wazuh)_
**Status:** Draft — attack captured, detection pending SIEM

## Attack

Automated password guessing against DVWA's Brute Force login module. Unlike the
injection attacks, this exploits no parsing flaw — it uses the login form exactly
as intended, but submits guesses far faster than a human could and without any
rate limit, lockout, or CAPTCHA to stop it. The target account's password is
recovered by trying entries from a wordlist until the login succeeds.

A custom Python script (`brute.py`, in this repo) was written rather than using
Hydra, both because Hydra's form-syntax proved brittle for this endpoint and
because a self-authored tool demonstrates the mechanism more clearly.

| Field | Value |
|-------|-------|
| Target | `http://192.168.122.1:8080/vulnerabilities/brute/` |
| Configuration | DVWA security level: low |
| Attacker | Kali VM (192.168.122.23) |
| Tool | `brute.py` (custom), wordlist `rockyou.txt` |
| Username targeted | `admin` |
| Time run | 2026-09-01 ~08:03 |
| Result | Password `password` recovered in **4 attempts, <1 second** |

### How the tool works

- Submits the login form via HTTP GET, substituting each wordlist entry as the
  password for a fixed username.
- Carries the logged-in DVWA session cookie (`PHPSESSID` + `security=low`), which
  DVWA requires to reach this module — an artefact of DVWA being a training app
  behind its own login, not a feature of brute force in general.
- Detects success by the **absence** of DVWA's failure string
  (`Username and/or password incorrect.`) in the response. Same logic as Hydra's
  `F=` condition.
- Includes an upfront session-validity check so a stale cookie fails fast rather
  than silently reporting every attempt as a failure.

## Log evidence

Each guess is a login request. The attack appears as a burst of near-identical
requests from a single source in a very short window — three failures followed by
a success:

```
GET /vulnerabilities/brute/?username=admin&password=123456&Login=Login   (fail)
GET /vulnerabilities/brute/?username=admin&password=12345&Login=Login     (fail)
GET /vulnerabilities/brute/?username=admin&password=123456789&Login=Login (fail)
GET /vulnerabilities/brute/?username=admin&password=password&Login=Login  (success)
```

All from `192.168.122.23`, within the same second.

_TODO Phase 3: replace with actual Wazuh/web server + auth log lines once the
agent is collecting, and record exact timestamps._

## The rule

_TODO — Phase 3. Detection will key on a **threshold**: N failed authentication
events from the same source IP within a short time window. This is a frequency /
correlation rule, not a content-match rule — the individual requests are
individually legitimate; it is the *rate and repetition* that signal the attack.
Wazuh's built-in frequency rules (and the `<frequency>` / `<timeframe>` options)
are the mechanism. Map to T1110._

## Alert

_TODO — Phase 3. Screenshot of the Wazuh alert firing, saved to `evidence/`._

## False positives

_TODO — Phase 3. Consider: a legitimate user fat-fingering their password a few
times; shared NAT sources where many users appear as one IP; automated health
checks or password managers retrying. Tuning is mostly about setting the
threshold high enough to clear normal fumbling but low enough to catch an attack
— note the chosen values and the reasoning._

## What this misses

- **Low-and-slow brute force.** An attacker who guesses slowly — one attempt
  every few minutes, or spread across many source IPs — stays under any
  rate threshold and evades a frequency rule entirely. This is the fundamental
  limitation of threshold-based detection and worth stating plainly.
- **Credential stuffing** using valid credentials leaked elsewhere may succeed on
  the *first* try, producing no failed-login burst at all — nothing for a
  brute-force rule to catch.
- **Password spraying** (one common password against many usernames) inverts the
  pattern — few failures per account, so a per-account threshold misses it; needs
  a per-source-across-accounts view instead.
- The web log shows request volume; distinguishing a successful compromise from a
  failed spree cleanly may need the auth-success event correlated with the
  preceding failures.
