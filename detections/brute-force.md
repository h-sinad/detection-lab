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

### Custom rules (authored)

Brute force is a frequency-based detection, not content-based — a single login
attempt is indistinguishable from legitimate use (verified: the access log shows
no difference between a failed and successful login). The signal is the *rate*:
many attempts from one source in a short window. This needs two chained rules.

```xml
<group name="web,attack,brute_force,">

  <rule id="100600" level="3">
    <if_sid>31100</if_sid>
    <url>/vulnerabilities/brute/</url>
    <description>Login attempt on brute-force endpoint</description>
    <group>authentication_attempt,</group>
  </rule>

  <rule id="100601" level="10" frequency="6" timeframe="30">
    <if_matched_sid>100600</if_matched_sid>
    <same_source_ip />
    <description>Brute force attack: multiple login attempts from same source</description>
    <mitre>
      <id>T1110</id>
    </mitre>
    <group>brute_force,authentication_failures,</group>
  </rule>

</group>
```

Design: 100600 is a low-severity "counter" that fires on each attempt; 100601
watches it via `if_matched_sid` and escalates to level 10 when 6+ attempts occur
within 30s from the *same source IP* (`same_source_ip` — critical, so distinct
users each logging in once don't trigger it). Threshold of 6-in-30s clears normal
human fumbling but catches automated brute force. Mapped to MITRE T1110.

## Alert

```
Rule: 100601 (level 10) -> 'Brute force attack: multiple login attempts from same source'
```

## False positives

This rule fires on request *rate*, so benign high-frequency activity can trigger
it. Considered cases:

- **A user fumbling their password.** Someone mistyping a few times is normal.
  The 6-in-30s threshold is set above typical human fumbling (most people don't
  make 6 attempts in half a minute) but low enough to catch an automated tool.
  This is the core tuning trade-off.
- **Shared NAT / proxy sources.** Many real users behind one public IP (corporate
  network, VPN, campus wifi) appear as a single source. Their combined legitimate
  logins could cross the threshold and false-positive, because `same_source_ip`
  can't tell "one attacker" from "many users sharing an IP." A production tuning
  would account for known NAT ranges.
- **Automation:** password managers retrying, health checks, or monitoring hitting
  the login endpoint could also trip it.

Chosen values: `frequency=6`, `timeframe=30s`. Reasoning: fast enough to catch an
automated brute force (which fires many attempts per second) while clearing normal
human retry behaviour. Against a fast tool like the custom `brute.py` (Phase 2),
which fired its attempts near-instantly, this threshold catches it comfortably.
The trade-off is documented in "What this misses" — a slow attacker pacing under
the threshold evades it.

## What this misses

- Low-and-slow brute force: an attacker pacing attempts below 6-per-30s (e.g.
  one every 10s) stays under the threshold and evades this rule entirely. The
  fundamental limit of any frequency threshold — tuning trades false positives
  against slow-attack coverage.
- Distributed brute force: attempts spread across many source IPs defeat
  `same_source_ip`, since no single IP crosses the threshold.
- Credential stuffing with a valid password may succeed on the first try — no
  burst, nothing to count.
- The log cannot distinguish failed from successful logins, so this counts
  *attempts*, not *failures* — it would also fire on a legitimate burst of rapid
  logins (rare, but possible).
