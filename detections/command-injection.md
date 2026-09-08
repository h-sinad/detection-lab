# Detection — Command Injection

**Technique:** T1059 — Command and Scripting Interpreter
**Rule:** _TODO — Phase 3 (Wazuh)_
**Status:** Draft — attack captured, detection pending SIEM

## Attack

OS command injection against DVWA's Command Injection module. The page runs
`ping <input>` on the server via a shell. Because the input is passed to the
shell unsanitised, a shell metacharacter (`;`) can be used to terminate the
intended `ping` command and append an arbitrary second command, which the server
then executes as the web-server user.

This is the highest-severity of the web attacks tested: the interpreter reached
is the operating system shell itself, so successful injection means arbitrary
command execution on the host — the starting point for full server compromise.

| Field | Value |
|-------|-------|
| Target | `http://192.168.122.1:8080/vulnerabilities/exec/` |
| Configuration | DVWA security level: low |
| Attacker | Kali VM (192.168.122.0/24) |
| Time run | 2026-09-08 01:31:52 (approx)|

### Steps

1. **Baseline** — input `127.0.0.1` returned normal `ping` output. Confirms the
   app runs a real shell command containing user input.
2. **Command chaining** — input `127.0.0.1; whoami` returned the ping output
   followed by the web-server user (e.g. `www-data`). The `;` ends the `ping`
   command and starts a second one. Confirms arbitrary command execution.
3. **Filesystem read** — input `127.0.0.1; ls` returned the ping output followed
   by a directory listing (`help`, `index.php`, `source`), confirming filesystem
   access as the web user.

### Shell separators

The `;` used here is one of several shell metacharacters that enable chaining. A
detection rule must account for all of them, not just `;`:

| Separator | Behaviour |
|-----------|-----------|
| `;` | Run the second command unconditionally |
| `&&` | Run the second only if the first succeeds |
| `\|` | Pipe the first command's output into the second |
| `` `cmd` `` / `$(cmd)` | Command substitution — runs inline, works even when `;` is filtered |

## Log evidence

The underlying vulnerable pattern is a shell invocation of the form:

```
ping -c 4 <input>
```

With the injection payload, the server executes:

```
ping -c 4 127.0.0.1 ; whoami
```

Request as seen on the wire (POST body, URL-encoded):

```
POST /vulnerabilities/exec/ HTTP/1.1
Content-Type: application/x-www-form-urlencoded

ip=127.0.0.1; whoami&Submit=Submit
```

_Note: the request line above shows the payload (`ip=127.0.0.1; whoami`) as it
was *sent*, but Apache's default access log does NOT record POST bodies. The
actual logged line is only `POST /vulnerabilities/exec/` — the payload is
absent. This shapes the detection (see False positives).

## The rule

### Custom rule (authored)

Wazuh's default rule 31108 ("Ignored URLs") matches these requests at level 0 —
i.e. it actively *silences* them. So command injection to this endpoint produced
no alert at all by default: a detection gap. This custom rule chains off 31108
to override that suppression and raise an alert.

`/var/ossec/etc/rules/local_rules.xml`:

```xml
<group name="web,attack,command-injection,">
  <rule id="100400" level="8">
    <if_sid>31108</if_sid>
    <url>/vulnerabilities/exec/</url>
    <protocol>POST</protocol>
    <description>Possible command injection, POST to command-exec endpoint</description>
    <mitre>
      <id>T1059</id>
    </mitre>
    <group>command-injection,web-attack</group>
  </rule>
</group>
```

Design decisions: chained off 31108 to override a default that was silencing
these requests; level 8 (not 12) because the payload is NOT visible in the log
(see limitation below) — this is suspicion, not confirmation, and severity
reflects that; mapped to MITRE T1059.

## Alert

Rule 100400 firing live on a command injection attempt:

```
** Alert 1788831112.1543: - web,attack,command-injection,command-injection,web-attack
2026 Sep 08 01:31:52 (danish) any->/home/danish/lab/dvwa/logs/access.log
Rule: 100400 (level 8) -> 'Possible command injection, POST to command-exec endpoint'
Src IP: 172.18.0.1
172.18.0.1 - - [08/Sep/2026:01:31:51 +0000] "POST /vulnerabilities/exec/ HTTP/1.1" 302 429 "-" "curl/8.21.0"
```

## False positives

This rule fires on ANY POST to /vulnerabilities/exec/, including legitimate use.
Verified directly: a benign ping (`ip=127.0.0.1`, no injection) triggers the
same alert as an actual attack (`ip=127.0.0.1;whoami`).

Root cause: Apache's default access log does NOT record POST request bodies, so
the injected command (`;whoami`) never reaches the log Wazuh reads. The rule can
only match on method + endpoint, which are identical for attack and normal use.

This is a fundamental limitation: **detection quality is capped by log quality.**
You cannot detect on data that was never logged.

Proper fix (not yet implemented): reconfigure Apache to log POST bodies (custom
LogFormat), or add a WAF / mod_security in front, so the payload becomes visible.
The rule could then match `;`, `&&`, `whoami`, `cat`, etc. and distinguish attack
from legitimate ping — allowing a higher, confident severity.

## What this misses

Because the rule matches only endpoint + method (not payload), it misses nothing
*additional* about the attack — but it also cannot distinguish attacks from
legitimate use (see False positives). Beyond that:

- It only covers this one endpoint (/vulnerabilities/exec/). Command injection
  on any other endpoint would need its own rule.
- Payload-based evasion is moot here — nothing about the payload is inspected,
  so encoding tricks, alternative separators (&&, |, backticks), and specific
  commands are all invisible either way.
- Confirming a command actually *executed* (vs. was merely attempted) needs
  host-level process telemetry on the server — e.g. Sysmon/auditd watching for
  processes spawned by the web server user. This is the Phase 4 argument.