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
| Time run | _fill in: timestamp_ |

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

_TODO Phase 3: replace with actual Wazuh/web server log lines once the agent is
collecting, and record the exact timestamp for correlation._

## The rule

_TODO — Phase 3. Detection will key on shell metacharacters and common command
names appearing in HTTP request parameters (e.g. `;`, `&&`, `|`, backticks,
`$(`, followed by tokens like `whoami`, `cat`, `id`, `ls`, `uname`). Rule to be
written and mapped once Wazuh is ingesting DVWA's logs._

## Alert

_TODO — Phase 3. Screenshot of the Wazuh alert firing, saved to `evidence/`._

## False positives

_TODO — Phase 3. Consider: parameters that legitimately contain semicolons or
ampersands (URL-encoded data, query strings with multiple values, some search
inputs). Shell metacharacters appear in benign traffic, so keyword-only matching
is noisy — note how the rule is tuned to require a metacharacter *plus* a command
token, or to scope to specific endpoints._

## What this misses

- **Encoding and obfuscation** — payloads using URL/hex encoding, whitespace
  alternatives (`${IFS}` in place of spaces), or variable expansion can evade
  literal metacharacter matching.
- **Blind command injection** — where the command runs but produces no output in
  the response (e.g. exfiltration via DNS, or time-based `sleep`), leaving no
  obvious content signal in the response.
- The log records the **attempt**. Confirming the command actually executed, and
  what it did, requires host-level telemetry (process creation on the server),
  not just web request logs — a strong argument for the Sysmon/endpoint work in
  Phase 4.
- Metacharacters split across parameters or delivered via less common vectors
  (headers, cookies) if only the primary parameter is inspected.
