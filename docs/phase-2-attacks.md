# Phase 2 — Attack & Telemetry

**Status:** Complete
**Goal:** Run real attacks against the DVWA target from Kali and document each
one precisely, so that in Phase 3 the resulting telemetry can be located in the
logs and matched against detection rules.

## Summary

Four distinct attack classes were executed against DVWA from the Kali attacker
VM, each documented as a self-contained case in [`../detections/`](../detections).
The purpose was not exploitation — DVWA is trivially exploitable — but to
generate known, well-understood telemetry. Because each attack was run
deliberately, with its payload and timing recorded, Phase 3 can answer the
question that matters: *for each attack, did the SIEM see it, and could a rule
catch it?* This attack-to-log mapping is the foundation of the detection work.

## What was run

| Attack | Technique | Interpreter targeted | Detection file |
|--------|-----------|----------------------|----------------|
| SQL injection (UNION) | T1190 | Database | [sqli-union.md](../detections/sqli-union.md) |
| Cross-Site Scripting (reflected + stored) | T1059.007 | Browser | [xss.md](../detections/xss.md) |
| Command injection | T1059 | OS shell | [command-injection.md](../detections/command-injection.md) |
| Login brute force | T1110 | (none — auth abuse) | [brute-force.md](../detections/brute-force.md) |

## The through-line

Three of the four attacks are the **same underlying flaw** — untrusted input
crossing a boundary and being interpreted as instructions — aimed at three
different interpreters:

- **SQL injection** → input reaches the **database**, executed as a query.
- **XSS** → input reaches a **browser**, executed as JavaScript.
- **Command injection** → input reaches the **OS shell**, executed as a system
  command.

The severity rises with the interpreter's reach: a query exposes data, a browser
script hijacks a user's session, and a shell command owns the whole server.

The fourth attack, **brute force**, is deliberately different. It exploits no
parsing flaw — it uses the login exactly as designed, but abuses the absence of
rate limiting to guess at machine speed. It was included precisely because it
produces a different *kind* of signal: not malicious content in a single
request, but an anomalous *rate* of ordinary requests. That distinction matters
for Phase 3, because it needs a different detection approach (frequency /
correlation) than the content-matching rules the injection attacks call for.

The result is four different log signatures to detect, spanning both
content-based and frequency-based detection — a deliberately broader foundation
than four variations of the same attack would give.

## Tooling note

The brute force was carried out with a small custom Python script
([`../tools/brute.py`](../tools/brute.py)) rather than Hydra, after Hydra's
form-string syntax proved brittle against this endpoint. Writing the tool made
the mechanism explicit — a wordlist loop submitting login requests and detecting
success by the absence of the failure string — and is a clearer demonstration of
understanding than a working Hydra invocation would have been.

## Notes for Phase 3

Each detection file has its **detection half deliberately left as TODO** — the
rule, the alert screenshot, false-positive tuning, and the real log lines. Those
cannot be completed until Wazuh is ingesting DVWA's logs. Phase 3 fills them in:

- Stand up Wazuh and get it collecting the DVWA web/access logs.
- For each attack above, locate its telemetry by timestamp and record the real
  log line.
- Author a rule, map it to the technique already noted, and capture the alert.
- Tune out false positives and document what the rule still cannot see.

## Cleanup

The stored XSS payload planted in the guestbook was removed via
**Setup / Reset DB** to return the app to a clean state. Note that resetting the
DVWA container also clears the database and invalidates the session cookie, which
must be re-obtained after any container recreate.
