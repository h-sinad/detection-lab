# What This Lab Cannot Detect

Every detection in this lab has blind spots. This document consolidates them —
not as an afterthought, but because knowing the limits of a detection is as much
a part of detection engineering as writing it. A rule that looks like coverage
but silently misses a class of attack is worse than no rule, because it creates
false confidence.

The limitations below fall into three themes: **you can't detect what isn't
logged**, **every threshold is a trade-off**, and **the log shows the attempt,
not the outcome**.

## Theme 1 — You can't detect what isn't logged

Detection quality is capped by log quality. Several attacks were invisible or
partially invisible not because the rule was weak, but because the relevant data
never reached the log.

**Command injection payloads (POST bodies).** DVWA's command-injection endpoint
receives its payload in the POST body, and Apache's default access log does not
record request bodies. So the injected command (`;whoami`, `; cat /etc/passwd`)
never appears in the log Wazuh reads. The rule (100400) can only match the
endpoint and method — meaning it cannot distinguish an actual attack from a
legitimate ping to the same page. This is why its severity is 8 (suspicion), not
12 (confirmation), and why it fires on benign traffic (verified live).
*Proper fix:* configure Apache to log POST bodies, or place a WAF / mod_security
in front, so the payload becomes matchable.

**DOM-based XSS.** Cross-site scripting that executes entirely client-side, in
the browser's DOM, never sends the payload to the server. There is no server-side
log entry at all, so no server-log rule can ever see it. Detecting it would
require client-side instrumentation, which is out of scope for a server-log SIEM.

## Theme 2 — Every threshold and signature is a trade-off

Detection rules draw a line. Attackers who stay on the safe side of that line are
missed; legitimate activity that crosses it produces false positives. Both
failure modes are real and were observed.

**Low-and-slow brute force.** The brute-force rule (100601) fires on 6+ attempts
from one IP within 30 seconds. An attacker pacing attempts slower than that — one
every ten seconds, say — never trips the threshold and is missed entirely. This
is the fundamental limit of any frequency rule: lowering the threshold to catch
slow attacks raises false positives on legitimate bursts, and vice versa. There
is no setting that catches both without cost.

**Distributed brute force.** The same rule requires the attempts to come from the
*same source IP* (`same_source_ip`) — the condition that makes it mean "one
attacker hammering the login" rather than "many users each logging in once."
That condition is also its blind spot: an attacker spreading attempts across many
IPs never crosses the per-IP threshold, and the attack passes unseen.

**Shared-IP false positives (the same weakness, inverted).** Because the rule
keys on source IP, many legitimate users behind one public IP (corporate NAT,
VPN, campus wifi) can look like a single aggressive source and trigger a false
alarm. The property that makes the rule precise against a single attacker makes
it wrong about shared infrastructure.

**Encoded and obfuscated payloads.** The signature-based rules match specific
strings. The XSS rule (100500) matches `script`, `%3Cscript`, and common event
handlers — but an attacker using mixed-case tags (`<ScRiPt>`), character-code
encoding, or a novel event-handler vector evades it. Likewise the SQLi rule keys
on `UNION SELECT`; heavily obfuscated or comment-broken variants
(`UN/**/ION`) would slip past. Broadening the signature catches more attacks but
raises false positives on benign traffic containing those substrings — the same
trade-off in a different form.

**Credential stuffing.** An attacker using a valid, leaked credential may succeed
on the first attempt. There is no burst of failures to count, so a brute-force
rule has nothing to fire on. This is a detection gap that frequency rules
structurally cannot close.

## Theme 3 — The log shows the attempt, not the outcome

Web access logs record that a request was *made*. They rarely record what
*happened* as a result.

**Attempt vs. success.** The access log cannot reliably distinguish a failed
login from a successful one (both may return the same status), nor a blocked
injection from one that exfiltrated data. The rules here detect that an attack
was *attempted*, which is valuable, but confirming *compromise* requires
correlating additional signals — response sizes, status codes, or downstream
events — that were out of scope.

**No proof of execution.** For command injection especially, the web log shows
the request arrived, but cannot show whether the injected command actually ran on
the server. Confirming execution requires host-level process telemetry — a tool
like Sysmon or auditd watching for processes spawned by the web-server user. This
is precisely the argument for endpoint detection, and the main reason the planned
Windows + Sysmon phase would strengthen this lab: it closes the gap between
"an attack was attempted" and "an attack succeeded."

## What this means

None of these gaps are failures of the individual rules — they are the honest
boundary of what web-server-log detection can do. A mature detection posture
layers sources: web logs catch the attempt at the perimeter, endpoint telemetry
confirms execution on the host, and network data catches what spans them. This
lab covers the first layer thoroughly and documents exactly where that layer
ends. Recognizing that boundary — rather than assuming a green dashboard means
full coverage — is the point.
