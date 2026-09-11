# Detection — Cross-Site Scripting (Reflected & Stored)

**Technique:** T1059.007 — Command and Scripting Interpreter: JavaScript
**Rule:** _TODO — Phase 3 (Wazuh)_
**Status:** Draft — attack captured, detection pending SIEM

## Attack

Cross-Site Scripting against DVWA's Reflected and Stored XSS modules. User input
is rendered into the page without sanitisation, so injected markup is
interpreted by the browser as HTML/JavaScript rather than displayed as text.
This allows arbitrary script to execute in the browser of anyone viewing the
page. Both variants were tested to capture their different behaviours.

| Field | Value |
|-------|-------|
| Target (reflected) | `http://192.168.122.1:8080/vulnerabilities/xss_r/` |
| Target (stored) | `http://192.168.122.1:8080/vulnerabilities/xss_s/` |
| Configuration | DVWA security level: low |
| Attacker | Kali VM (192.168.122.0/24) |
| Time run | 2026-08-29 ~15:13 (approx) |

### Reflected

Input is echoed straight back in the immediate response and is not persisted.
Built up in stages:

1. **Baseline** — input `Danish` returned "Hello Danish". Input is reflected
   onto the page.
2. **HTML rendering test** — input `<b>test</b>` rendered as bold text,
   confirming input is interpreted as HTML, not escaped.
3. **Script execution** — input `<script>alert('XSS')</script>` executed,
   producing a JavaScript alert. Confirms arbitrary script execution.

Reflected XSS only affects a victim who is induced to submit the payload —
typically by clicking a crafted link that carries the script in the URL. The
script exists only in that single response.

### Stored

Input is saved server-side (the guestbook) and served to every subsequent
visitor.

1. **Inject** — submitted `<script>alert('stored')</script>` in the guestbook
   Message field. The alert fired on submission.
2. **Confirm persistence** — navigated away (Home) and back to the Stored XSS
   page. The alert fired again on a clean page load, with no resubmission. This
   confirms the payload is stored server-side and executes for anyone who views
   the page.

Stored XSS is more severe: the payload is planted once and runs automatically in
the browser of every visitor — including, in a real scenario, an administrator,
whose session could then be hijacked.

### Cleanup

The stored payload persists in the guestbook until removed. Cleared via
**Setup / Reset DB → Create / Reset Database** to return the app to a clean
state.

## Log evidence

Reflected — payload visible in the request query string:

```
GET /vulnerabilities/xss_r/?name=<script>alert('XSS')</script> HTTP/1.1
```

Stored — payload submitted via POST body (the request that plants it):

```
POST /vulnerabilities/xss_s/ HTTP/1.1
Content-Type: application/x-www-form-urlencoded

txtName=test&mtxMessage=<script>alert('stored')</script>&btnSign=Sign+Guestbook
```

_TODO Phase 3: replace with actual Wazuh/web server log lines once the agent is
collecting, and record exact timestamps for correlation._

## The rule

### Custom rule (authored)

Wazuh's default rule 31105 flags generic "XSS attempt" at level 6. This custom
rule chains off it and escalates to level 10 when a concrete script-injection
signature is present in the URL.

```xml
<group name="web,attack,xss,">
  <rule id="100500" level="10">
    <if_sid>31105</if_sid>
    <url>script|%3Cscript|onerror=|onload=|javascript:</url>
    <description>Reflected XSS: script injection attempt in URL parameter</description>
    <mitre>
      <id>T1059.007</id>
    </mitre>
    <group>xss,reflected_xss,web_attack,</group>
  </rule>
</group>
```

Design: chained off 31105 to escalate rather than duplicate; matches the
technique (script tags + common event-handler vectors) not a specific payload;
includes the URL-encoded form (%3Cscript) so a browser-encoded attack still
matches. Level 10 = confirmed signature vs. the default's heuristic level 6.
Mapped to MITRE T1059.007.

## Alert

```
Rule: 100500 (level 10) -> 'Reflected XSS: script injection attempt in URL parameter'
```

## False positives

Matching the bare word `script` is deliberately broad to catch raw `<script>`
without putting XML-breaking `<` characters in the rule. Trade-off: a benign URL
containing "script" as a substring (e.g. /scripts/app.js, ?ref=description) could
false-positive. A tighter rule would match `%3Cscript` or `script>` specifically,
trading coverage for precision. Verify against real traffic before production use.

## What this misses

- Stored XSS: the payload is submitted via POST body, which Apache's default log
  does not record (same limitation as command injection) — this rule only covers
  reflected XSS where the payload rides in the URL.
- DOM-based XSS: handled entirely client-side, never reaches the server log.
- Heavy obfuscation: mixed-case tags, char-code encoding, or novel event handlers
  beyond the listed set would evade the signature.
- The log shows the attempt, not whether the script executed in a victim's browser.
