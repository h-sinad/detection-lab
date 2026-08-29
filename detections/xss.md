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

_TODO — Phase 3. Detection will key on script-related markup appearing in HTTP
request parameters and bodies (e.g. `<script`, `onerror=`, `onload=`,
`javascript:`, common event handlers). Rule to be written and mapped once Wazuh
is ingesting DVWA's logs._

## Alert

_TODO — Phase 3. Screenshot of the Wazuh alert firing, saved to `evidence/`._

## False positives

_TODO — Phase 3. Consider: forums, comment systems, or CMS admin fields where
users legitimately submit HTML or code snippets; security tooling and WAF logs
that themselves contain payload strings. Note how the rule is tuned._

## What this misses

- **Stored XSS is a two-part problem.** The malicious *request* (the POST that
  plants the payload) happens once and is detectable. But the payload then fires
  on later page loads whose requests contain **no attack content at all** —
  those loads look completely normal in the logs. A request-inspection rule sees
  the planting, not the ongoing execution. This gap is worth documenting
  explicitly.
- **Encoding and obfuscation** — payloads using HTML entities, URL encoding,
  `String.fromCharCode`, or event-handler vectors without the literal `<script>`
  string can evade naive keyword matching.
- **DOM-based XSS** — where the injection never reaches the server (handled
  entirely client-side in JavaScript) produces no server-side log at all.
- The log shows the **attempt**, not whether the script actually executed in any
  victim's browser.
