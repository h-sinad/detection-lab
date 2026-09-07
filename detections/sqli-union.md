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
| Time run | 2026-09-07 13:41:30 (approx) |

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

The Wazuh manager detected this via its built-in web ruleset. Raw alert from
`/var/ossec/logs/alerts/alerts.log`:

```
** Alert 1788788490.0: - web,accesslog,attack,sql_injection,pci_dss_6.5,...
2026 Sep 07 13:41:30 (danish) any->/home/danish/lab/dvwa/logs/access.log
Rule: 31103 (level 7) -> 'SQL injection attempt.'
Src IP: 172.18.0.1
172.18.0.1 - - [07/Sep/2026:13:41:29 +0000] "GET /vulnerabilities/sqli/?id=1' UNION SELECT 1,2-- -&Submit=Submit HTTP/1.1" 302 429
```

## The rule

Currently caught by Wazuh's built-in rule 31103 (level 7, generic SQL
injection). This is a default rule, not custom-authored. A higher-severity
custom rule for confirmed UNION-based data extraction is authored below.

### Custom rule (authored)

Wazuh's default rule 31103 catches SQLi generically at level 7. This custom
rule chains off it to escalate confirmed UNION-based data extraction to
level 12 (high), so an analyst triages active exfiltration ahead of mere probes.

`/var/ossec/etc/rules/local_rules.xml`:

```xml
<group name="web,attack,sql_injection,">
  <rule id="100200" level="12">
    <if_sid>31103</if_sid>
    <url>UNION SELECT|union select|UNION+SELECT|union+select</url>
    <description>SQLi: confirmed UNION-based data extraction attempt</description>
    <mitre>
      <id>T1190</id>
    </mitre>
    <group>sql_injection,data_exfiltration,</group>
  </rule>
</group>
```

Design decisions: chained via `if_sid` to build on the validated SQLi
detection rather than re-detect from scratch; level 12 because `UNION SELECT`
indicates confirmed extraction, not reconnaissance; ID in the 100000+ custom
range; mapped to MITRE T1190.

## Alert

Rule 100200 firing on a live UNION-based attack:

```
** Alert 1788791402.755: web,attack,sql_injection,data_exfiltration,
2026 Sep 07 14:30:02 (danish) any->/home/danish/lab/dvwa/logs/access.log
Rule: 100200 (level 12) -> 'SQLi: confirmed UNION-based data extraction attempt'
Src IP: 172.18.0.1
172.18.0.1 - - "GET /vulnerabilities/sqli/?id=1'+UNION+SELECT+1,2-- - ..." 302
```

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
