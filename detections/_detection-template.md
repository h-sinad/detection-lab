# Detection — [Attack name]

**Technique:** [MITRE ATT&CK ID and name, e.g. T1190 — Exploit Public-Facing Application]
**Rule:** [`rules/xxxxx.xml`](../rules/xxxxx.xml)
**Status:** [Draft | Validated | Tuned]

## Attack

[What was run, precisely enough to reproduce. The exact payload or command, the
target, the security level or configuration, and the timestamp it was run at.
The timestamp matters — it is how this attack is located in the logs.]

| Field | Value |
|-------|-------|
| Target | |
| Configuration | |
| Payload / command | |
| Time run | |

## Log evidence

[The raw log line(s) the attack produced, in a code block. This is the ground
truth the rule matches against. Trim to the relevant fields but do not
paraphrase — show the actual log.]

```
[raw log line here]
```

## The rule

[The Wazuh rule that fires on this, with a short explanation of what each part
matches and why the match is specific to this technique rather than to normal
activity.]

```xml
<rule id="100001" level="10">
  <!-- rule body -->
</rule>
```

## Alert

[Evidence the rule fired: a screenshot in `evidence/`, or the alert JSON. Link
or embed it.]

## False positives

[What benign activity could also trigger this rule, whether it was observed, and
how the rule was tuned to exclude it. This section is what separates a written
rule from a usable one — an untuned rule that fires on normal traffic is noise,
not a detection.]

## What this misses

[Honest limitations. Variants of the technique this rule would not catch,
evasions that defeat it, or conditions under which it produces no telemetry at
all. Feeds the repo-wide "what I couldn't detect" writeup.]
