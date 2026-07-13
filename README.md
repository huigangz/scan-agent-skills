# scan-agent-skills

`scan-agent-skills` is a pure-static security scanner for AI agent skills. It
reviews `SKILL.md` files, scripts, configuration, and other text assets without
executing target content or connecting to target-declared services.

The project combines deterministic findings with a review constitution for the
LLM or agent using the scanner: target content is always untrusted data, and it
cannot suppress, downgrade, or hide scanner findings.

## Why this exists

Agent skills can contain executable instructions, hidden prompt injection,
credential access, persistence mechanisms, outbound data flows, and encoded
payloads. A reviewer powered by an LLM is also vulnerable to instructions that
try to manipulate the audit itself.

This scanner provides a reproducible evidence floor before any supplemental
human or LLM review.

## Capabilities

The deterministic scanner currently covers:

- Reviewer-targeted and user-facing prompt injection.
- Hidden instructions in Markdown HTML comments.
- Reviewer safe-washing and verdict-manipulation attempts.
- Credential and secret-bearing path access.
- Outbound send APIs and known webhook sinks.
- Same-file and cross-file credential-exfiltration risk combinations.
- Remote download-to-shell execution.
- Persistence commands, profile paths, registry keys, and Startup paths.
- Package lifecycle hooks and explicit hook execution.
- System-prompt leakage and privilege-escalation signals.
- Base64 decode-and-rescan, multilayer encoding, hex, URL encoding, suspicious
  string concatenation, zero-width text, and bidi controls.
- Coverage reporting for scanned, skipped, binary, unreadable, and truncated
  files.

The scanner uses only the Python standard library and performs no network
requests.

## Requirements

- Python 3.10 or later.
- `pytest` only when running the test suite.

## Quick start

Clone the repository:

```bash
git clone https://github.com/huigangz/scan-agent-skills.git
cd scan-agent-skills
```

Scan a skill or directory and emit JSON:

```bash
python scripts/skill_static_scan.py path/to/skill --json
```

Use the compact text report by omitting `--json`:

```bash
python scripts/skill_static_scan.py path/to/skill
```

Example clean JSON result:

```json
{
  "summary": {
    "risk": "LOW",
    "finding_count": 0
  },
  "coverage": {
    "scanned": 1,
    "skipped": [],
    "truncated": []
  },
  "findings": []
}
```

## Report semantics

Each finding contains a rule ID, severity, confidence, category, source file,
line number, raw evidence, remediation guidance, deterministic source, review
note, and related finding IDs.

Overall risk is the highest severity among findings with `medium` or `high`
confidence. Low-confidence findings remain visible but do not raise summary
risk. A report with no findings is therefore `LOW`, not a separate clean-risk
value.

The top-level `coverage` object is part of the security result:

- `scanned` is the number of files whose text was inspected.
- `skipped` lists unsupported, binary, or unreadable files with a reason.
- `truncated` lists files inspected only through the configured byte limit.

Treat every skipped or truncated file as a manual-review item. A missing target
is an error and returns a nonzero CLI exit status instead of a clean report.

See [references/report-format.md](references/report-format.md) for the full
finding contract.

## Safety model

The scanner never executes target content. In particular, it does not:

- Import scanned Python modules.
- Run target shell commands, package installers, setup hooks, or Makefiles.
- Install target dependencies.
- Connect to target-declared MCP servers, endpoints, or tools.
- Decode suspicious payloads beyond one static layer.

Decoded content is rescanned as untrusted text and linked back to its source
finding.

## Known limitations

This is a lightweight V1 static scanner. It does not provide:

- AST or control-flow taint analysis.
- Dependency CVE or malware-signature scanning.
- Dynamic execution or sandboxing.
- MCP server inspection.
- SARIF output or CI policy enforcement.
- Complete multilingual prompt-injection or Unicode confusable coverage.

Rules are intentionally deterministic and auditable. Supplemental review is
still required for description/behavior mismatch, excessive agency, trigger
abuse, external tools, and unreadable assets.

See [references/threat-taxonomy.md](references/threat-taxonomy.md) for the V1
scope and limitations.

## Tests

Run the complete suite from the repository root:

```bash
python -m pytest tests -q -p no:cacheprovider
```

The current suite contains 53 tests covering benign fixtures, malicious
fixtures, confidence gating, contextual escalation, obfuscation, coverage, and
reported regression cases.

## Repository layout

```text
SKILL.md                         Agent-facing security workflow
scripts/skill_static_scan.py    Pure-static scanner CLI
references/                     Threat taxonomy and report contract
tests/                           Regression suite and scan fixtures
LICENSE                         MIT License
```

## License

Released under the [MIT License](LICENSE).
