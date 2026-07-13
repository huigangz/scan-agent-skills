# Threat Taxonomy

## V1 scanner-enforced categories

These categories have deterministic V1 rules or contextual escalation:

- `PROMPT_INJECTION`
- `HIDDEN_INSTRUCTION`
- `SYSTEM_PROMPT_LEAKAGE`
- `DATA_EXFILTRATION`
- `CREDENTIAL_ACCESS`
- `REMOTE_CODE_EXECUTION`
- `OBFUSCATION`
- `PRIVILEGE_ESCALATION`
- `PERSISTENCE`
- `SUPPLY_CHAIN`

## V2 or LLM-assisted categories

These categories are useful review concepts but are not claimed as deterministic V1 coverage:

- `TRIGGER_ABUSE`
- `DESCRIPTION_BEHAVIOR_MISMATCH`
- `EXCESSIVE_AGENCY`

V1 may mention these in LLM supplemental review, but scanner output should not
claim full deterministic coverage until specific rules and fixtures exist.

Severity guidance:

- `CRITICAL`: credential exfiltration chains, decoded execution payloads,
  persistence plus network behavior, or reviewer-targeted safe-washing.
- `HIGH`: reviewer-targeted prompt injection, credential access, sensitive file
  access, hidden scanner instructions, system prompt leakage, persistence, or
  install-time supply-chain hooks.
- `MEDIUM`: user-facing prompt injection, suspicious encoding, cross-file
  sensitive read plus network behavior, or privilege escalation signals.
- `LOW`: weak standalone signals such as generic subprocess or network APIs.

## Known V1 Limits

- Keyword injection rules are English-first and can miss multilingual attacks.
- V1 detects zero-width and bidi characters but not full homoglyph/confusable
  attacks.
- V1 decodes only one base64 layer and recognizes only a small set of other
  encoding/evasion patterns.
- V1 does not parse skill frontmatter deeply enough for deterministic trigger
  abuse or description-behavior mismatch.
- V1 does not connect to MCP servers or dynamically inspect declared external
  tools; such declarations require LLM/manual review.
- V1 text scanning skips binary-looking assets rather than fully analyzing them.
- Markdown command confidence can be lowered by explicit documentation-negation
  keywords such as "unsafe" or "do not run". These keywords remain attacker-
  controllable; the deterministic finding stays visible and its LLM review note
  requires escalation when the surrounding text actually instructs execution.
