# Report Format

Use this field order for every finding:

1. `id`
2. `rule_id`
3. `severity`
4. `confidence`
5. `category`
6. `file`
7. `line`
8. `evidence`
9. `why_it_matters`
10. `remediation`
11. `deterministic_source`
12. `llm_review_note`
13. `related_findings`

Overall risk is the highest severity among findings with `confidence` of
`medium` or `high`. Low-confidence findings stay in the report but do not raise
the summary risk.

Every report includes a top-level `coverage` object:

- `scanned`: number of files whose text was scanned.
- `skipped`: path/reason objects for `unsupported_type`, `read_error`, or
  `binary` files.
- `truncated`: paths scanned only through the first `MAX_FILE_BYTES` bytes.

Treat skipped and truncated paths as explicit coverage limits rather than clean
scan results.

`deterministic_source` values:

- `static_rule`
- `decoded_static_rule`
- `contextual_escalation`
- `manual_llm_review`

Never drop deterministic findings. Contextual escalation findings must refer to
their source finding IDs so the evidence chain stays explainable.
