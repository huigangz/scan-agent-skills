from __future__ import annotations

import argparse
import base64
import json
import re
import sys
from pathlib import Path
from typing import Any


SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
RANK_SEVERITY = {value: key for key, value in SEVERITY_RANK.items()}
TEXT_SUFFIXES = {
    ".md",
    ".txt",
    ".py",
    ".js",
    ".ts",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".sh",
    ".ps1",
    ".mjs",
    ".cjs",
    ".jsx",
    ".tsx",
    ".bat",
    ".cmd",
    ".rb",
    ".php",
}
TEXT_BASENAMES = {"Dockerfile", "Makefile"}

MAX_FILE_BYTES = 1024 * 1024
MAX_DECODE_BYTES = 256 * 1024

BASE64_RE = re.compile(r"\b[A-Za-z0-9+/]{32,}={0,2}\b")
PURE_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
HEX_BLOB_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}|(?:0x[0-9a-fA-F]{2}[\s,]*){4,}")
URL_ENCODE_RE = re.compile(r"(?:%[0-9a-fA-F]{2}){4,}")
STRING_CONCAT_RE = re.compile(
    r"['\"](?:ev|cu|ba|sh|al|rl)['\"]\s*\+\s*['\"](?:ev|cu|ba|sh|al|rl)['\"]",
    re.IGNORECASE,
)
REMOTE_EXEC_RE = re.compile(
    r"curl\s+\S+.*\|\s*(?:ba)?sh\b|wget\s+\S+.*(?:&&|\|)\s*(?:ba)?sh\b",
    re.IGNORECASE,
)
PERSISTENCE_RE = re.compile(
    r"\b(?:crontab|systemctl\s+enable|launchctl\s+load|schtasks)\b"
    r"|(^|[\s\"'=:/\\~`])\.(?:bashrc|zshrc|profile|bash_profile|zprofile)\b"
    r"|currentversion\\+run(?:once)?\b"
    r"|start menu[/\\]+programs[/\\]+startup\b",
    re.IGNORECASE,
)
SUPPLY_CHAIN_HOOK_RE = re.compile(
    r"[\"'](?:postinstall|preinstall|prepare|install)[\"']\s*:"
    r"|\bnpm\s+run\s+(?:postinstall|preinstall|prepare|install)\b",
    re.IGNORECASE,
)
CREDENTIAL_ACCESS_RE = re.compile(
    r"\.ssh[/\\]id_|~/\.ssh|\.aws[/\\]credentials|~/\.aws|(^|[\s\"'=:/\\~`])\.env\b",
    re.IGNORECASE,
)
SYSTEM_PROMPT_LEAKAGE_RE = re.compile(
    r"(reveal|print|show|dump|write|output).{0,40}"
    r"(system prompt|system instructions|developer instructions|hidden instructions)",
    re.IGNORECASE,
)
PRIVILEGE_ESCALATION_RE = re.compile(
    r"\bsudo\b|chmod\s+(?:777|a\+[rwx]|[+]s)|setfacl\b|takeown\b|icacls\b",
    re.IGNORECASE,
)
GENERIC_SUBPROCESS_RE = re.compile(
    r"\bsubprocess\.(run|call|popen)|os\.system\(|child_process|exec\(",
    re.IGNORECASE,
)
NETWORK_SEND_RULES = (
    (
        re.compile(
            r"webhook\.site|hooks\.slack\.com|discord\.com/api/webhooks",
            re.IGNORECASE,
        ),
        "medium",
    ),
    (
        re.compile(
            r"requests\.(?:get|post)\s*\(|urllib\.request\.urlopen\s*\("
            r"|httpx\.(?:get|post)\s*\(|(?<![\w$])fetch\s*\(|axios\.post\s*\("
            r"|curl\s+[^\n]*(?:-d\b|--data|-X\s+POST)|Invoke-RestMethod",
            re.IGNORECASE,
        ),
        "medium",
    ),
    (re.compile(r"Invoke-WebRequest", re.IGNORECASE), "low"),
)


def _new_finding(
    findings: list[dict[str, Any]],
    *,
    rule_id: str,
    severity: str,
    confidence: str,
    category: str,
    file: str,
    line: int,
    evidence: str,
    why_it_matters: str,
    remediation: str,
    deterministic_source: str,
    llm_review_note: str = "",
    related_findings: list[str] | None = None,
) -> dict[str, Any]:
    finding = {
        "id": f"F{len(findings) + 1}",
        "rule_id": rule_id,
        "severity": severity,
        "confidence": confidence,
        "category": category,
        "file": file,
        "line": line,
        "evidence": evidence[:240],
        "why_it_matters": why_it_matters,
        "remediation": remediation,
        "deterministic_source": deterministic_source,
        "llm_review_note": llm_review_note,
        "related_findings": related_findings or [],
    }
    findings.append(finding)
    return finding


def _read_text(path: Path) -> tuple[str | None, bool, str | None]:
    try:
        with path.open("rb") as handle:
            data = handle.read(MAX_FILE_BYTES + 1)
    except OSError:
        return None, False, "read_error"
    if b"\x00" in data:
        return None, False, "binary"
    truncated = len(data) > MAX_FILE_BYTES
    return data[:MAX_FILE_BYTES].decode("utf-8", errors="replace"), truncated, None


def _iter_files(target: Path) -> tuple[list[Path], list[Path]]:
    if target.is_file():
        return [target], []
    files: list[Path] = []
    unsupported: list[Path] = []
    for path in target.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() in TEXT_SUFFIXES or path.name in TEXT_BASENAMES:
            files.append(path)
        else:
            unsupported.append(path)
    return sorted(files), sorted(unsupported)


def _rel(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _context(lines: list[str], index: int, window: int = 1) -> str:
    start = max(0, index - window)
    end = min(len(lines), index + window + 1)
    return " ".join(lines[start:end]).strip()


def _phrase_variants(text: str) -> tuple[str, str]:
    invisible = r"[\u200b\u200c\u200d\ufeff\u202a-\u202e]+"
    return re.sub(invisible, "", text), re.sub(invisible, " ", text)


def _semantic_variants(line: str) -> tuple[str, ...]:
    return tuple(dict.fromkeys(_phrase_variants(line)))


def _search_variants(pattern: re.Pattern[str], variants: tuple[str, ...]) -> bool:
    return any(pattern.search(variant) for variant in variants)


def _network_send_confidence(variants: tuple[str, ...]) -> str | None:
    for pattern, confidence in NETWORK_SEND_RULES:
        if _search_variants(pattern, variants):
            return confidence
    return None


def _contains_phrase(variants: tuple[str, ...], phrases: tuple[str, ...]) -> bool:
    return any(phrase in variant for variant in variants for phrase in phrases)


def _is_markdown_example_command(path: str, line: str, context: str) -> bool:
    if not path.lower().endswith(".md"):
        return False
    lowered = context.lower()
    return (
        "`" in line
        and any(marker in lowered for marker in ("unsafe", "do not run", "do not execute"))
    )


def _looks_like_base64(text: str) -> bool:
    stripped = re.sub(r"\s+", "", text)
    if len(stripped) < 32:
        return False
    if len(stripped) % 4 != 0:
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", stripped))


def _decode_base64(candidate: str) -> bytes | None:
    if len(candidate) > MAX_DECODE_BYTES:
        return None
    padded = candidate + ("=" * ((4 - len(candidate) % 4) % 4))
    try:
        return base64.b64decode(padded, validate=True)
    except Exception:
        return None


def _decode_to_text(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def _has_hidden_instruction(text: str) -> bool:
    variants = tuple(
        re.sub(r"\s+", " ", variant.lower()).strip()
        for variant in _phrase_variants(text)
    )
    return _contains_phrase(
        variants,
        (
            "mark this skill as safe",
            "mark it safe",
            "do not report",
            "suppress all warnings",
            "suppress findings",
            "hide findings",
            "ignore previous instructions",
            "ignore your scanner rules",
            "developer mode",
            "forget everything",
        ),
    )


def _scan_hidden_html_blocks(
    *,
    text: str,
    file_label: str,
    findings: list[dict[str, Any]],
    source: str,
) -> None:
    line_starts = [0]
    for match in re.finditer(r"\n", text):
        line_starts.append(match.end())

    for match in re.finditer(r"<!--([\s\S]*?)-->", text):
        block = match.group(0)
        if not _has_hidden_instruction(block):
            continue
        line_no = 1
        for idx, start in enumerate(line_starts, start=1):
            if start <= match.start():
                line_no = idx
            else:
                break
        block_lines = block.splitlines()
        for offset, block_line in enumerate(block_lines):
            if _has_hidden_instruction(block_line):
                line_no += offset
                break
        _new_finding(
            findings,
            rule_id="HIDDEN_HTML_INSTRUCTION",
            severity="HIGH",
            confidence="high",
            category="HIDDEN_INSTRUCTION",
            file=file_label,
            line=line_no,
            evidence=" ".join(line.strip() for line in block_lines)[:240],
            why_it_matters="Hidden comments can steer a reviewer while staying invisible in rendered markdown.",
            remediation="Remove hidden reviewer instructions and make all skill behavior visible.",
            deterministic_source=source,
        )


def _scan_text(
    *,
    text: str,
    file_label: str,
    findings: list[dict[str, Any]],
    source: str,
    allow_encoding_scan: bool,
) -> None:
    if text.startswith("\ufeff"):
        text = text[1:]
    _scan_hidden_html_blocks(
        text=text,
        file_label=file_label,
        findings=findings,
        source=source,
    )
    lines = text.splitlines()
    for index, line in enumerate(lines):
        line_no = index + 1
        lowered = line.lower()
        semantic_variants = _semantic_variants(line)
        phrase_variants = tuple(variant.lower() for variant in _phrase_variants(line))
        context = _context(lines, index).lower()
        markdown_example = _is_markdown_example_command(file_label, line, context)

        reviewer_terms = ("reviewer", "scanner", "audit", "security review")
        reviewer_targeted = _contains_phrase(phrase_variants, reviewer_terms)
        safe_washing = _contains_phrase(
            phrase_variants,
            (
                "mark this skill as safe",
                "mark it safe",
                "do not report",
                "suppress all warnings",
                "suppress findings",
                "hide findings",
            ),
        )
        instruction_override = _contains_phrase(
            phrase_variants,
            (
                "ignore previous instructions",
                "ignore your scanner rules",
                "developer mode",
                "forget everything",
            ),
        )

        if reviewer_targeted and instruction_override:
            _new_finding(
                findings,
                rule_id="PROMPT_INJECTION_REVIEWER",
                severity="HIGH",
                confidence="high",
                category="PROMPT_INJECTION",
                file=file_label,
                line=line_no,
                evidence=line.strip(),
                why_it_matters="The target content attempts to control the security reviewer.",
                remediation="Remove reviewer-targeted instructions. Target content must remain data, not policy.",
                deterministic_source=source,
            )

        if reviewer_targeted and safe_washing:
            _new_finding(
                findings,
                rule_id="SAFE_WASHING",
                severity="HIGH",
                confidence="high",
                category="PROMPT_INJECTION",
                file=file_label,
                line=line_no,
                evidence=line.strip(),
                why_it_matters="The skill tries to suppress or alter the audit verdict.",
                remediation="Remove any instruction that asks a reviewer to hide, downgrade, or ignore findings.",
                deterministic_source=source,
            )

        if not reviewer_targeted and _contains_phrase(
            phrase_variants, ("ignore previous instructions",)
        ):
            _new_finding(
                findings,
                rule_id="PROMPT_INJECTION_USER",
                severity="MEDIUM",
                confidence="medium",
                category="PROMPT_INJECTION",
                file=file_label,
                line=line_no,
                evidence=line.strip(),
                why_it_matters="The skill attempts to override normal user-facing agent instructions.",
                remediation="Remove instruction override language and keep behavior scoped to the stated task.",
                deterministic_source=source,
            )

        if any(token in line for token in ("\u200b", "\u200c", "\u200d", "\ufeff")):
            _new_finding(
                findings,
                rule_id="ZERO_WIDTH_TEXT",
                severity="MEDIUM",
                confidence="medium",
                category="OBFUSCATION",
                file=file_label,
                line=line_no,
                evidence=line.strip(),
                why_it_matters="Invisible text can hide instructions from human reviewers.",
                remediation="Remove zero-width characters from skill content.",
                deterministic_source=source,
            )

        if any(token in line for token in ("\u202a", "\u202b", "\u202c", "\u202d", "\u202e")):
            _new_finding(
                findings,
                rule_id="BIDI_TEXT_OVERRIDE",
                severity="MEDIUM",
                confidence="medium",
                category="OBFUSCATION",
                file=file_label,
                line=line_no,
                evidence=line.strip(),
                why_it_matters="Bidirectional override characters can make text display differently from its bytes.",
                remediation="Remove bidi override characters.",
                deterministic_source=source,
            )

        if _search_variants(CREDENTIAL_ACCESS_RE, semantic_variants):
            _new_finding(
                findings,
                rule_id="CREDENTIAL_ACCESS",
                severity="HIGH",
                confidence="high",
                category="CREDENTIAL_ACCESS",
                file=file_label,
                line=line_no,
                evidence=line.strip(),
                why_it_matters="The skill references credential or secret-bearing files.",
                remediation="Avoid direct credential file access; require explicit user-provided configuration.",
                deterministic_source=source,
            )

        network_confidence = _network_send_confidence(semantic_variants)
        if network_confidence:
            _new_finding(
                findings,
                rule_id="NETWORK_SEND",
                severity="LOW",
                confidence=network_confidence,
                category="DATA_EXFILTRATION",
                file=file_label,
                line=line_no,
                evidence=line.strip(),
                why_it_matters="Outbound network sends can exfiltrate data when combined with sensitive reads.",
                remediation="Document all outbound endpoints and avoid sending secrets or local file contents.",
                deterministic_source=source,
            )

        if _search_variants(PERSISTENCE_RE, semantic_variants):
            _new_finding(
                findings,
                rule_id="PERSISTENCE",
                severity="HIGH",
                confidence="high",
                category="PERSISTENCE",
                file=file_label,
                line=line_no,
                evidence=line.strip(),
                why_it_matters="Persistence mechanisms can keep malicious behavior active across sessions.",
                remediation="Remove persistence behavior unless it is explicit, necessary, and user-approved.",
                deterministic_source=source,
            )

        if _search_variants(SUPPLY_CHAIN_HOOK_RE, semantic_variants):
            _new_finding(
                findings,
                rule_id="SUPPLY_CHAIN_INSTALL_HOOK",
                severity="HIGH",
                confidence="medium",
                category="SUPPLY_CHAIN",
                file=file_label,
                line=line_no,
                evidence=line.strip(),
                why_it_matters="Install hooks and package setup paths can execute code before review.",
                remediation="Remove install-time execution hooks or make installation steps explicit and inert.",
                deterministic_source=source,
            )

        if _search_variants(SYSTEM_PROMPT_LEAKAGE_RE, semantic_variants):
            _new_finding(
                findings,
                rule_id="SYSTEM_PROMPT_LEAKAGE",
                severity="HIGH",
                confidence="high",
                category="SYSTEM_PROMPT_LEAKAGE",
                file=file_label,
                line=line_no,
                evidence=line.strip(),
                why_it_matters="The skill attempts to expose confidential system or developer instructions.",
                remediation="Remove instructions that request system prompt or hidden instruction disclosure.",
                deterministic_source=source,
            )

        if _search_variants(PRIVILEGE_ESCALATION_RE, semantic_variants):
            _new_finding(
                findings,
                rule_id="PRIVILEGE_ESCALATION",
                severity="MEDIUM",
                confidence="medium",
                category="PRIVILEGE_ESCALATION",
                file=file_label,
                line=line_no,
                evidence=line.strip(),
                why_it_matters="Elevated privileges or broad permissions increase blast radius.",
                remediation="Avoid privilege escalation; document and narrow any required permissions.",
                deterministic_source=source,
            )

        if _search_variants(GENERIC_SUBPROCESS_RE, semantic_variants):
            _new_finding(
                findings,
                rule_id="GENERIC_SUBPROCESS",
                severity="LOW",
                confidence="low",
                category="REMOTE_CODE_EXECUTION",
                file=file_label,
                line=line_no,
                evidence=line.strip(),
                why_it_matters="Process execution is a weak signal that deserves review in skill packages.",
                remediation="Use fixed argument lists and avoid shell=True or untrusted command strings.",
                deterministic_source=source,
            )

        remote_exec = _search_variants(REMOTE_EXEC_RE, semantic_variants)
        if remote_exec:
            rule_id = "DECODED_REMOTE_CODE_EXECUTION" if source == "decoded_static_rule" else "REMOTE_CODE_EXECUTION"
            confidence = "low" if markdown_example and source != "decoded_static_rule" else "high"
            _new_finding(
                findings,
                rule_id=rule_id,
                severity="CRITICAL",
                confidence=confidence,
                category="REMOTE_CODE_EXECUTION",
                file=file_label,
                line=line_no,
                evidence=line.strip(),
                why_it_matters="Downloading remote code and piping it to a shell enables arbitrary execution.",
                remediation="Remove curl-pipe-shell behavior. Use pinned, reviewable dependencies instead.",
                deterministic_source=source,
                llm_review_note=(
                    "Confidence lowered on documentation-negation keywords; escalate if the surrounding text actually instructs execution."
                    if confidence == "low"
                    else ""
                ),
            )

        if HEX_BLOB_RE.search(line):
            _new_finding(
                findings,
                rule_id="HEX_ENCODING",
                severity="MEDIUM",
                confidence="medium",
                category="OBFUSCATION",
                file=file_label,
                line=line_no,
                evidence=line.strip(),
                why_it_matters="Hex-encoded blobs can hide payload text from simple review.",
                remediation="Replace encoded content with readable source.",
                deterministic_source=source,
            )

        if URL_ENCODE_RE.search(line):
            _new_finding(
                findings,
                rule_id="URL_ENCODING",
                severity="MEDIUM",
                confidence="medium",
                category="OBFUSCATION",
                file=file_label,
                line=line_no,
                evidence=line.strip(),
                why_it_matters="URL-encoded blobs can hide payload text from simple review.",
                remediation="Replace encoded content with readable source.",
                deterministic_source=source,
            )

        if STRING_CONCAT_RE.search(line):
            _new_finding(
                findings,
                rule_id="STRING_CONCAT_OBFUSCATION",
                severity="MEDIUM",
                confidence="medium",
                category="OBFUSCATION",
                file=file_label,
                line=line_no,
                evidence=line.strip(),
                why_it_matters="String concatenation can hide dangerous tokens from simple matching.",
                remediation="Use readable string literals and avoid evasive construction.",
                deterministic_source=source,
            )

        if allow_encoding_scan:
            _scan_base64_line(
                line=line,
                line_no=line_no,
                file_label=file_label,
                findings=findings,
            )


def _scan_base64_line(
    *,
    line: str,
    line_no: int,
    file_label: str,
    findings: list[dict[str, Any]],
) -> None:
    for match in BASE64_RE.finditer(line):
        candidate = match.group(0)
        if PURE_HEX_RE.fullmatch(candidate):
            continue
        decoded = _decode_base64(candidate)
        if decoded is None:
            continue
        blob = _new_finding(
            findings,
            rule_id="BASE64_BLOB",
            severity="MEDIUM",
            confidence="low",
            category="OBFUSCATION",
            file=file_label,
            line=line_no,
            evidence=candidate[:120],
            why_it_matters="Base64 can hide instructions or executable payloads from human review.",
            remediation="Store payloads as readable text or remove them.",
            deterministic_source="static_rule",
        )
        if len(decoded) > MAX_DECODE_BYTES:
            continue
        decoded_text = _decode_to_text(decoded)
        if _looks_like_base64(decoded_text) or HEX_BLOB_RE.search(decoded_text):
            _new_finding(
                findings,
                rule_id="MULTILAYER_ENCODING",
                severity="MEDIUM",
                confidence="medium",
                category="OBFUSCATION",
                file=file_label,
                line=line_no,
                evidence=decoded_text[:120],
                why_it_matters="Multiple encoding layers are a strong evasion signal.",
                remediation="Remove nested encoding and provide readable content.",
                deterministic_source="decoded_static_rule",
                related_findings=[blob["id"]],
            )
            continue
        if "\ufffd" in decoded_text and sum(ch == "\ufffd" for ch in decoded_text) > max(4, len(decoded_text) // 5):
            _new_finding(
                findings,
                rule_id="OBFUSCATED_BINARY_BLOB",
                severity="MEDIUM",
                confidence="medium",
                category="OBFUSCATION",
                file=file_label,
                line=line_no,
                evidence="<decoded binary content>",
                why_it_matters="Embedded binary blobs in skills are unusual and hard to review.",
                remediation="Remove embedded binary payloads or ship transparent source artifacts.",
                deterministic_source="decoded_static_rule",
                related_findings=[blob["id"]],
            )
            continue
        before = len(findings)
        _scan_text(
            text=decoded_text,
            file_label=f"{file_label}:decoded-base64",
            findings=findings,
            source="decoded_static_rule",
            allow_encoding_scan=False,
        )
        for finding in findings[before:]:
            if blob["id"] not in finding["related_findings"]:
                finding["related_findings"].append(blob["id"])


def _add_contextual_escalations(findings: list[dict[str, Any]]) -> None:
    original = list(findings)

    def base_file(finding: dict[str, Any]) -> str:
        return finding["file"].split(":decoded-base64", 1)[0]

    def pair_confidence(first: dict[str, Any], second: dict[str, Any], elevated: str) -> str:
        if "low" in {first["confidence"], second["confidence"]}:
            return "low"
        return elevated

    def preferred_pair(
        first: list[dict[str, Any]],
        second: list[dict[str, Any]],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        return max(
            ((left, right) for left in first for right in second),
            key=lambda pair: sum(item["confidence"] != "low" for item in pair),
        )

    by_file: dict[str, list[dict[str, Any]]] = {}
    for finding in original:
        by_file.setdefault(base_file(finding), []).append(finding)

    for file_label, items in by_file.items():
        reviewer = [f for f in items if f["rule_id"] == "PROMPT_INJECTION_REVIEWER"]
        safe = [f for f in items if f["rule_id"] == "SAFE_WASHING"]
        if reviewer and safe:
            _new_finding(
                findings,
                rule_id="REVIEWER_SAFE_WASHING_ESCALATION",
                severity="CRITICAL",
                confidence="high",
                category="PROMPT_INJECTION",
                file=file_label,
                line=min(reviewer[0]["line"], safe[0]["line"]),
                evidence="Reviewer-targeted instruction attempts to alter the audit verdict.",
                why_it_matters="This attacks the scanner's core decision boundary.",
                remediation="Remove all reviewer-targeted safe-washing instructions.",
                deterministic_source="contextual_escalation",
                related_findings=[reviewer[0]["id"], safe[0]["id"]],
            )

        credentials = [f for f in items if f["rule_id"] == "CREDENTIAL_ACCESS"]
        network = [f for f in items if f["rule_id"] == "NETWORK_SEND"]
        persistence = [f for f in items if f["rule_id"] == "PERSISTENCE"]
        if credentials and network:
            credential, send = preferred_pair(credentials, network)
            _new_finding(
                findings,
                rule_id="DATA_EXFILTRATION_CHAIN",
                severity="CRITICAL",
                confidence=pair_confidence(credential, send, "high"),
                category="DATA_EXFILTRATION",
                file=file_label,
                line=min(credential["line"], send["line"]),
                evidence="Sensitive file access and outbound network send occur in the same file.",
                why_it_matters="This is a high-confidence credential exfiltration pattern.",
                remediation="Remove the data flow from sensitive local files to outbound requests.",
                deterministic_source="contextual_escalation",
                related_findings=[credential["id"], send["id"]],
            )

        if persistence and network:
            persistent_action, send = preferred_pair(persistence, network)
            _new_finding(
                findings,
                rule_id="PERSISTENCE_NETWORK_ESCALATION",
                severity="CRITICAL",
                confidence=pair_confidence(persistent_action, send, "high"),
                category="PERSISTENCE",
                file=file_label,
                line=min(persistent_action["line"], send["line"]),
                evidence="Persistence behavior and outbound network send occur in the same file.",
                why_it_matters="Persistence plus outbound communication is a high-risk backdoor pattern.",
                remediation="Remove persistent execution and outbound communication unless explicitly required and user-approved.",
                deterministic_source="contextual_escalation",
                related_findings=[persistent_action["id"], send["id"]],
            )

        base64_blobs = [f for f in items if f["rule_id"] == "BASE64_BLOB"]
        decoded_exec = [f for f in items if f["rule_id"] == "DECODED_REMOTE_CODE_EXECUTION"]
        decoded_pair = next(
            (
                (blob, execution)
                for execution in decoded_exec
                for blob in base64_blobs
                if blob["id"] in execution["related_findings"]
            ),
            None,
        )
        if decoded_pair:
            blob, execution = decoded_pair
            _new_finding(
                findings,
                rule_id="DECODED_PAYLOAD_EXECUTION_ESCALATION",
                severity="CRITICAL",
                confidence="high",
                category="REMOTE_CODE_EXECUTION",
                file=file_label,
                line=blob["line"],
                evidence="Base64-decoded content contains remote shell execution.",
                why_it_matters="Encoded execution payloads indicate deliberate evasion plus code execution.",
                remediation="Remove encoded remote execution payloads.",
                deterministic_source="contextual_escalation",
                related_findings=[blob["id"], execution["id"]],
            )

    credentials = [f for f in original if f["rule_id"] == "CREDENTIAL_ACCESS"]
    network = [f for f in original if f["rule_id"] == "NETWORK_SEND"]
    cross_file_pairs = [
            (credential, send)
            for credential in credentials
            for send in network
            if base_file(credential) != base_file(send)
    ]
    if cross_file_pairs:
        credential, send = max(
            cross_file_pairs,
            key=lambda pair: sum(item["confidence"] != "low" for item in pair),
        )
        _new_finding(
            findings,
            rule_id="SKILL_LEVEL_EXFILTRATION_RISK",
            severity="MEDIUM",
            confidence=pair_confidence(credential, send, "medium"),
            category="DATA_EXFILTRATION",
            file="<skill>",
            line=1,
            evidence="Sensitive file access and outbound network send appear in different files in the same skill package.",
            why_it_matters="Cross-file splitting can hide an exfiltration flow from file-local review.",
            remediation="Manually inspect whether sensitive data can flow between these files.",
            deterministic_source="contextual_escalation",
            related_findings=[credential["id"], send["id"]],
        )


def _summary(findings: list[dict[str, Any]]) -> dict[str, Any]:
    eligible = [f for f in findings if f["confidence"] in {"medium", "high"}]
    risk_rank = max((SEVERITY_RANK[f["severity"]] for f in eligible), default=0)
    return {
        "risk": RANK_SEVERITY[risk_rank],
        "finding_count": len(findings),
    }


def scan_path(path: str | Path) -> dict[str, Any]:
    target = Path(path).resolve()
    if not target.exists():
        raise FileNotFoundError(f"target does not exist: {target}")
    root = target if target.is_dir() else target.parent
    findings: list[dict[str, Any]] = []
    files, unsupported = _iter_files(target)
    coverage: dict[str, Any] = {
        "scanned": 0,
        "skipped": [
            {"path": _rel(file_path, root), "reason": "unsupported_type"}
            for file_path in unsupported
        ],
        "truncated": [],
    }
    for file_path in files:
        text, truncated, skip_reason = _read_text(file_path)
        if skip_reason:
            coverage["skipped"].append(
                {"path": _rel(file_path, root), "reason": skip_reason}
            )
            continue
        assert text is not None
        coverage["scanned"] += 1
        if truncated:
            coverage["truncated"].append(_rel(file_path, root))
        _scan_text(
            text=text,
            file_label=_rel(file_path, root),
            findings=findings,
            source="static_rule",
            allow_encoding_scan=True,
        )
    _add_contextual_escalations(findings)
    return {
        "summary": _summary(findings),
        "coverage": coverage,
        "findings": findings,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Pure static scanner for agent skill packages.")
    parser.add_argument("path", help="Skill file or directory to scan")
    parser.add_argument("--json", action="store_true", help="Emit JSON output")
    args = parser.parse_args()

    try:
        report = scan_path(args.path)
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"Risk: {report['summary']['risk']}")
        coverage = report["coverage"]
        print(
            f"Coverage: scanned={coverage['scanned']} "
            f"skipped={len(coverage['skipped'])} truncated={len(coverage['truncated'])}"
        )
        for finding in report["findings"]:
            print(
                f"{finding['severity']} {finding['confidence']} "
                f"{finding['rule_id']} {finding['file']}:{finding['line']}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
