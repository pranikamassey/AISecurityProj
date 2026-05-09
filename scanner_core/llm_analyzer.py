"""Gemini-backed LLM analyzer with structured output parsing and retry logic."""

import re
from typing import Optional

from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from .models import Vulnerability, Severity

_PROMPT = """\
You are a senior application security engineer performing a thorough code audit.

Analyze the {language} code below for ALL security vulnerabilities including but not limited to:
OWASP Top 10, CWE Top 25, injection flaws, authentication weaknesses, cryptographic failures,
hardcoded secrets, insecure configurations, and language-specific pitfalls.

For EACH vulnerability output a block in EXACTLY this format (no markdown, no extra text between blocks):

---
SEVERITY: CRITICAL|HIGH|MEDIUM|LOW
TYPE: <specific vulnerability name>
LINE: <line number or N/A>
DESCRIPTION: <one precise sentence>
IMPACT: <one sentence on potential damage if exploited>
FIX: <minimal code snippet or concrete remediation>
---

Be thorough — do not skip lower-severity issues. Include every finding.
If the code has NO vulnerabilities, output exactly: NO_VULNERABILITIES

Code ({language}):
```
{code}
```
"""


def _parse_severity(raw: str) -> Severity:
    try:
        return Severity(raw.strip().upper())
    except ValueError:
        return Severity.MEDIUM


def _parse_line(raw: str) -> Optional[int]:
    s = raw.strip()
    if s.upper() in ("N/A", "NA", "UNKNOWN", ""):
        return None
    try:
        return int(re.sub(r"[^\d]", "", s) or "0") or None
    except ValueError:
        return None


def _extract_field(block: str, field: str) -> str:
    match = re.search(
        rf"^{field}:\s*(.+?)(?=\n[A-Z]+:|$)",
        block,
        re.MULTILINE | re.DOTALL,
    )
    return match.group(1).strip() if match else ""


def parse_llm_response(text: str) -> list[Vulnerability]:
    if "NO_VULNERABILITIES" in text.upper():
        return []

    # Split on separator lines (---)
    raw_blocks = re.split(r"\n-{3,}\n", "\n" + text.strip() + "\n")
    vulns: list[Vulnerability] = []

    for block in raw_blocks:
        block = block.strip()
        if not block:
            continue

        severity_raw = _extract_field(block, "SEVERITY")
        vuln_type = _extract_field(block, "TYPE")

        if not severity_raw or not vuln_type:
            continue

        vulns.append(Vulnerability(
            severity=_parse_severity(severity_raw),
            type=vuln_type,
            description=_extract_field(block, "DESCRIPTION"),
            impact=_extract_field(block, "IMPACT"),
            fix=_extract_field(block, "FIX"),
            line_number=_parse_line(_extract_field(block, "LINE")),
            confidence=0.80,
            source="llm",
        ))

    return vulns


class LLMAnalyzer:
    def __init__(self, client, model: str = "gemini-2.5-flash") -> None:
        self.client = client
        self.model = model

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type(Exception),
        reraise=True,
    )
    def analyze(self, code: str, language: str) -> list[Vulnerability]:
        prompt = _PROMPT.format(language=language, code=code)
        response = self.client.models.generate_content(
            model=self.model,
            contents=prompt,
        )
        return parse_llm_response(response.text)
