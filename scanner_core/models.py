from enum import Enum
from typing import Optional, Any
from pydantic import BaseModel, model_validator


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def score(self) -> int:
        return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}[self.value]

    @property
    def rich_color(self) -> str:
        return {
            "CRITICAL": "bold red",
            "HIGH": "yellow",
            "MEDIUM": "blue",
            "LOW": "green",
            "INFO": "dim",
        }[self.value]


_OWASP_KEYWORDS: dict[str, str] = {
    "sql injection": "A03:2021 – Injection",
    "command injection": "A03:2021 – Injection",
    "code injection": "A03:2021 – Injection",
    "eval": "A03:2021 – Injection",
    "exec": "A03:2021 – Injection",
    "xss": "A03:2021 – Injection",
    "cross-site scripting": "A03:2021 – Injection",
    "path traversal": "A01:2021 – Broken Access Control",
    "broken access": "A01:2021 – Broken Access Control",
    "weak crypto": "A02:2021 – Cryptographic Failures",
    "weak cryptograph": "A02:2021 – Cryptographic Failures",
    "md5": "A02:2021 – Cryptographic Failures",
    "sha1": "A02:2021 – Cryptographic Failures",
    "hardcoded": "A07:2021 – Identification and Authentication Failures",
    "secret": "A07:2021 – Identification and Authentication Failures",
    "password": "A07:2021 – Identification and Authentication Failures",
    "api key": "A07:2021 – Identification and Authentication Failures",
    "insecure deserialization": "A08:2021 – Software and Data Integrity Failures",
    "ssrf": "A10:2021 – Server-Side Request Forgery",
    "open redirect": "A01:2021 – Broken Access Control",
}


def infer_owasp(vuln_type: str) -> Optional[str]:
    lower = vuln_type.lower()
    for keyword, owasp in _OWASP_KEYWORDS.items():
        if keyword in lower:
            return owasp
    return None


class Vulnerability(BaseModel):
    severity: Severity
    type: str
    description: str
    impact: str
    fix: str
    line_number: Optional[int] = None
    owasp: Optional[str] = None
    confidence: float = 1.0
    source: str = "llm"  # "static" | "llm"

    @model_validator(mode="after")
    def _infer_owasp(self) -> "Vulnerability":
        if self.owasp is None:
            self.owasp = infer_owasp(self.type)
        return self


class FileResult(BaseModel):
    file_path: str
    file_hash: str
    language: str
    vulnerabilities: list[Vulnerability] = []
    scan_duration_ms: float = 0.0
    from_cache: bool = False
    error: Optional[str] = None

    @property
    def severity_counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for v in self.vulnerabilities:
            counts[v.severity.value] += 1
        return counts

    @property
    def risk_score(self) -> int:
        return sum(v.severity.score for v in self.vulnerabilities)


class ScanReport(BaseModel):
    files: list[FileResult] = []
    total_duration_ms: float = 0.0
    cache_hits: int = 0

    @property
    def total_vulnerabilities(self) -> int:
        return sum(len(f.vulnerabilities) for f in self.files)

    @property
    def severity_counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.files:
            for v in f.vulnerabilities:
                counts[v.severity.value] += 1
        return counts

    @property
    def riskiest_file(self) -> Optional[FileResult]:
        if not self.files:
            return None
        return max(self.files, key=lambda f: f.risk_score)
