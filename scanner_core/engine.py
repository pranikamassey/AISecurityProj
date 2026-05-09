"""Concurrent scan engine — runs static + LLM analyzers per file, merges results."""

import hashlib
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable, Optional

from .cache import ScanCache
from .llm_analyzer import LLMAnalyzer
from .models import FileResult, ScanReport, Severity, Vulnerability
from .static_analyzer import StaticAnalyzer
from .utils import SCANNABLE_EXTENSIONS, collect_files, detect_language

ProgressCallback = Callable[[FileResult], None]


def _fingerprint(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8", errors="replace")).hexdigest()


def _merge(static: list[Vulnerability], llm: list[Vulnerability]) -> list[Vulnerability]:
    """Prefer static findings; add LLM findings not already covered by static."""
    covered: set[str] = {_type_key(v) for v in static}
    merged = list(static)
    for lf in llm:
        if _type_key(lf) not in covered:
            merged.append(lf)
    merged.sort(key=lambda v: (v.severity.score, v.confidence), reverse=True)
    return merged


def _type_key(v: Vulnerability) -> str:
    # Normalize to first 24 chars of lowercased type for fuzzy dedup
    return v.type.lower().replace(" ", "")[:24]


class ScanEngine:
    def __init__(
        self,
        llm: LLMAnalyzer,
        use_cache: bool = True,
        use_static: bool = True,
        min_severity: Severity = Severity.LOW,
        max_workers: int = 4,
    ) -> None:
        self.llm = llm
        self.static = StaticAnalyzer()
        self.cache: Optional[ScanCache] = ScanCache() if use_cache else None
        self.use_static = use_static
        self.min_severity = min_severity
        self.max_workers = max_workers

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def scan(
        self,
        paths: list[str],
        on_file_done: Optional[ProgressCallback] = None,
    ) -> ScanReport:
        start = time.monotonic()
        all_files = self._resolve_paths(paths)
        report = ScanReport()

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(self._scan_file, p): p for p in all_files}
            for future in as_completed(futures):
                result = future.result()
                # Apply severity filter
                result.vulnerabilities = [
                    v for v in result.vulnerabilities
                    if v.severity.score >= self.min_severity.score
                ]
                if result.from_cache:
                    report.cache_hits += 1
                report.files.append(result)
                if on_file_done:
                    on_file_done(result)

        report.total_duration_ms = (time.monotonic() - start) * 1000
        return report

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    @staticmethod
    def _resolve_paths(paths: list[str]) -> list[Path]:
        result: list[Path] = []
        for raw in paths:
            p = Path(raw)
            if p.is_file():
                result.append(p)
            elif p.is_dir():
                result.extend(collect_files(p, SCANNABLE_EXTENSIONS))
        return result

    def _scan_file(self, path: Path) -> FileResult:
        t0 = time.monotonic()

        try:
            code = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return FileResult(
                file_path=str(path), file_hash="", language="unknown", error=str(exc)
            )

        fhash = _fingerprint(code)
        language = detect_language(path)

        # Cache lookup
        if self.cache:
            cached = self.cache.get(fhash)
            if cached is not None:
                return FileResult(
                    file_path=str(path),
                    file_hash=fhash,
                    language=language,
                    vulnerabilities=cached,
                    scan_duration_ms=(time.monotonic() - t0) * 1000,
                    from_cache=True,
                )

        # Run analyzers
        static_findings: list[Vulnerability] = []
        if self.use_static and language == "Python":
            static_findings = self.static.analyze(code, str(path))

        llm_findings: list[Vulnerability] = []
        try:
            llm_findings = self.llm.analyze(code, language)
        except Exception as exc:
            # LLM failure is non-fatal; surface as a warning vulnerability
            llm_findings = [Vulnerability(
                severity=Severity.INFO,
                type="LLM Analysis Error",
                description=f"LLM analysis failed: {exc}",
                impact="Some vulnerabilities may not have been detected.",
                fix="Check your API key and network connectivity.",
                source="llm",
                confidence=1.0,
            )]

        vulns = _merge(static_findings, llm_findings)
        duration_ms = (time.monotonic() - t0) * 1000

        if self.cache:
            self.cache.put(fhash, str(path), language, vulns, duration_ms)

        return FileResult(
            file_path=str(path),
            file_hash=fhash,
            language=language,
            vulnerabilities=vulns,
            scan_duration_ms=duration_ms,
        )
