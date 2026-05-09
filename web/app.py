"""
Security Scanner — Web UI

Usage:
    cd /path/to/security-scanner
    source venv/bin/activate
    python web/app.py
    # then open http://localhost:8000
"""

import asyncio
import base64
import hashlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import AsyncGenerator, Optional

import httpx
import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from pydantic import BaseModel

# Allow importing scanner_core from project root
sys.path.insert(0, str(Path(__file__).parent.parent))

import google.genai as genai
from scanner_core.engine import _merge
from scanner_core.llm_analyzer import LLMAnalyzer
from scanner_core.models import FileResult, ScanReport, Severity, Vulnerability
from scanner_core.reporters import write_html, write_json, write_sarif
from scanner_core.static_analyzer import StaticAnalyzer
from scanner_core.utils import SCANNABLE_EXTENSIONS, detect_language

load_dotenv()

app = FastAPI(title="Security Scanner")

_HTML = (Path(__file__).parent / "index.html").read_text(encoding="utf-8")
_scans: dict[str, dict] = {}  # scan_id → {queue, report, status}


# ---------------------------------------------------------------------------
# Request model
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    pr_url: str
    github_token: str
    model: str = "gemini-2.5-flash"
    min_severity: str = "LOW"
    use_static: bool = True


# ---------------------------------------------------------------------------
# GitHub API helpers
# ---------------------------------------------------------------------------

def _parse_pr_url(url: str) -> tuple[str, str, int]:
    m = re.match(r"https?://github\.com/([^/]+)/([^/]+)/pull/(\d+)", url.strip())
    if not m:
        raise ValueError(f"Not a valid GitHub PR URL: {url!r}")
    owner, repo, num = m.groups()
    return owner, repo, int(num)


async def _gh(path: str, token: str, **kwargs):
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:  # only add Authorization when a token is actually provided
        headers["Authorization"] = f"Bearer {token}"

    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(f"https://api.github.com{path}", headers=headers, **kwargs)

    if resp.status_code == 401:
        raise PermissionError(
            "GitHub token is invalid or expired. "
            "Generate one at github.com/settings/tokens (needs 'repo' scope for private repos)."
        )
    if resp.status_code == 403:
        raise PermissionError(
            "Access denied — rate limit hit or token lacks 'repo' scope. "
            "For private repos a token with 'repo' scope is required."
        )
    if resp.status_code == 404:
        raise FileNotFoundError(
            "PR not found. Check the URL is correct and the token has access to the repo."
        )
    resp.raise_for_status()
    return resp.json()


async def _fetch_file_content(owner: str, repo: str, path: str, ref: str, token: str) -> str:
    try:
        data = await _gh(f"/repos/{owner}/{repo}/contents/{path}", token, params={"ref": ref})
        if not isinstance(data, dict):
            return ""
        # Normal file ≤ 1 MB
        if data.get("encoding") == "base64" and data.get("content"):
            return base64.b64decode(data["content"].replace("\n", "")).decode("utf-8", errors="replace")
        # Large file — fall back to raw download URL
        download_url = data.get("download_url")
        if download_url:
            dl_headers = {"Authorization": f"Bearer {token}"} if token else {}
            async with httpx.AsyncClient(timeout=30) as client:
                r = await client.get(download_url, headers=dl_headers)
                if r.status_code == 200:
                    return r.text
    except Exception:
        pass
    return ""


# ---------------------------------------------------------------------------
# Scan runner (async, streams events into per-scan queue)
# ---------------------------------------------------------------------------

async def _run_scan(scan_id: str, req: ScanRequest) -> None:
    state = _scans[scan_id]
    queue: asyncio.Queue = state["queue"]

    async def emit(event_type: str, **data) -> None:
        await queue.put(json.dumps({"type": event_type, **data}))

    try:
        owner, repo, pr_num = _parse_pr_url(req.pr_url)
        await emit("log", level="info", text=f"Fetching PR #{pr_num} from {owner}/{repo}…")

        pr_meta = await _gh(f"/repos/{owner}/{repo}/pulls/{pr_num}", req.github_token)
        head_sha = pr_meta["head"]["sha"]
        pr_files = await _gh(
            f"/repos/{owner}/{repo}/pulls/{pr_num}/files",
            req.github_token,
            params={"per_page": 100},
        )

        scannable = [
            f for f in pr_files
            if Path(f["filename"]).suffix.lower() in SCANNABLE_EXTENSIONS
            and f.get("status") != "removed"
        ]

        await emit("pr_info",
            title=pr_meta.get("title", ""),
            repo=f"{owner}/{repo}",
            pr_num=pr_num,
            branch=pr_meta["head"]["ref"],
            author=pr_meta["user"]["login"],
            avatar=pr_meta["user"]["avatar_url"],
            pr_url=pr_meta["html_url"],
            total_files=len(pr_files),
            scannable_files=len(scannable),
            sha=head_sha[:8],
        )

        if not scannable:
            await emit("log", level="warning", text="No scannable source files changed in this PR.")
            state["report"] = ScanReport()
            await emit("complete", total_files=0, total_findings=0, severity_counts={})
            return

        api_key = os.getenv("GOOGLE_API_KEY")
        if not api_key:
            raise EnvironmentError("GOOGLE_API_KEY is not set. Add it to your .env file.")

        client = genai.Client(api_key=api_key)
        llm = LLMAnalyzer(client, model=req.model)
        static = StaticAnalyzer() if req.use_static else None
        min_sev = Severity(req.min_severity)
        file_results: list[FileResult] = []

        for i, file_info in enumerate(scannable):
            filepath = file_info["filename"]
            language = detect_language(Path(filepath))
            await emit("file_start", file=filepath, language=language, index=i, total=len(scannable))

            content = await _fetch_file_content(owner, repo, filepath, head_sha, req.github_token)
            if not content.strip():
                await emit("file_skip", file=filepath)
                continue

            # Run both analyzers in worker threads (they're synchronous)
            static_v: list[Vulnerability] = []
            if static and language == "Python":
                static_v = await asyncio.to_thread(static.analyze, content, filepath)

            try:
                llm_v = await asyncio.to_thread(llm.analyze, content, language)
            except Exception as exc:
                llm_v = []
                await emit("log", level="warning", text=f"LLM failed for {filepath}: {exc}")

            vulns = _merge(static_v, llm_v)
            vulns = [v for v in vulns if v.severity.score >= min_sev.score]

            fhash = hashlib.sha256(content.encode()).hexdigest()
            result = FileResult(
                file_path=filepath, file_hash=fhash,
                language=language, vulnerabilities=vulns,
            )
            file_results.append(result)

            await emit("file_done",
                file=filepath,
                findings=len(vulns),
                severity=vulns[0].severity.value if vulns else None,
                vulns=[v.model_dump() for v in vulns],
            )

        report = ScanReport(files=file_results)
        state["report"] = report

        await emit("complete",
            total_files=len(file_results),
            total_findings=report.total_vulnerabilities,
            severity_counts=report.severity_counts,
        )

    except Exception as exc:
        import traceback
        await emit("error", text=str(exc), detail=traceback.format_exc())
    finally:
        state["status"] = "done"
        await queue.put(None)  # sentinel — tells SSE generator to close


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def index():
    return _HTML


@app.post("/api/scan")
async def start_scan(req: ScanRequest):
    import uuid
    scan_id = str(uuid.uuid4())[:8]
    _scans[scan_id] = {"queue": asyncio.Queue(), "report": None, "status": "running"}
    asyncio.create_task(_run_scan(scan_id, req))
    return {"scan_id": scan_id}


@app.get("/api/scan/{scan_id}/events")
async def scan_events(scan_id: str):
    state = _scans.get(scan_id)
    if not state:
        raise HTTPException(404, "Scan not found")

    queue: asyncio.Queue = state["queue"]

    async def generate() -> AsyncGenerator[str, None]:
        while True:
            msg = await queue.get()
            if msg is None:
                yield 'data: {"type":"done"}\n\n'
                break
            yield f"data: {msg}\n\n"

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/api/scan/{scan_id}/download/{fmt}")
async def download_report(scan_id: str, fmt: str):
    state = _scans.get(scan_id)
    if not state:
        raise HTTPException(404, "Scan not found")
    report: Optional[ScanReport] = state.get("report")
    if not report:
        raise HTTPException(409, "Scan not complete yet")

    tmp = Path(tempfile.mkdtemp())
    if fmt == "html":
        out = tmp / "security-report.html"
        write_html(report, out)
        return FileResponse(str(out), filename="security-report.html", media_type="text/html")
    elif fmt == "json":
        out = tmp / "security-report.json"
        write_json(report, out)
        return FileResponse(str(out), filename="security-report.json", media_type="application/json")
    elif fmt == "sarif":
        out = tmp / "security-results.sarif"
        write_sarif(report, out)
        return FileResponse(str(out), filename="security-results.sarif", media_type="application/json")
    else:
        raise HTTPException(400, f"Unknown format: {fmt!r}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    print(f"\n  Security Scanner UI → http://localhost:{port}\n")
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")
