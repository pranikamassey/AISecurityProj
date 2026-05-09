import os
import subprocess
from pathlib import Path
from typing import Optional

_SKIP_DIRS = frozenset({
    "node_modules", ".git", "venv", ".venv", "__pycache__",
    "dist", "build", ".next", ".cache", "target",
})

_LANGUAGE_MAP: dict[str, str] = {
    ".py": "Python",
    ".js": "JavaScript",
    ".ts": "TypeScript",
    ".jsx": "JavaScript (JSX)",
    ".tsx": "TypeScript (TSX)",
    ".java": "Java",
    ".go": "Go",
    ".rb": "Ruby",
    ".php": "PHP",
    ".cs": "C#",
    ".cpp": "C++",
    ".c": "C",
    ".rs": "Rust",
    ".sh": "Shell",
    ".yaml": "YAML",
    ".yml": "YAML",
    ".sql": "SQL",
    ".tf": "Terraform",
}

SCANNABLE_EXTENSIONS = frozenset(_LANGUAGE_MAP.keys())


def detect_language(path: Path) -> str:
    return _LANGUAGE_MAP.get(path.suffix.lower(), "Unknown")


def collect_files(root: Path, extensions: frozenset[str] = SCANNABLE_EXTENSIONS) -> list[Path]:
    results: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in extensions:
            continue
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        results.append(path)
    return results


def get_git_changed_files(base_ref: Optional[str] = None) -> list[str]:
    """Return scannable files changed vs base_ref (falls back to HEAD~1).

    In GitHub Actions, GITHUB_BASE_REF is set automatically on pull_request
    events, so callers can pass it directly or leave it None to auto-detect.
    """
    if base_ref is None:
        base_ref = os.environ.get("GITHUB_BASE_REF")

    if base_ref:
        # PR context: diff between the merge base and HEAD
        cmd = ["git", "diff", "--name-only", f"origin/{base_ref}...HEAD"]
    else:
        # Push / local context: last commit
        cmd = ["git", "diff", "--name-only", "HEAD~1", "HEAD"]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []

    changed = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    return [
        f for f in changed
        if Path(f).exists() and Path(f).suffix.lower() in SCANNABLE_EXTENSIONS
    ]
