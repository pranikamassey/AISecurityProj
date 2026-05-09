"""AST-based static analyzer for Python source files.

Detects patterns the LLM might miss or mislocate:
- SQL injection via f-string / format / % in cursor.execute
- Command injection via os.system, subprocess shell=True, eval, exec
- Weak crypto (MD5/SHA1 for hashing)
- Insecure deserialization (pickle.loads, yaml.load without Loader)
- Hardcoded secrets via regex
"""

import ast
import re
from typing import Optional

from .models import Vulnerability, Severity


class _ASTVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.findings: list[Vulnerability] = []

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _line(node: ast.AST) -> Optional[int]:
        return getattr(node, "lineno", None)

    def _add(self, v: Vulnerability) -> None:
        self.findings.append(v)

    # ------------------------------------------------------------------
    # Dispatch
    # ------------------------------------------------------------------
    def visit_Call(self, node: ast.Call) -> None:
        self._check_eval_exec(node)
        self._check_os_shell(node)
        self._check_subprocess_shell(node)
        self._check_sql_execute(node)
        self._check_weak_hash(node)
        self._check_pickle(node)
        self._check_yaml_load(node)
        self.generic_visit(node)

    # ------------------------------------------------------------------
    # Checkers
    # ------------------------------------------------------------------
    def _check_eval_exec(self, node: ast.Call) -> None:
        func = node.func
        if not (isinstance(func, ast.Name) and func.id in ("eval", "exec")):
            return
        self._add(Vulnerability(
            severity=Severity.CRITICAL,
            type="Code Injection (eval/exec)",
            description=f"`{func.id}()` executes arbitrary Python, including attacker-supplied strings.",
            impact="Full remote code execution with the application's OS privileges.",
            fix="Replace eval/exec with ast.literal_eval() for safe literal parsing, or redesign the logic.",
            line_number=self._line(node),
            confidence=0.97,
            source="static",
        ))

    def _check_os_shell(self, node: ast.Call) -> None:
        func = node.func
        if not (isinstance(func, ast.Attribute) and func.attr in ("system", "popen")
                and isinstance(func.value, ast.Name) and func.value.id == "os"):
            return
        # f-string argument → near-certain injection
        confidence = 0.98 if (node.args and isinstance(node.args[0], ast.JoinedStr)) else 0.80
        self._add(Vulnerability(
            severity=Severity.CRITICAL,
            type="Command Injection",
            description=f"os.{func.attr}() passes unsanitized input directly to the shell.",
            impact="Arbitrary OS command execution as the application user.",
            fix="Use subprocess.run(['cmd', arg], shell=False) and validate/whitelist all inputs.",
            line_number=self._line(node),
            confidence=confidence,
            source="static",
        ))

    def _check_subprocess_shell(self, node: ast.Call) -> None:
        func = node.func
        if not (isinstance(func, ast.Attribute) and func.attr in ("run", "call", "Popen", "check_output")
                and isinstance(func.value, ast.Name) and func.value.id == "subprocess"):
            return
        for kw in node.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                self._add(Vulnerability(
                    severity=Severity.HIGH,
                    type="Command Injection (shell=True)",
                    description="subprocess called with shell=True; shell metacharacters in arguments cause injection.",
                    impact="Command injection when any argument is user-controlled.",
                    fix="Remove shell=True and pass arguments as a list: subprocess.run(['cmd', arg1, arg2]).",
                    line_number=self._line(node),
                    confidence=0.92,
                    source="static",
                ))

    def _check_sql_execute(self, node: ast.Call) -> None:
        func = node.func
        if not (isinstance(func, ast.Attribute) and func.attr == "execute"):
            return
        if not node.args:
            return
        first = node.args[0]

        def _vuln(description: str, confidence: float) -> None:
            self._add(Vulnerability(
                severity=Severity.CRITICAL,
                type="SQL Injection",
                description=description,
                impact="Authentication bypass, full data exfiltration, or database destruction.",
                fix="Use parameterized queries: cursor.execute('SELECT * FROM t WHERE id = ?', (val,))",
                line_number=self._line(node),
                confidence=confidence,
                source="static",
            ))

        if isinstance(first, ast.JoinedStr):
            _vuln("SQL query built with an f-string embeds user input directly.", 0.98)
        elif isinstance(first, ast.BinOp) and isinstance(first.op, ast.Mod):
            _vuln("SQL query built with %-formatting allows injection.", 0.90)
        elif (isinstance(first, ast.Call) and isinstance(first.func, ast.Attribute)
              and first.func.attr == "format"):
            _vuln("SQL query built with str.format() allows injection.", 0.90)

    def _check_weak_hash(self, node: ast.Call) -> None:
        func = node.func
        if not (isinstance(func, ast.Attribute) and func.attr in ("md5", "sha1")
                and isinstance(func.value, ast.Name) and func.value.id == "hashlib"):
            return
        self._add(Vulnerability(
            severity=Severity.HIGH,
            type="Weak Cryptographic Hash",
            description=f"hashlib.{func.attr}() is cryptographically broken; do not use for password hashing.",
            impact="Hashed passwords cracked in seconds with rainbow tables or GPU attacks.",
            fix="Use a proper password KDF: `from passlib.hash import argon2; argon2.hash(password)`",
            line_number=self._line(node),
            confidence=0.88,
            source="static",
        ))

    def _check_pickle(self, node: ast.Call) -> None:
        func = node.func
        if not (isinstance(func, ast.Attribute) and func.attr == "loads"
                and isinstance(func.value, ast.Name) and func.value.id == "pickle"):
            return
        self._add(Vulnerability(
            severity=Severity.CRITICAL,
            type="Insecure Deserialization",
            description="pickle.loads() deserializes arbitrary Python objects and can execute embedded code.",
            impact="Remote code execution when deserializing attacker-controlled payloads.",
            fix="Use JSON/MessagePack for untrusted data. If pickle is required, verify an HMAC signature first.",
            line_number=self._line(node),
            confidence=0.92,
            source="static",
        ))

    def _check_yaml_load(self, node: ast.Call) -> None:
        func = node.func
        if not (isinstance(func, ast.Attribute) and func.attr == "load"
                and isinstance(func.value, ast.Name) and func.value.id == "yaml"):
            return
        if any(kw.arg == "Loader" for kw in node.keywords):
            return
        self._add(Vulnerability(
            severity=Severity.HIGH,
            type="Insecure YAML Deserialization",
            description="yaml.load() without an explicit Loader can deserialize and execute arbitrary Python.",
            impact="Arbitrary code execution via crafted YAML input.",
            fix="Use yaml.safe_load(data) or yaml.load(data, Loader=yaml.SafeLoader).",
            line_number=self._line(node),
            confidence=0.95,
            source="static",
        ))


# Regex patterns for secrets that can't be caught by AST
_SECRET_PATTERNS: list[tuple[str, str, Severity]] = [
    (r'(?i)(?:password|passwd|pwd)\s*=\s*["\']([^"\']{4,})["\']',
     "Hardcoded Password", Severity.HIGH),
    (r'(?i)(?:api_?key|apikey|secret_?key|access_?token|auth_?token)\s*=\s*["\']([^"\']{8,})["\']',
     "Hardcoded API Key", Severity.HIGH),
    (r'sk-[a-zA-Z0-9]{20,}',
     "Hardcoded OpenAI-style API Key", Severity.HIGH),
    (r'(?i)aws_secret_access_key\s*=\s*["\']([^"\']+)["\']',
     "Hardcoded AWS Secret", Severity.CRITICAL),
    (r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
     "Embedded Private Key", Severity.CRITICAL),
]


class StaticAnalyzer:
    def analyze(self, code: str, file_path: str) -> list[Vulnerability]:
        findings: list[Vulnerability] = []

        try:
            tree = ast.parse(code)
        except SyntaxError:
            return []

        visitor = _ASTVisitor()
        visitor.visit(tree)
        findings.extend(visitor.findings)
        findings.extend(self._scan_secrets(code))
        return self._deduplicate(findings)

    @staticmethod
    def _scan_secrets(code: str) -> list[Vulnerability]:
        results: list[Vulnerability] = []
        for lineno, line in enumerate(code.splitlines(), start=1):
            for pattern, vuln_type, severity in _SECRET_PATTERNS:
                if re.search(pattern, line):
                    results.append(Vulnerability(
                        severity=severity,
                        type=vuln_type,
                        description=f"Hardcoded secret found in source — pattern matches '{vuln_type}'.",
                        impact="Anyone with code access (repo clone, leak, employee) gains the credential.",
                        fix="Use os.getenv('SECRET_NAME') and store the value in .env (gitignored). "
                            "Rotate the secret immediately if it was ever committed.",
                        line_number=lineno,
                        confidence=0.88,
                        source="static",
                    ))
        return results

    @staticmethod
    def _deduplicate(findings: list[Vulnerability]) -> list[Vulnerability]:
        seen: set[tuple[str, Optional[int]]] = set()
        unique: list[Vulnerability] = []
        for v in findings:
            key = (v.type, v.line_number)
            if key not in seen:
                seen.add(key)
                unique.append(v)
        return unique
