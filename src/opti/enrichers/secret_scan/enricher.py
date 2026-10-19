"""Scan related public repositories on a collector; return only redacted findings."""

from __future__ import annotations

import asyncio
import json
import os
import re
import signal
import tempfile
import time
from collections.abc import Awaitable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar, Protocol

from opti.core.codehits import CONTEXT_LINE_CHARS, CONTEXT_MAX_LINES, clean_repo_meta
from opti.core.secrets import fingerprint, is_critical_rule, mask, redact_findings, redact_text
from opti.sdk.base import Enricher
from opti.sdk.context import ConnectorContext
from opti.sdk.http import HttpError
from opti.sdk.models import Tier

REPO_VALUE = re.compile(r"^github\.com/([A-Za-z0-9][A-Za-z0-9-]{0,38})/([A-Za-z0-9._-]{1,100})$")
API = "https://api.github.com"
OUTPUT_LIMIT = 10_000
BLOB_LIMIT = 6_000_000  # gitleaks --max-target-megabytes 5; longer output means truncated
CONTEXT_SECRETS = 10
CONTEXT_LINES = 3
LONG_LINE = 2000  # minified or generated content: no context
CONTEXT_BUDGET = 6.0  # seconds for all context reads; remote enrichment waits 90 s in total


@dataclass(frozen=True)
class RunResult:
    returncode: int
    stdout: str
    timed_out: bool


class Runner(Protocol):
    def __call__(
        self,
        args: Sequence[str],
        timeout: float,
        env: Mapping[str, str],
        cwd: str,
        *,
        limit: int = OUTPUT_LIMIT,
    ) -> Awaitable[RunResult]: ...


async def run_process(
    args: Sequence[str],
    timeout: float,
    env: Mapping[str, str],
    cwd: str,
    *,
    limit: int = OUTPUT_LIMIT,
) -> RunResult:
    proc = await asyncio.create_subprocess_exec(
        *args,
        cwd=cwd,
        env=dict(env),
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout)
    except TimeoutError:
        with suppress(ProcessLookupError):
            os.killpg(proc.pid, signal.SIGKILL)
        await proc.wait()
        return RunResult(-9, "", True)
    return RunResult(
        proc.returncode if proc.returncode is not None else -1,
        out.decode(errors="replace")[:limit],
        False,
    )


def _window(
    text: str, secret: str, start: int, end: int, *, known: Sequence[str] = (),
    neighbours: Sequence[tuple[int, int, str]] = (),
) -> list[str]:  # fmt: skip
    """Masked lines around one finding; empty whenever the content looks unsafe or unexpected.

    known: every secret gitleaks found in the repository (all are masked, not just this one);
    neighbours: (start, end, value) of findings in the same file and commit.
    """
    if "\x00" in text:
        return []
    lines = text.split("\n")
    if start < 1 or end < start or end > len(lines):
        return []
    lo, hi = max(1, start - CONTEXT_LINES), min(len(lines), end + CONTEXT_LINES)
    chunk = lines[lo - 1 : hi]
    if any(len(line) > LONG_LINE for line in chunk):
        return []
    block = "\n".join(chunk)
    if secret not in block:  # line numbers do not match this blob: never guess
        return []
    for first, last, value in neighbours:
        if (
            first <= hi and last >= lo and value not in block
        ):  # the window cuts through another secret
            return []
    for value in sorted({secret, *known}, key=len, reverse=True):
        block = block.replace(value, mask(value))
    masked = redact_text(block)
    return [line.rstrip()[:CONTEXT_LINE_CHARS] for line in masked.split("\n")][:CONTEXT_MAX_LINES]


def _line(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


async def _context(
    run: Runner, checkout: str, finding: Mapping[str, Any], commit: str, *, git_bin: str,
    env: Mapping[str, str], workdir: str, timeout: float, known: Sequence[str] = (),
    neighbours: Sequence[tuple[int, int, str]] = (),
) -> list[str]:  # fmt: skip
    path = str(finding.get("File") or "")
    if not path or path.startswith("/") or ".." in path.split("/"):
        return []
    start = _line(finding.get("StartLine"))
    end = max(start, _line(finding.get("EndLine")))
    result = await run(
        [git_bin, "-C", checkout, "show", "--no-textconv", "--no-color", f"{commit}:{path}"],
        timeout, env, workdir, limit=BLOB_LIMIT,
    )  # fmt: skip
    if result.timed_out or result.returncode != 0 or len(result.stdout) >= BLOB_LIMIT:
        return []
    return _window(
        result.stdout, str(finding["Secret"]), start, end, known=known, neighbours=neighbours
    )


async def attach_context(
    run: Runner, checkout: str, raw: Sequence[Any], secrets: list[dict[str, Any]], *,
    git_bin: str, env: Mapping[str, str], workdir: str,
) -> None:  # fmt: skip
    """Add masked surrounding lines to up to CONTEXT_SECRETS findings (critical first, newest first)."""
    found: dict[tuple[str, str, int], Mapping[str, Any]] = {}
    known: set[str] = set()
    ranges: dict[tuple[str, str], list[tuple[int, int, str]]] = {}
    for finding in raw:
        secret = finding.get("Secret") if isinstance(finding, dict) else None
        if isinstance(secret, str) and secret:
            commit, start = str(finding.get("Commit") or ""), _line(finding.get("StartLine"))
            found.setdefault((fingerprint(secret), commit, start), finding)
            known.add(secret)
            end = max(start, _line(finding.get("EndLine")))
            ranges.setdefault((commit, str(finding.get("File") or "")), []).append(
                (start, end, secret)
            )
    for item in secrets:
        item["context"] = []
    newest = sorted(secrets, key=lambda item: str(item.get("date") or ""), reverse=True)
    chosen = sorted(newest, key=lambda item: not is_critical_rule(str(item["rule"])))
    deadline = time.monotonic() + CONTEXT_BUDGET
    for item in chosen[:CONTEXT_SECRETS]:
        finding = found.get((item["fingerprint"], item["commit"], item["line"]))
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        if finding is None or not item["commit"]:
            continue
        neighbours = ranges.get((item["commit"], str(finding.get("File") or "")), [])
        item["context"] = await _context(run, checkout, finding, item["commit"], git_bin=git_bin,
                                         env=env, workdir=workdir, timeout=min(2.0, remaining),
                                         known=sorted(known), neighbours=neighbours)  # fmt: skip


async def scan_checkout(
    run: Runner,
    checkout: str,
    repo: str,
    *,
    head: str,
    gitleaks_bin: str,
    depth: int,
    timeout: float,
    env: Mapping[str, str],
    workdir: str,
    git_bin: str = "git",
) -> dict[str, Any]:
    report = os.path.join(workdir, "gitleaks.json")
    result = await run(
        [gitleaks_bin, "git", "--no-banner", "--exit-code", "0", "--report-format", "json",
         "--report-path", report, "--max-target-megabytes", "5", f"--log-opts=--max-count={depth}", checkout],
        timeout, env, workdir,
    )  # fmt: skip
    try:
        if result.timed_out:
            return {"scanned": False, "error": "scan_timeout"}
        if result.returncode != 0:
            return {"scanned": False, "error": f"gitleaks:{result.returncode}"}
        try:
            raw = json.loads(Path(report).read_text(encoding="utf-8") or "[]")
        except (OSError, ValueError):
            return {"scanned": False, "error": "gitleaks:report"}
        if not isinstance(raw, list):
            return {"scanned": False, "error": "gitleaks:report"}
        secrets = redact_findings(raw, repo)
        await attach_context(run, checkout, raw, secrets, git_bin=git_bin, env=env, workdir=workdir)
        del raw
        return {
            "scanned": True,
            "commit": head,
            "depth": depth,
            "total": len(secrets),
            "secrets": secrets,
        }
    finally:
        Path(report).unlink(missing_ok=True)


def repo_meta(meta: Mapping[str, Any]) -> dict[str, Any]:
    """Public GitHub repository facts that help tell whose repository this is."""
    owner = meta.get("owner")
    owner = owner if isinstance(owner, Mapping) else {}
    return clean_repo_meta(
        {
            "description": meta.get("description"),
            "homepage": meta.get("homepage"),
            "owner": owner.get("login"),
            "owner_type": owner.get("type"),
            "fork": meta.get("fork"),
            "topics": meta.get("topics"),
            "created_at": meta.get("created_at"),
            "pushed_at": meta.get("pushed_at"),
        }
    )


class SecretScanEnricher(Enricher):
    id: ClassVar[str] = "secret_scan"
    tier: ClassVar[Tier] = Tier.FREE
    supported_types: ClassVar[tuple[str, ...]] = ("repo",)
    cache_ttl_seconds: ClassVar[int] = 30 * 24 * 3600

    def __init__(
        self, ctx: ConnectorContext, config: Mapping[str, Any], *, runner: Runner | None = None
    ) -> None:
        super().__init__(ctx, config)
        self._run = runner or run_process

    async def _meta(self, owner: str, name: str) -> Any:
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        token = self.ctx.secret("github_token")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        api = str(self.config.get("api_base", API)).rstrip("/")
        return (await self.ctx.http().get(f"{api}/repos/{owner}/{name}", headers=headers,
                                          follow_redirects=False)).json()  # fmt: skip

    async def enrich(self, entity_type: str, value: str) -> dict[str, Any]:
        match = REPO_VALUE.fullmatch(value)
        if entity_type != "repo" or match is None or ".." in value:
            return {"supported": False, "error": "invalid_repo"}
        owner, name = match.groups()
        repo = f"{owner}/{name}"
        if str(self.config.get("api_base", API)).rstrip("/") != API:
            return {"supported": True, "scanned": False, "error": "github:invalid_base"}
        try:
            meta = await self._meta(owner, name)
        except HttpError as exc:
            if exc.status == 404:
                return {"supported": True, "scanned": False, "skipped": "not_found"}
            return {
                "supported": True,
                "scanned": False,
                "error": f"github:{exc.status or 'network'}",
            }
        except ValueError:
            return {"supported": True, "scanned": False, "error": "github:invalid_json"}
        if not isinstance(meta, dict) or meta.get("private") is not False:
            return {"supported": True, "scanned": False, "skipped": "private"}
        size = meta.get("size")
        if not isinstance(size, int) or size > int(self.config.get("max_kb", 100_000)):
            return {"supported": True, "scanned": False, "skipped": "too_large"}
        depth = int(self.config.get("depth", 100))
        git = str(self.config.get("git_bin", "git"))
        clone_base = str(self.config.get("clone_base", "https://github.com")).rstrip("/")
        if clone_base != "https://github.com":
            return {"supported": True, "scanned": False, "error": "clone_base"}
        with tempfile.TemporaryDirectory(prefix="opti-scan-") as tmp:
            checkout = os.path.join(tmp, "repo")
            env = {
                "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
                "HOME": tmp,
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_LFS_SKIP_SMUDGE": "1",
                "GIT_CONFIG_NOSYSTEM": "1",
            }
            clone = await self._run(
                [git, "-c", "core.hooksPath=/dev/null", "-c", "protocol.file.allow=never", "-c",
                 "credential.helper=", "clone", "--quiet", "--no-tags", "--single-branch", "--depth",
                 str(depth), f"{clone_base}/{repo}.git", checkout],
                float(self.config.get("clone_timeout", 40)), env, tmp,
            )  # fmt: skip
            if clone.timed_out:
                return {"supported": True, "scanned": False, "error": "clone_timeout"}
            if clone.returncode != 0:
                return {"supported": True, "scanned": False, "error": "clone_failed"}
            head = await self._run([git, "-C", checkout, "rev-parse", "HEAD"], 10.0, env, tmp)
            if (
                head.timed_out
                or head.returncode != 0
                or not re.fullmatch(r"[0-9a-fA-F]{40}", head.stdout.strip())
            ):
                return {"supported": True, "scanned": False, "error": "clone_head"}
            result = await scan_checkout(
                self._run, checkout, repo, head=head.stdout.strip(),
                gitleaks_bin=str(self.config.get("gitleaks_bin", "gitleaks")), depth=depth,
                timeout=float(self.config.get("scan_timeout", 40)), env=env, workdir=tmp, git_bin=git,
            )  # fmt: skip
        if result.get("scanned"):
            result["repo_meta"] = repo_meta(meta)
        return {"supported": True, **result}
