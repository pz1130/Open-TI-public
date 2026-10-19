import json
import os
import shutil
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import httpx
import pytest

from opti.core.config import ProjectRules
from opti.core.secrets import fingerprint
from opti.enrichers.secret_scan.enricher import (
    BLOB_LIMIT,
    RunResult,
    SecretScanEnricher,
    run_process,
    scan_checkout,
)
from opti.sdk.testing import make_context

FAKE_AWS = "AKIA" + "QYLPMN5HTWX2BVFC"
REPORT = [
    {"RuleID": "aws-access-token", "Description": "AWS", "File": "config/app.env", "StartLine": 2,
     "EndLine": 2, "Commit": "c" * 40, "Date": "2026-09-20T00:00:00Z", "Secret": FAKE_AWS,
     "Match": "AWS=" + FAKE_AWS, "Author": "Jane Dev", "Email": "jane@example.org", "Message": "oops"},
]  # fmt: skip
APP_ENV = f"# deploy settings\nAWS={FAKE_AWS}\nREGION=ap-east-1\n"


class FakeRunner:
    def __init__(self, *, report: list[Any] | None = None, clone_rc: int = 0,
                 clone_timeout: bool = False, scan_timeout: bool = False,
                 files: dict[str, str | RunResult] | None = None) -> None:  # fmt: skip
        self.report = report if report is not None else REPORT
        self.clone_rc, self.clone_timeout, self.scan_timeout = clone_rc, clone_timeout, scan_timeout
        self.files = files if files is not None else {"config/app.env": APP_ENV}
        self.calls: list[tuple[list[str], float, dict[str, str], str]] = []
        self.limits: list[int] = []
        self.report_path: str | None = None

    async def __call__(self, args: Sequence[str], timeout: float, env: Mapping[str, str],
                       cwd: str, *, limit: int = 10_000) -> RunResult:  # fmt: skip
        args = list(args)
        self.calls.append((args, timeout, dict(env), cwd))
        self.limits.append(limit)
        if "show" in args:
            found = self.files.get(args[-1].split(":", 1)[1])
            if isinstance(found, RunResult):
                return found
            return RunResult(0, found, False) if found is not None else RunResult(128, "", False)
        if "clone" in args:
            if self.clone_timeout:
                return RunResult(-9, "", True)
            os.makedirs(args[-1], exist_ok=True)
            return RunResult(self.clone_rc, "", False)
        if "rev-parse" in args:
            return RunResult(0, "a" * 40 + "\n", False)
        if args[0] == "gitleaks":
            if self.scan_timeout:
                return RunResult(-9, "", True)
            self.report_path = args[args.index("--report-path") + 1]
            Path(self.report_path).write_text(json.dumps(self.report), encoding="utf-8")
            return RunResult(0, "", False)
        raise AssertionError(f"unexpected command {args}")


def _meta(status: int = 200, **fields: Any):
    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == "https://api.github.com/repos/acme/tools"
        return httpx.Response(
            status,
            json={"private": False, "size": 1200, "default_branch": "main",
                  "description": "Deploy scripts", "homepage": "https://acme.example",
                  "owner": {"login": "acme", "type": "Organization"}, "fork": False,
                  "topics": ["deploy", "ops"], "created_at": "2024-01-02T03:04:05Z",
                  "pushed_at": "2026-09-20T00:00:00Z", **fields},
        )  # fmt: skip

    return handler


def _enricher(rules: ProjectRules, runner: FakeRunner,
              handler: Any = None, **config: Any) -> SecretScanEnricher:  # fmt: skip
    context = make_context(rules, connector_id="secret_scan", handler=handler or _meta())
    return SecretScanEnricher(context, config, runner=runner)


async def test_scan_result_never_contains_raw_secret(sbr_rules: ProjectRules) -> None:
    runner = FakeRunner()
    out = await _enricher(sbr_rules, runner).enrich("repo", "github.com/acme/tools")
    assert out["scanned"] is True and out["commit"] == "a" * 40 and out["total"] == 1
    [secret] = out["secrets"]
    assert (
        secret["prefix"] == "AKIA" and secret["rule"] == "aws-access-token" and secret["line"] == 2
    )
    blob = json.dumps(out)
    for leaked in (FAKE_AWS[4:], "Jane", "jane", "oops"):
        assert leaked not in blob
    assert runner.report_path is not None and not Path(runner.report_path).exists()


async def test_clone_is_hardened(sbr_rules: ProjectRules) -> None:
    runner = FakeRunner()
    await _enricher(sbr_rules, runner).enrich("repo", "github.com/acme/tools")
    clone, timeout, env, cwd = runner.calls[0]
    for flag in (
        "core.hooksPath=/dev/null",
        "protocol.file.allow=never",
        "credential.helper=",
        "--no-tags",
        "--single-branch",
        "--quiet",
    ):
        assert flag in clone
    assert clone[clone.index("--depth") + 1] == "100"
    assert clone[-2] == "https://github.com/acme/tools.git" and "--recurse-submodules" not in clone
    assert (
        env["GIT_TERMINAL_PROMPT"] == "0"
        and env["GIT_LFS_SKIP_SMUDGE"] == "1"
        and env["HOME"] == cwd
    )
    assert timeout == 40
    scan = next(call for call in runner.calls if call[0][0] == "gitleaks")[0]
    assert scan[1] == "git" and scan[scan.index("--exit-code") + 1] == "0"
    assert "--log-opts=--max-count=100" in scan


async def test_skips_private_large_missing(sbr_rules: ProjectRules) -> None:
    runner = FakeRunner()
    assert (
        await _enricher(sbr_rules, runner, _meta(private=True)).enrich(
            "repo", "github.com/acme/tools"
        )
    )["skipped"] == "private"
    assert (
        await _enricher(sbr_rules, runner, _meta(size=500_000)).enrich(
            "repo", "github.com/acme/tools"
        )
    )["skipped"] == "too_large"
    assert (await _enricher(sbr_rules, runner, _meta(404)).enrich("repo", "github.com/acme/tools"))[
        "skipped"
    ] == "not_found"
    assert runner.calls == []
    assert (await _enricher(sbr_rules, runner).enrich("repo", "github.com/../etc"))[
        "error"
    ] == "invalid_repo"
    assert (
        await _enricher(sbr_rules, runner, api_base="https://evil.example").enrich(
            "repo", "github.com/acme/tools"
        )
    )["error"] == "github:invalid_base"


async def test_timeouts_and_failures(sbr_rules: ProjectRules) -> None:
    for runner, error in (
        (FakeRunner(clone_timeout=True), "clone_timeout"),
        (FakeRunner(clone_rc=128), "clone_failed"),
        (FakeRunner(scan_timeout=True), "scan_timeout"),
    ):
        out = await _enricher(sbr_rules, runner).enrich("repo", "github.com/acme/tools")
        assert out["scanned"] is False and out["error"] == error


async def test_run_process_kills_on_timeout(tmp_path: Path) -> None:
    result = await run_process(
        ["sleep", "5"], 0.2, {"PATH": os.environ.get("PATH", "")}, str(tmp_path)
    )
    assert result.timed_out


@pytest.mark.skipif(
    shutil.which("gitleaks") is None or shutil.which("git") is None,
    reason="requires git and gitleaks",
)
async def test_real_gitleaks_on_local_repo(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    env = {"PATH": os.environ.get("PATH", ""), "HOME": str(tmp_path), "GIT_CONFIG_NOSYSTEM": "1"}
    for args in (
        ["init", "-q"],
        ["config", "user.email", "t@example.org"],
        ["config", "user.name", "t"],
    ):
        subprocess.run(["git", *args], cwd=repo, env=env, check=True)
    (repo / "app.env").write_text(f"AWS_ACCESS_KEY_ID={FAKE_AWS}\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, env=env, check=True)
    subprocess.run(["git", "commit", "-qm", "add"], cwd=repo, env=env, check=True)
    work = tmp_path / "work"
    work.mkdir()
    out = await scan_checkout(run_process, str(repo), "acme/tools", head="x", gitleaks_bin="gitleaks",
                              depth=10, timeout=60, env=env, workdir=str(work))  # fmt: skip
    assert out["scanned"] is True
    assert any(
        secret["rule"].startswith("aws") and secret["prefix"] == "AKIA" for secret in out["secrets"]
    )
    assert any(
        secret["context"][:1] == [f"AWS_ACCESS_KEY_ID=AKIA…[REDACTED:{fingerprint(FAKE_AWS)[:8]}]"]
        for secret in out["secrets"]
    )
    assert FAKE_AWS[4:] not in json.dumps(out)


def _report(**overrides: Any) -> list[dict[str, Any]]:
    return [{**REPORT[0], **overrides}]


async def test_context_is_masked_window(sbr_rules: ProjectRules) -> None:
    runner = FakeRunner()
    out = await _enricher(sbr_rules, runner).enrich("repo", "github.com/acme/tools")
    [secret] = out["secrets"]
    tag = fingerprint(FAKE_AWS)[:8]
    assert secret["context"] == [
        "# deploy settings",
        f"AWS=AKIA…[REDACTED:{tag}]",
        "REGION=ap-east-1",
        "",
    ]
    assert FAKE_AWS[4:] not in json.dumps(out)
    show = next(call for call in runner.calls if "show" in call[0])[0]
    assert show[-1] == "c" * 40 + ":config/app.env" and "--no-textconv" in show
    assert BLOB_LIMIT in runner.limits


async def test_context_window_is_three_lines_each_side(sbr_rules: ProjectRules) -> None:
    body = (
        "\n".join(f"line{i}" for i in range(1, 10))
        + f"\nKEY={FAKE_AWS}\n"
        + "\n".join(f"line{i}" for i in range(11, 20))
    )
    runner = FakeRunner(report=_report(StartLine=10, EndLine=10), files={"config/app.env": body})
    [secret] = (await _enricher(sbr_rules, runner).enrich("repo", "github.com/acme/tools"))[
        "secrets"
    ]
    assert secret["context"][0] == "line7" and secret["context"][-1] == "line13"
    assert len(secret["context"]) == 7 and secret["context"][3].startswith("KEY=AKIA…[REDACTED:")


async def test_multiline_private_key_collapses(sbr_rules: ProjectRules) -> None:
    kind = "RSA " + "PRIVATE KEY"
    key = (
        f"-----BEGIN {kind}-----\n"
        + "\n".join(["MIIEow" + "Q" * 58] * 20)
        + f"\n-----END {kind}-----"
    )
    body = f"before\n{key}\nafter\n"
    runner = FakeRunner(report=_report(RuleID="private-key", Secret=key, StartLine=2, EndLine=23),
                        files={"config/app.env": body})  # fmt: skip
    out = await _enricher(sbr_rules, runner).enrich("repo", "github.com/acme/tools")
    [secret] = out["secrets"]
    assert secret["context"][0] == "before" and secret["context"][2] == "after"
    assert "Q" * 58 not in json.dumps(out)


@pytest.mark.parametrize(
    "files",
    [
        {},  # git show fails (file missing)
        {"config/app.env": f"\x00\x01binary AWS={FAKE_AWS}\n"},
        {"config/app.env": f"AWS={FAKE_AWS} " + "x" * 3000 + "\n"},
        {"config/app.env": "the secret is not on these lines\nAWS=rotated\n"},
        {"config/app.env": RunResult(-9, "", True)},
        {"config/app.env": RunResult(0, "y" * BLOB_LIMIT, False)},
    ],
    ids=["missing", "binary", "long-line", "secret-absent", "timeout", "truncated"],
)
async def test_unsafe_or_unreadable_context_is_empty(
    sbr_rules: ProjectRules, files: dict[str, str | RunResult]
) -> None:
    runner = FakeRunner(files=files)
    out = await _enricher(sbr_rules, runner).enrich("repo", "github.com/acme/tools")
    assert out["scanned"] is True and out["secrets"][0]["context"] == []
    assert FAKE_AWS[4:] not in json.dumps(out)


async def test_context_for_ten_secrets_critical_first(sbr_rules: ProjectRules) -> None:
    report = []
    files: dict[str, str] = {}
    for i in range(12):
        value = f"generic-{i:02d}-" + "k" * 20
        path = f"src/f{i}.py"
        files[path] = f"TOKEN = '{value}'\n"
        report.append({**REPORT[0], "RuleID": "generic-api-key", "File": path, "StartLine": 1,
                       "EndLine": 1, "Secret": value, "Date": f"2026-09-{i + 1:02d}T00:00:00Z"})  # fmt: skip
    files["config/app.env"] = APP_ENV
    report.append({**REPORT[0], "Date": "2020-01-01T00:00:00Z"})
    runner = FakeRunner(report=report, files=files)
    secrets = (await _enricher(sbr_rules, runner).enrich("repo", "github.com/acme/tools"))[
        "secrets"
    ]
    with_context = {s["file"] for s in secrets if s["context"]}
    assert len(with_context) == 10 and "config/app.env" in with_context
    assert "src/f0.py" not in with_context and "src/f1.py" not in with_context
    assert sum(1 for call in runner.calls if "show" in call[0]) == 10
    newest = next(s for s in secrets if s["file"] == "src/f11.py")
    tag = fingerprint("generic-11-" + "k" * 20)[:8]
    assert newest["context"] == [f"TOKEN = 'gene…[REDACTED:{tag}]'", ""]


async def test_repo_meta_is_cleaned(sbr_rules: ProjectRules) -> None:
    runner = FakeRunner()
    handler = _meta(description="Deploy " + FAKE_AWS + " " + "d" * 400, homepage="http://insecure",
                    topics=["ab." * 27] * 12)  # fmt: skip
    out = await _enricher(sbr_rules, runner, handler).enrich("repo", "github.com/acme/tools")
    meta = out["repo_meta"]
    assert meta["owner"] == "acme" and meta["owner_type"] == "Organization"
    assert meta["fork"] is False and meta["homepage"] == ""
    assert len(meta["description"]) <= 300 and FAKE_AWS[4:] not in meta["description"]
    assert len(meta["topics"]) == 10 and all(len(t) == 50 for t in meta["topics"])
    assert meta["created_at"] == "2024-01-02T03:04:05Z"


async def test_neighbouring_secrets_in_the_window_are_masked(sbr_rules: ProjectRules) -> None:
    signing = "f3a9c1d7" + "e2b84a6f"  # 16 位：redact_text 认不出这种形态
    header = "Zm9vYmFy" + "YmF6cXV4" + "MTIzNDU2"
    body = f"# deploy\nAWS={FAKE_AWS}\nsigning_key = '{signing}'\nauth_header: \"{header}\"\n"
    report = [
        *_report(),
        {**REPORT[0], "RuleID": "generic-api-key", "StartLine": 3, "EndLine": 3, "Secret": signing},
        {**REPORT[0], "RuleID": "generic-api-key", "StartLine": 4, "EndLine": 4, "Secret": header},
    ]
    runner = FakeRunner(report=report, files={"config/app.env": body})
    out = await _enricher(sbr_rules, runner).enrich("repo", "github.com/acme/tools")
    blob = json.dumps(out)
    for raw in (FAKE_AWS[4:], signing, header):
        assert raw not in blob
    first = next(s for s in out["secrets"] if s["line"] == 2)
    assert first["context"][2] == f"signing_key = 'f3a9…[REDACTED:{fingerprint(signing)[:8]}]'"


async def test_window_cutting_through_another_secret_is_dropped(sbr_rules: ProjectRules) -> None:
    kind = "RSA " + "PRIVATE KEY"
    key = (
        f"-----BEGIN {kind}-----\n"
        + "\n".join(["MIIEow" + "Q" * 58] * 20)
        + f"\n-----END {kind}-----"
    )
    body = f"AWS={FAKE_AWS}\nx\n{key}\n"
    report = [
        *_report(StartLine=1, EndLine=1),
        {**REPORT[0], "RuleID": "private-key", "Secret": key, "StartLine": 3, "EndLine": 24},
    ]
    runner = FakeRunner(report=report, files={"config/app.env": body})
    out = await _enricher(sbr_rules, runner).enrich("repo", "github.com/acme/tools")
    aws = next(s for s in out["secrets"] if s["line"] == 1)
    assert aws["context"] == []  # 窗口只截到私钥的开头几行：整段丢弃
    assert "Q" * 58 not in json.dumps(out)
