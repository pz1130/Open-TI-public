import { screen } from "@testing-library/react";
import CodeLeakCard from "./CodeLeakCard";
import { renderApp } from "../test/render";

const MATCH = {
  repo: "dev2/deploy",
  hits: [
    { path: "config/app.env", html_url: "https://github.com/dev2/deploy/blob/main/config/app.env",
      term_kind: "internal", fork: true, fragments: ["HOST=intranet-gw01"] },
  ],
  scan: {
    scanned_at: "2026-10-03T08:00:00+00:00", status: "ok", total: 1,
    secrets: [
      { rule: "aws-access-token", file: "config/app.env", line: 2, date: "2026-09-20T00:00:00Z",
        prefix: "AKIA", fingerprint: "f".repeat(64), length: 20,
        url: "https://github.com/dev2/deploy/blob/ccc/config/app.env#L2" },
    ],
  },
  disclosure: {
    policy: "https://github.com/dev2/deploy/security/policy",
    report: "https://github.com/dev2/deploy/security/advisories/new",
  },
};

test("shows redacted secrets, matching files and private disclosure links", async () => {
  renderApp(<CodeLeakCard match={MATCH} />);
  expect(await screen.findByRole("link", { name: "dev2/deploy" })).toHaveAttribute("href", "https://github.com/dev2/deploy");
  expect(screen.getByText("aws-access-token")).toBeInTheDocument();
  expect(screen.getByText("AKIA•••（20 个字符）")).toBeInTheDocument();
  expect(screen.getByText("ffffffffffff")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "config/app.env:2" })).toHaveAttribute("rel", "noopener noreferrer");
  expect(screen.getByText("HOST=intranet-gw01")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "通过 GitHub 私密报告漏洞" })).toHaveAttribute(
    "href", "https://github.com/dev2/deploy/security/advisories/new",
  );
});

test("shows pending scan", async () => {
  renderApp(<CodeLeakCard match={{ ...MATCH, scan: null }} />);
  expect(await screen.findByText("尚未完成密钥扫描")).toBeInTheDocument();
});

test("does not link unexpected hosts", () => {
  renderApp(<CodeLeakCard match={{ ...MATCH, hits: [{ ...MATCH.hits[0], html_url: "javascript:alert(1)" }] }} />);
  expect(screen.queryByRole("link", { name: "config/app.env" })).toBeNull();
});

const JUDGED = {
  ...MATCH,
  scan: {
    ...MATCH.scan, total: 2,
    secrets: [
      { ...MATCH.scan.secrets[0], context: ["# deploy", "AWS=AKIA…[REDACTED:1a2b3c4d]", "REGION=ap-east-1"] },
      { ...MATCH.scan.secrets[0], file: "tests/fixture.py", line: 1, fingerprint: "e".repeat(64),
        url: "https://github.com/dev2/deploy/blob/ccc/tests/fixture.py#L1" },
    ],
  },
  llm_code: {
    secrets: [{ fingerprint: "f".repeat(64), verdict: "real" }, { fingerprint: "e".repeat(64), verdict: "example" }],
    relation: "org", confidence: 0.82, rationale: "生产部署配置", summary: "部署脚本仓库",
    model: "m", prompt_version: "code-1", assessed_at: "2026-10-17T08:00:00Z",
  },
};

test("shows masked context, per-secret verdicts and repository relation", async () => {
  renderApp(<CodeLeakCard match={JUDGED} />);
  expect(await screen.findByText("大模型研判：本机构的仓库（置信度 82%）")).toBeInTheDocument();
  expect(screen.getByText(/部署脚本仓库/)).toBeInTheDocument();
  expect(screen.getByText("模型只判断看起来像不像真实配置，无法确认密钥是否仍然有效。")).toBeInTheDocument();
  expect(screen.getByText("像真实配置")).toBeInTheDocument();
  expect(screen.getByText("像示例或测试")).toBeInTheDocument();
  expect(screen.getByText(/AWS=AKIA…\[REDACTED:1a2b3c4d\]/)).toBeInTheDocument();
});

test("old results without context or verdicts still render", async () => {
  renderApp(<CodeLeakCard match={MATCH} />);
  expect(await screen.findByText("aws-access-token")).toBeInTheDocument();
  expect(screen.queryByText(/大模型研判/)).toBeNull();
  expect(screen.queryByText("像真实配置")).toBeNull();
  expect(screen.queryByRole("button", { name: /展开/ })).toBeNull();
});
