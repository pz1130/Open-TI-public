import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { useState } from "react";
import KeywordScanPanel, { publicTextTerms } from "./KeywordScanPanel";
import { renderApp } from "../test/render";
import { server } from "../test/server";

const RESULT = { scan: { project_id: "sbr", rules_version: 3, scope: "domain", term: "newbrand" }, connectors: {
  crtsh: { name: "crt.sh", status: "queued" }, dnstwist: { name: "dnstwist", status: "too_soon", next_allowed_at: "2026-10-16T08:00:00Z" }, urlscan: { name: "urlscan", status: "unavailable", reason: "unconfigured：缺少凭据" },
} };

test("只使用已保存的新词和版本，逐一显示数据源安排结果", async () => {
  let body: unknown;
  server.use(http.post("*/api/v1/rules/scan", async ({ request }) => { body = await request.json(); return HttpResponse.json(RESULT, { status: 202 }); }));
  renderApp(<KeywordScanPanel version={3} domainTerms={["oldbrand", "newbrand"]} />);
  await userEvent.setup().click(screen.getByRole("button", { name: "立即扫描" }));
  expect(await screen.findByText("已排队")).toBeInTheDocument();
  expect(screen.getByText("未到最小间隔")).toBeInTheDocument();
  expect(screen.getByText("unconfigured：缺少凭据")).toBeInTheDocument();
  expect(body).toEqual({ scope: "domain", term: "newbrand", base_version: 3 });
});

test("配置页能选择文本或域名词，新保存的词会自动选中", async () => {
  const bodies: unknown[] = [];
  server.use(http.post("*/api/v1/rules/scan", async ({ request }) => { bodies.push(await request.json()); return HttpResponse.json(RESULT, { status: 202 }); }));
  function Editor() {
    const [saved, setSaved] = useState(false);
    return <><button onClick={() => setSaved(true)}>模拟保存新词</button><KeywordScanPanel version={saved ? 4 : 3} textTerms={saved ? ["Old Phrase", "New Phrase"] : ["Old Phrase"]} domainTerms={["domainbrand"]} /></>;
  }
  renderApp(<Editor />);
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: "模拟保存新词" }));
  await user.click(screen.getByRole("button", { name: "立即扫描" }));
  await waitFor(() => expect(bodies).toHaveLength(1));
  expect(bodies[0]).toEqual({ scope: "text", term: "New Phrase", base_version: 4 });
  await user.click(screen.getByRole("radio", { name: "域名关键词" }));
  await user.click(screen.getByRole("button", { name: "立即扫描" }));
  await waitFor(() => expect(bodies).toHaveLength(2));
  expect(bodies[1]).toEqual({ scope: "domain", term: "domainbrand", base_version: 4 });
});

test("不提供人员、私有、禁止外发或非短语词；无可用词时禁用扫描", () => {
  const eligible = { value: "Public Phrase", mode: "phrase", remote_search: true };
  const data = { sets: {
    brand: { role: "match", type: "brand", terms: [eligible, { ...eligible, value: "Disabled", remote_search: false }, { ...eligible, value: "SBR", mode: "token" }] },
    person: { role: "match", type: "executive", terms: [eligible] },
    private: { role: "match", private: true, terms: [{ ...eligible, value: "Private Phrase" }] },
  } };
  expect(publicTextTerms(data)).toEqual(["Public Phrase"]);
  renderApp(<KeywordScanPanel version={0} textTerms={[]} domainTerms={[]} />);
  expect(screen.getByRole("button", { name: "立即扫描" })).toBeDisabled();
});

test("过期版本显示错误，不自动重复提交", async () => {
  let calls = 0;
  server.use(http.post("*/api/v1/rules/scan", () => { calls++; return HttpResponse.json({ detail: { message: "规则已变化，请刷新" } }, { status: 409 }); }));
  renderApp(<KeywordScanPanel version={1} domainTerms={["brand"]} />);
  await userEvent.setup().click(screen.getByRole("button", { name: "立即扫描" }));
  expect(await screen.findByText(/规则已变化，请刷新/)).toBeInTheDocument();
  expect(calls).toBe(1);
});
