import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import DocumentCard from "./DocumentCard";
import { renderApp } from "../test/render";
import { server } from "../test/server";

const MATCH = {
  kind: "fraud",
  document: {
    id: 3, url: "https://scam.example/1", title: "Cheap loans",
    source_name: "Example News", language: "en", published_at: null,
  },
  documents: [
    {
      id: 3, url: "https://scam.example/1", title: "Cheap loans",
      source_name: "Example News", language: "en", published_at: null,
    },
    {
      id: 4, url: "https://mirror.example/x", title: "Cheap loans (mirror)",
      source_name: "Mirror", language: "en", published_at: null,
    },
  ],
  terms: ["Sample Brand"],
  boosters: ["loan offer", "processing fee"],
  contexts: ["Fake Sample Brand loan offer asks for a processing fee"],
  reprints: 2,
};

test("显示文档、命中词、增强词与转载", async () => {
  renderApp(<DocumentCard match={MATCH} />);
  expect(await screen.findByRole("link", { name: "Cheap loans (mirror)" }))
    .toHaveAttribute("href", "https://mirror.example/x");
  expect(screen.getByText("Sample Brand")).toBeInTheDocument();
  expect(screen.getByText("processing fee")).toBeInTheDocument();
  expect(screen.getByText("共 2 篇相同或转载的文章")).toBeInTheDocument();
  expect(screen.getByText("Fake Sample Brand loan offer asks for a processing fee"))
    .toBeInTheDocument();
});

test("显示大模型研判结论", async () => {
  renderApp(<DocumentCard match={{ ...MATCH, llm: { verdict: "no", confidence: 0.92, summary: "斯里兰卡银行季度利润", rationale: "Different bank." } }} />);
  expect(await screen.findByText("大模型研判：不是本机构（置信度 92%）")).toBeInTheDocument();
  expect(screen.getByText("斯里兰卡银行季度利润 — Different bank.")).toBeInTheDocument();
});

test("分析员可按需查看本地译文，原文仍保留", async () => {
  let request: unknown;
  server.use(http.post("*/api/v1/alerts/7/translation", async ({ request: incoming }) => {
    request = await incoming.json();
    return HttpResponse.json({
      source_language: "en", target_language: "zh", title: "优惠贷款",
      contexts: ["冒用样本品牌的贷款广告收取手续费"],
    });
  }));
  const user = userEvent.setup();
  renderApp(<DocumentCard match={MATCH} alertId={7} translationAvailable />);
  await user.click(screen.getByRole("button", { name: "译为中文" }));
  expect(await screen.findByText("优惠贷款")).toBeInTheDocument();
  expect(screen.getByText("冒用样本品牌的贷款广告收取手续费")).toBeInTheDocument();
  expect(screen.getByText("译文仅供阅读，请对照上方原文核查；译文不会保存。")).toBeInTheDocument();
  expect(screen.getByText("Fake Sample Brand loan offer asks for a processing fee"))
    .toBeInTheDocument();
  expect(request).toEqual({ target_language: "zh" });
});

test("未启用翻译时不展示入口", () => {
  renderApp(<DocumentCard match={MATCH} alertId={7} />);
  expect(screen.queryByRole("button", { name: "译为中文" })).toBeNull();
});
