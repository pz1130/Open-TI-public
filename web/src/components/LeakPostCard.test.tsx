import { screen } from "@testing-library/react";
import LeakPostCard from "./LeakPostCard";
import { renderApp } from "../test/render";

const MATCH = {
  post: {
    group: "akira", victim: "Acme Inc", domain: "acme.example", country: "US", activity: "Technology",
    discovered: "2026-10-02T08:00:00+00:00", published: null, sources: ["ransomware_live", "ransomlook"],
    links: ["https://www.ransomware.live/id/YWNtZQ"], other_links: ["hxxp://lockbitxyz[.]onion/post/1"],
    description: "Acme is a provider of cloud services.",
  },
  parties: [
    { kind: "vendor", id: "acme", name: "Acme Holdings Ltd", tier: "critical", owner: "IT 基础设施组", how: "domain", detail: "acme.example" },
  ],
  reasons: [{ reason: "critical_vendor" }],
};

test("显示受害者、团伙、匹配上的供应商与安全链接", async () => {
  renderApp(<LeakPostCard match={MATCH} />);
  expect(await screen.findByText("Acme Inc")).toBeInTheDocument();
  expect(screen.getByText("akira")).toBeInTheDocument();
  expect(screen.getByText("供应商 Acme Holdings Ltd（核心供应商）被列为受害者")).toBeInTheDocument();
  expect(screen.getByText("按域名匹配：acme.example · 负责团队：IT 基础设施组")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "https://www.ransomware.live/id/YWNtZQ" })).toHaveAttribute("rel", "noopener noreferrer");
  // 泄露站地址只作为文本，不可点击
  expect(screen.getByText("hxxp://lockbitxyz[.]onion/post/1").closest("a")).toBeNull();
});

test("本机构被列为受害者", async () => {
  renderApp(<LeakPostCard match={{ ...MATCH, parties: [{ ...MATCH.parties[0], kind: "self", name: "Example Organization", how: "name", detail: "example organization", owner: "" }] }} />);
  expect(await screen.findByText("本机构（Example Organization）被列为受害者")).toBeInTheDocument();
});

test("没有帖子数据时不显示", () => {
  renderApp(<LeakPostCard match={{}} />);
  expect(screen.queryByText("勒索泄露站帖子")).toBeNull();
});

test("拒绝把危险协议渲染为链接", () => {
  renderApp(<LeakPostCard match={{ ...MATCH, post: { ...MATCH.post, links: ["javascript:alert(1)", "https://user:pass@ransomware.live/post"] } }} />);
  expect(screen.queryByRole("link")).toBeNull();
});
