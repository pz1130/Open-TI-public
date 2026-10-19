import { secretName, slugify } from "./alertingForm";

test("渠道 ID 由名称生成，中文名称退回到备用 ID", () => {
  expect(slugify("Security On-Call!", "teams-1")).toBe("security-on-call");
  expect(slugify("安全值班", "teams-1")).toBe("teams-1");
  expect(slugify("a".repeat(40), "x")).toHaveLength(32);
  expect(secretName("secops")).toBe("channel:secops:webhook_url");
});
