import { extraRows, fromForm, parseExtra, toForm } from "./ticketsForm";

const JIRA = { base_url: "https://acme.atlassian.net", email: "ti@acme.org", project_key: "SEC", issue_type: "Task",
  priority_map: { critical: "Highest" }, extra_fields: { labels: ["drp"], customfield_10050: { value: "Brand" }, team: "SOC" } };

test("附加字段的值先按 JSON 解析，失败按文本", () => {
  expect(parseExtra([
    { key: "labels", value: '["drp","brand"]' }, { key: "assignment_group", value: "Security Operations" },
    { key: "count", value: "3" }, { key: " ", value: "ignored" },
  ])).toEqual({ labels: ["drp", "brand"], assignment_group: "Security Operations", count: 3 });
  expect(extraRows(JIRA.extra_fields)).toEqual([
    { key: "labels", value: '["drp"]' }, { key: "customfield_10050", value: '{"value":"Brand"}' }, { key: "team", value: "SOC" },
  ]);
});

test("表单往返保留配置，并清理留空的映射", () => {
  const data = { enabled: true, mode: "jira", auto_push: [], id_field: "ticket_id", email_to: [], status_map: { resolved: "closed" },
    include_accounts: false, proxy: null, jira: JIRA, servicenow: null };
  const values = toForm(data);
  (values.jira as Record<string, unknown>).priority_map = { critical: "Highest", high: " ", low: undefined };
  expect(fromForm(values)).toEqual({ ...data, jira: { ...JIRA, priority_map: { critical: "Highest" } } });
});

test("没填地址的段存为 null；ServiceNow 只保留紧急度与影响都填了的级别", () => {
  const values = toForm({ mode: "servicenow", status_map: {}, jira: null, servicenow: null });
  values.servicenow = { base_url: "https://acme.service-now.com", table: "incident", auth: "oauth", username: "", client_id: "cid",
    urgency_impact_map: { critical: { urgency: 1, impact: 1 }, high: { urgency: 2 } } };
  values.proxy = "  ";
  const data = fromForm(values);
  expect(data.jira).toBeNull();
  expect(data.proxy).toBeNull();
  expect(data.servicenow).toEqual({ base_url: "https://acme.service-now.com", table: "incident", auth: "oauth", username: null,
    client_id: "cid", urgency_impact_map: { critical: { urgency: 1, impact: 1 } }, extra_fields: {} });
});

test("看起来像 JSON 的字符串保存后仍是字符串", () => {
  const fields = { customfield_10050: "10", flag: "true", none: "null", team: "SOC", count: 3 };
  const rows = extraRows(fields);
  expect(rows).toEqual([
    { key: "customfield_10050", value: '"10"' }, { key: "flag", value: '"true"' }, { key: "none", value: '"null"' },
    { key: "team", value: "SOC" }, { key: "count", value: "3" },
  ]);
  expect(parseExtra(rows)).toEqual(fields);
});
