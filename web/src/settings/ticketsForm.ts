// 工单配置 ⇄ 表单值。附加字段在表单里是 {key, value} 行，值先按 JSON 解析，失败按文本。
type Json = Record<string, unknown>;
export type ExtraRow = { key: string; value: string };
type StatusRow = { status: string; state: string };

export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
export const REMOTE_MODES = ["jira", "servicenow"];

function parsesAsJson(text: string): boolean {
  try {
    JSON.parse(text);
    return true;
  } catch {
    return false;
  }
}

export function extraRows(fields: unknown): ExtraRow[] {
  return Object.entries((fields ?? {}) as Json).map(([key, value]) => ({
    key,
    // "10"、"true" 这类字符串若原样显示，保存时会被 JSON 解析成数字 / 布尔
    value: typeof value === "string" && !parsesAsJson(value) ? value : JSON.stringify(value),
  }));
}

export function parseExtra(rows: ExtraRow[] | undefined): Json {
  const out: Json = {};
  for (const row of rows ?? []) {
    const key = row.key?.trim();
    if (!key) continue;
    try {
      out[key] = JSON.parse(row.value);
    } catch {
      out[key] = row.value;
    }
  }
  return out;
}

function blank(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function filled(section: unknown): section is Json {
  return !!section && typeof (section as Json).base_url === "string" && !!((section as Json).base_url as string).trim();
}

export function toForm(data: Json): Json {
  const jira = data.jira as Json | null | undefined;
  const servicenow = data.servicenow as Json | null | undefined;
  return {
    ...data,
    status_map: Object.entries((data.status_map ?? {}) as Record<string, string>).map(([status, state]) => ({ status, state })),
    jira: jira ?? { issue_type: "Task", priority_map: {} },
    servicenow: servicenow ?? { table: "incident", auth: "basic", urgency_impact_map: {} },
    jira_extra: extraRows(jira?.extra_fields),
    servicenow_extra: extraRows(servicenow?.extra_fields),
  };
}

export function fromForm(values: Json): Json {
  const { status_map, jira, servicenow, jira_extra, servicenow_extra, proxy, ...rest } = values;
  const data: Json = {
    ...rest,
    proxy: blank(proxy),
    status_map: Object.fromEntries(((status_map ?? []) as StatusRow[]).map((row) => [row.status.trim(), row.state])),
    jira: null,
    servicenow: null,
  };
  if (filled(jira)) {
    const priorities = Object.entries((jira.priority_map ?? {}) as Record<string, string | undefined>)
      .filter(([, name]) => !!name?.trim()).map(([severity, name]) => [severity, name!.trim()]);
    data.jira = { ...jira, priority_map: Object.fromEntries(priorities), extra_fields: parseExtra(jira_extra as ExtraRow[]) };
  }
  if (filled(servicenow)) {
    const levels = Object.entries((servicenow.urgency_impact_map ?? {}) as Record<string, { urgency?: number; impact?: number } | undefined>)
      .filter(([, level]) => level?.urgency != null && level?.impact != null);
    data.servicenow = {
      ...servicenow,
      username: blank(servicenow.username),
      client_id: blank(servicenow.client_id),
      urgency_impact_map: Object.fromEntries(levels),
      extra_fields: parseExtra(servicenow_extra as ExtraRow[]),
    };
  }
  return data;
}
