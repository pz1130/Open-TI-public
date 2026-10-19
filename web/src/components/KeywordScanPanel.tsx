import { useMutation } from "@tanstack/react-query";
import { Button, Card, Radio, Select, Space, Table, Tag, Typography } from "antd";
import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { api, unwrap } from "../api/client";
import { fmtTime } from "./format";
import { listPagination } from "./pagination";
import QueryError from "./QueryError";

type Scope = "text" | "domain";

/** Choices come from the saved response, never from the form's unsaved draft. */
export function publicTextTerms(data: Record<string, unknown>): string[] {
  const sets = (data.sets ?? {}) as Record<string, { role?: string; type?: string; private?: boolean; terms?: { value: string; mode?: string; remote_search?: boolean }[] }>;
  return [...new Set(Object.values(sets).filter((set) => set.role === "match" && set.type !== "executive" && !set.private)
    .flatMap((set) => (set.terms ?? []).filter((term) => term.mode === "phrase" && term.remote_search).map((term) => term.value)))];
}

export default function KeywordScanPanel({ version, domainTerms, textTerms }: { version: number; domainTerms: string[]; textTerms?: string[] }) {
  const { t } = useTranslation();
  const [scope, setScope] = useState<Scope>(textTerms ? "text" : "domain");
  const [selected, setSelected] = useState<Partial<Record<Scope, string>>>({});
  const terms = [...new Set(scope === "text" ? textTerms ?? [] : domainTerms)];
  const termsKey = JSON.stringify(terms);
  const previous = useRef<Record<Scope, string[]>>({ text: textTerms ?? [], domain: domainTerms });
  useEffect(() => {
    const current = JSON.parse(termsKey) as string[];
    const added = current.filter((term) => !previous.current[scope].includes(term));
    previous.current[scope] = current;
    if (added.length) setSelected((prior) => ({ ...prior, [scope]: added.at(-1)! }));
  }, [scope, termsKey]);
  const choice = selected[scope];
  const value = choice === "" || (choice !== undefined && terms.includes(choice)) ? choice : terms.at(-1) ?? "";
  const scan = useMutation({
    retry: false,
    mutationFn: async () => unwrap(await api.POST("/api/v1/rules/scan", { body: { scope, term: value || null, base_version: version } })),
  });
  const results = Object.entries(scan.data?.connectors ?? {}).map(([id, result]) => ({ id, ...result }));
  return <Card size="small" title={t("keywordScan.title")} extra={<Tag>{t("keywordScan.version", { version })}</Tag>} data-testid="keyword-scan-panel">
    <Space direction="vertical" style={{ width: "100%" }}>
      <Typography.Paragraph type="secondary" style={{ marginBottom: 0 }}>{t("keywordScan.description")}</Typography.Paragraph>
      <Space wrap>
        {textTerms && <Radio.Group aria-label={t("keywordScan.scope")} value={scope} disabled={scan.isPending} onChange={(e) => { setScope(e.target.value as Scope); scan.reset(); }} options={[{ value: "text", label: t("keywordScan.text") }, { value: "domain", label: t("keywordScan.domain") }]} />}
        <Select aria-label={t("keywordScan.term")} style={{ minWidth: 220, maxWidth: "100%" }} value={value} disabled={scan.isPending} onChange={(term) => { setSelected({ ...selected, [scope]: term }); scan.reset(); }} options={[{ value: "", label: t("keywordScan.all") }, ...terms.map((term) => ({ value: term, label: term }))]} />
        <Button type="primary" loading={scan.isPending} disabled={!terms.length} onClick={() => scan.mutate()}>{t("keywordScan.run")}</Button>
      </Space>
      {!terms.length && <Typography.Text type="secondary">{t(scope === "text" ? "keywordScan.noText" : "keywordScan.noDomain")}</Typography.Text>}
      <QueryError error={scan.error} />
      {scan.data && <>
        <Typography.Text>{t("keywordScan.accepted", { project: scan.data.scan.project_id, version: scan.data.scan.rules_version, term: scan.data.scan.term ?? t("keywordScan.all") })}</Typography.Text>
        <Table size="small" rowKey="id" pagination={listPagination} dataSource={results} columns={[
          { title: t("keywordScan.source"), dataIndex: "name" },
          { title: t("keywordScan.status"), render: (_, row) => <Tag color={row.status === "queued" ? "processing" : row.status === "unavailable" ? "warning" : "default"}>{t(`keywordScan.states.${row.status}`)}</Tag> },
          { title: t("keywordScan.detail"), render: (_, row) => row.reason || (row.next_allowed_at ? t("keywordScan.next", { time: fmtTime(row.next_allowed_at) }) : "—") },
        ]} />
        <Typography.Text type="secondary">{t("keywordScan.results")}</Typography.Text>
      </>}
    </Space>
  </Card>;
}
