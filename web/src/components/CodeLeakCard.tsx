import { listPagination } from "./pagination";
import { Alert, Card, Descriptions, List, Space, Table, Tag, Typography } from "antd";
import { useTranslation } from "react-i18next";
import { fmtTime } from "./format";

interface Hit {
  path: string;
  html_url: string;
  term_kind: string;
  fork: boolean;
  fragments: string[];
}

interface Secret {
  rule: string;
  file: string;
  line: number;
  date: string | null;
  prefix: string;
  fingerprint?: string;
  length: number;
  url: string;
  context?: string[];
}

interface CodeVerdict {
  secrets: { fingerprint: string; verdict: string }[];
  relation: string;
  confidence: number;
  rationale: string;
  summary: string;
}

const VERDICT_COLOR: Record<string, string> = { real: "red", example: "default", unsure: "gold" };

interface Scan {
  scanned_at: string;
  status: string;
  total: number;
  secrets: Secret[];
}

const EXTERNAL = { target: "_blank", rel: "noopener noreferrer" } as const;

function githubLink(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "https:" && url.hostname === "github.com" && !url.username && !url.password;
  } catch {
    return false;
  }
}

/** Public-code evidence only. Raw credential values never enter this component. */
export default function CodeLeakCard({ match }: { match: Record<string, unknown> }) {
  const { t } = useTranslation();
  const repo = match.repo as string | undefined;
  if (!repo) return null;
  const hits = (match.hits as Hit[] | undefined) ?? [];
  const scan = (match.scan as Scan | null | undefined) ?? null;
  const disclosure = (match.disclosure as { policy: string; report: string } | undefined) ?? null;
  const llm = (match.llm_code as CodeVerdict | undefined) ?? null;
  const verdicts = new Map((llm?.secrets ?? []).map((s) => [s.fingerprint, s.verdict]));
  return (
    <Card title={t("code.title")} extra={<a href={`https://github.com/${repo}`} {...EXTERNAL}>{repo}</a>}>
      <Space direction="vertical" style={{ width: "100%" }}>
        <Alert type="info" showIcon message={t("code.policy")} />
        {llm && (
          <Alert
            type={llm.relation === "unrelated" ? "warning" : "info"}
            showIcon
            message={t("code.llm", {
              relation: t(`code.relation.${llm.relation}`, { defaultValue: llm.relation }),
              confidence: Math.round((llm.confidence ?? 0) * 100),
            })}
            description={
              <Space direction="vertical" size={0}>
                {[llm.summary, llm.rationale].filter(Boolean).join(" — ") || null}
                <Typography.Text type="secondary">{t("code.llmLimit")}</Typography.Text>
              </Space>
            }
          />
        )}
        {scan ? (
          <Descriptions
            size="small"
            column={{ xs: 1, md: 3 }}
            items={[
              { key: "at", label: t("code.scannedAt"), children: fmtTime(scan.scanned_at) },
              { key: "status", label: t("code.status"), children: scan.status },
              { key: "total", label: t("code.secretCount"), children: scan.total },
            ]}
          />
        ) : <Typography.Text type="secondary">{t("code.notScanned")}</Typography.Text>}
        {scan && scan.secrets.length > 0 && (
          <Table<Secret>
            rowKey={(secret) => `${secret.fingerprint ?? ""}:${secret.file}:${secret.line}:${secret.rule}`}
            size="small"
            pagination={listPagination}
            dataSource={scan.secrets}
            expandable={{
              defaultExpandAllRows: true,
              rowExpandable: (secret) => (secret.context?.length ?? 0) > 0,
              expandedRowRender: (secret) => (
                <pre className="opti-mono" style={{ margin: 0, whiteSpace: "pre-wrap" }}>{(secret.context ?? []).join("\n")}</pre>
              ),
            }}
            columns={[
              { title: t("code.rule"), dataIndex: "rule", render: (value: string) => <Tag color="red">{value}</Tag> },
              { title: t("code.location"), key: "location", render: (_: unknown, secret) =>
                githubLink(secret.url) ? <a href={secret.url} {...EXTERNAL}>{`${secret.file}:${secret.line}`}</a>
                  : `${secret.file}:${secret.line}` },
              { title: t("code.value"), key: "value", render: (_: unknown, secret) =>
                t("code.masked", { prefix: secret.prefix, n: secret.length }) },
              { title: t("code.hash"), dataIndex: "fingerprint", render: (value: string | undefined) =>
                <Typography.Text className="opti-mono">{value ? value.slice(0, 12) : "-"}</Typography.Text> },
              { title: t("code.date"), dataIndex: "date", render: (value: string | null) => value ? fmtTime(value) : "-" },
              ...(llm ? [{ title: t("code.verdictCol"), key: "verdict", render: (_: unknown, secret: Secret) => {
                const verdict = secret.fingerprint ? verdicts.get(secret.fingerprint) : undefined;
                return verdict ? <Tag color={VERDICT_COLOR[verdict]}>{t(`code.secretVerdict.${verdict}`, { defaultValue: verdict })}</Tag> : "-";
              } }] : []),
            ]}
          />
        )}
        <List pagination={listPagination}
          header={t("code.hits", { n: hits.length })}
          size="small"
          dataSource={hits}
          renderItem={(hit) => (
            <List.Item>
              <Space direction="vertical" style={{ width: "100%" }}>
                <Space wrap>
                  {githubLink(hit.html_url) ? <a href={hit.html_url} {...EXTERNAL}>{hit.path}</a> : hit.path}
                  <Tag>{t(`code.termKind.${hit.term_kind}`, { defaultValue: hit.term_kind })}</Tag>
                  {hit.fork && <Tag>{t("code.fork")}</Tag>}
                </Space>
                {hit.fragments.map((fragment, index) => (
                  <Typography.Text key={index} className="opti-mono" type="secondary">{fragment}</Typography.Text>
                ))}
              </Space>
            </List.Item>
          )}
        />
        {disclosure && <Space wrap>
          {githubLink(disclosure.policy) && <a href={disclosure.policy} {...EXTERNAL}>{t("code.disclosurePolicy")}</a>}
          {githubLink(disclosure.report) && <a href={disclosure.report} {...EXTERNAL}>{t("code.disclosureReport")}</a>}
        </Space>}
      </Space>
    </Card>
  );
}
