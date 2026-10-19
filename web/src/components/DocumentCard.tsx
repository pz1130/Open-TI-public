import { listPagination } from "./pagination";
import { Alert, Button, Card, List, Space, Tag, Typography } from "antd";
import { useMutation } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { api, errorMessage, unwrap } from "../api/client";
import { fmtTime } from "./format";

interface DocBrief {
  id: number;
  url: string | null;
  title: string;
  source_name: string;
  language: string | null;
  published_at: string | null;
}

/** Shows only stored title and excerpts; full article text is not retained. */
export default function DocumentCard({ match, alertId, translationAvailable = false }: {
  match: Record<string, unknown>; alertId?: number; translationAvailable?: boolean;
}) {
  const { t, i18n } = useTranslation();
  const docs = (match.documents as DocBrief[] | undefined) ?? [];
  const target = i18n.language.startsWith("zh") ? "zh" : "en";
  const source = (match.document as DocBrief | undefined)?.language?.split("-")[0]?.toLowerCase();
  const translation = useMutation({
    mutationFn: async () => unwrap(await api.POST("/api/v1/alerts/{alert_id}/translation", {
      params: { path: { alert_id: alertId! } }, body: { target_language: target },
    })),
  });
  if (!match.document) return null;
  const terms = (match.terms as string[] | undefined) ?? [];
  const boosters = (match.boosters as string[] | undefined) ?? [];
  const contexts = (match.contexts as string[] | undefined) ?? [];
  const llm = match.llm as { verdict: string; confidence?: number; summary?: string; rationale?: string } | undefined;
  return (
    <Card title={t("doc.title")}>
      <Space direction="vertical" style={{ width: "100%" }}>
        <Space wrap>
          {terms.map((term) => <Tag key={term} color="blue">{term}</Tag>)}
          {boosters.map((term) => <Tag key={term} color="red">{term}</Tag>)}
        </Space>
        {contexts.map((context) => (
          <Typography.Text key={context} type="secondary">{context}</Typography.Text>
        ))}
        {translationAvailable && alertId && source && source !== target && (
          <Button loading={translation.isPending} onClick={() => translation.mutate()}>
            {t(target === "zh" ? "doc.translateToZh" : "doc.translateToEn")}
          </Button>
        )}
        {translation.isError && <Alert type="error" showIcon message={errorMessage(translation.error)} />}
        {translation.data && (
          <Card size="small" title={t("doc.translationTitle")}>
            <Space direction="vertical">
              <Typography.Text type="secondary">{t("doc.translationReview")}</Typography.Text>
              {translation.data.title && <Typography.Text strong>{translation.data.title}</Typography.Text>}
              {translation.data.contexts.map((context, index) => (
                <Typography.Text key={index}>{context}</Typography.Text>
              ))}
            </Space>
          </Card>
        )}
        {llm && (
          <Alert
            type={llm.verdict === "no" ? "warning" : "info"}
            showIcon
            message={t("doc.llm", {
              verdict: t(`doc.verdict.${llm.verdict}`, { defaultValue: llm.verdict }),
              confidence: Math.round((llm.confidence ?? 0) * 100),
            })}
            description={[llm.summary, llm.rationale].filter(Boolean).join(" — ") || undefined}
          />
        )}
        <List pagination={listPagination}
          size="small"
          header={t("doc.reprints", { n: Number(match.reprints ?? docs.length) })}
          dataSource={docs}
          renderItem={(document) => (
            <List.Item key={document.id}>
              <Space wrap>
                {document.url ? (
                  <a href={document.url} target="_blank" rel="noopener noreferrer">
                    {document.title || document.url}
                  </a>
                ) : (
                  <span>{document.title}</span>
                )}
                <Typography.Text type="secondary">
                  {[document.source_name, document.published_at ? fmtTime(document.published_at) : null]
                    .filter(Boolean).join(" · ")}
                </Typography.Text>
              </Space>
            </List.Item>
          )}
        />
      </Space>
    </Card>
  );
}
