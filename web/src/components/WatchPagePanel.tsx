import { Alert, Button, Card, Descriptions, Empty, Image, Space, Tag, Typography } from "antd";
import { useTranslation } from "react-i18next";
import type { Schemas } from "../api/client";
import { evidenceUrl } from "../api/hooks";
import { fmtTime } from "./format";

type Inspection = Schemas["WatchInspectionOut"];
const COLOR: Record<string, string> = { website: "green", parking: "gold", phishing: "red", redirect: "blue", challenge: "orange" };

export function WatchPageTag({ verdict }: { verdict: string }) {
  const { t } = useTranslation();
  return <Tag color={COLOR[verdict] ?? "default"}>{t(`watchlist.pageKinds.${verdict}`, { defaultValue: verdict })}</Tag>;
}

export default function WatchPagePanel({ inspection, canView }: { inspection: Inspection | null | undefined; canView: boolean }) {
  const { t } = useTranslation();
  if (!inspection) return <Empty description={t("watchlist.pageNotChecked")} />;
  const screenshot = inspection.evidence?.find((e) => e.kind === "screenshot");
  const html = inspection.evidence?.find((e) => e.kind === "html");
  const redirects = inspection.redirects ?? [];
  const terms = inspection.brand_terms ?? [];
  return <Space direction="vertical" size="middle" style={{ width: "100%" }}>
    <Alert type="info" showIcon message={t("watchlist.pageReviewHint")} />
    {inspection.source !== "browser" && <Alert type="warning" showIcon message={t("watchlist.probeOnly")} />}
    <Card title={t("watchlist.pageContent")}>
      <Space wrap style={{ marginBottom: 12 }}><WatchPageTag verdict={inspection.verdict} /><Typography.Text type="secondary">{fmtTime(inspection.observed_at)}</Typography.Text></Space>
      <Descriptions column={1} size="small" items={[
        { key: "title", label: t("watchlist.pageTitle"), children: inspection.title || t("watchlist.noPageTitle") },
        { key: "status", label: t("watchlist.httpStatus"), children: inspection.status ?? "–" },
        { key: "url", label: t("watchlist.finalUrl"), children: inspection.final_url ? <Typography.Text copyable style={{ wordBreak: "break-all" }}>{inspection.final_url}</Typography.Text> : "–" },
        { key: "brand", label: t("watchlist.brandTerms"), children: terms.length ? terms.join(", ") : t("watchlist.noBrandTerms") },
      ]} />
      {redirects.length > 0 && <Space direction="vertical" style={{ marginTop: 12, width: "100%" }}>
        <Typography.Text type="secondary">{t("watchlist.redirectChain")}</Typography.Text>
        {[...redirects, ...(inspection.final_url && redirects.at(-1) !== inspection.final_url ? [inspection.final_url] : [])].map((url, index) => <Typography.Text key={`${index}-${url}`} style={{ wordBreak: "break-all" }}>{index + 1}. {url}</Typography.Text>)}
      </Space>}
      <Typography.Paragraph style={{ marginTop: 16, whiteSpace: "pre-wrap", overflowWrap: "anywhere" }} ellipsis={{ rows: 8, expandable: true }}>{inspection.text_excerpt || t("watchlist.noPageText")}</Typography.Paragraph>
    </Card>
    <Card title={t("watchlist.screenshot")}>
      {!canView ? <Typography.Text type="secondary">{t("detail.noScreenshotPerm")}</Typography.Text> : screenshot ? <Space direction="vertical" style={{ width: "100%" }}>
        <Image src={evidenceUrl(screenshot.id)} alt={t("watchlist.screenshot")} width="100%" />
        <Typography.Text type="secondary">{t("detail.capturedBy", { time: fmtTime(screenshot.captured_at), node: screenshot.node_id, method: screenshot.method })}</Typography.Text>
        {html && <Button href={evidenceUrl(html.id)}>{t("detail.downloadText")}</Button>}
      </Space> : <Alert type="warning" showIcon message={t(`watchlist.captureStatuses.${inspection.capture_status}`, { defaultValue: t("watchlist.captureStatuses.failed") })} />}
    </Card>
  </Space>;
}
