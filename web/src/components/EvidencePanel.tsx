import { listPagination } from "./pagination";
import { UploadOutlined } from "@ant-design/icons";
import { Alert, Button, Card, Empty, Image, List, Space, Typography, Upload } from "antd";
import { useTranslation } from "react-i18next";
import { errorMessage, type Schemas } from "../api/client";
import { evidenceUrl, useUploadEvidence } from "../api/hooks";
import { fmtTime } from "./format";

type Evidence = Schemas["EvidenceOut"];

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function logoMatches(enrichment: Record<string, unknown>): { reference: string; distance: number }[] {
  const screenshot = enrichment.screenshot;
  const data = isObject(screenshot) ? screenshot.data : null;
  const visual = isObject(data) ? data.visual : null;
  const matches = isObject(visual) ? visual.possible_matches : null;
  if (!Array.isArray(matches)) return [];
  return matches.filter(
    (match): match is { reference: string; distance: number } =>
      isObject(match) && typeof match.reference === "string" &&
      typeof match.distance === "number" && Number.isInteger(match.distance) &&
      match.distance >= 0 && match.distance <= 64,
  ).slice(0, 3);
}

function faviconHint(enrichment: Record<string, unknown>): { hash: number; matches: string[] } | null {
  const screenshot = enrichment.screenshot;
  const data = isObject(screenshot) ? screenshot.data : null;
  const favicon = isObject(data) ? data.favicon : null;
  if (!isObject(favicon) || typeof favicon.hash !== "number" ||
    !Number.isInteger(favicon.hash) || favicon.hash < -2147483648 || favicon.hash > 2147483647) return null;
  const names = Array.isArray(favicon.reference_matches) ? favicon.reference_matches : [];
  return {
    hash: favicon.hash,
    matches: names.filter((name): name is string => typeof name === "string" && name.length > 0).slice(0, 3),
  };
}

function ocrTerms(enrichment: Record<string, unknown>): string[] {
  const screenshot = enrichment.screenshot;
  const data = isObject(screenshot) ? screenshot.data : null;
  const ocr = isObject(data) ? data.ocr : null;
  const terms = isObject(ocr) ? ocr.brand_terms : null;
  return Array.isArray(terms)
    ? terms.filter((term): term is string => typeof term === "string" && term.length > 0).slice(0, 12)
    : [];
}

export default function EvidencePanel({ evidence, canView, enrichment, alertId, canUpload = false, platform = false }: {
  evidence: Evidence[]; canView: boolean; enrichment: Record<string, unknown>;
  alertId?: number; canUpload?: boolean; platform?: boolean;
}) {
  const { t } = useTranslation();
  const upload = useUploadEvidence(alertId ?? 0);
  const matches = canView ? logoMatches(enrichment) : [];
  const favicon = canView ? faviconHint(enrichment) : null;
  const terms = canView ? ocrTerms(enrichment) : [];
  const caption = (e: Evidence) =>
    t("detail.capturedBy", { time: fmtTime(e.captured_at), node: e.node_id, method: e.method });
  return (
    <Card
      title={t("detail.evidence")}
      extra={canUpload && alertId !== undefined && (
        <span data-testid="evidence-upload">
          <Upload
            accept="image/png,image/jpeg,image/webp"
            showUploadList={false}
            customRequest={({ file, onSuccess, onError }) =>
              upload.mutateAsync(file as File).then(onSuccess, (e: unknown) => onError?.(e as Error))
            }
          >
            <Button icon={<UploadOutlined />} loading={upload.isPending}>{t("detail.uploadScreenshot")}</Button>
          </Upload>
        </span>
      )}
    >
      {upload.error && <Alert type="error" showIcon style={{ marginBottom: 16 }} message={errorMessage(upload.error)} />}
      {platform && canUpload && evidence.length === 0 && (
        <Alert type="warning" showIcon style={{ marginBottom: 16 }} message={t("detail.platformNeedsUpload")} />
      )}
      {matches.length > 0 && (
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 16 }}
          message={t("detail.logoPossible")}
          description={
            <Space direction="vertical" size={0}>
              {matches.map((m, i) => (
                <Typography.Text key={`${m.reference}-${i}`}>
                  {t("detail.logoMatch", { name: m.reference, distance: m.distance })}
                </Typography.Text>
              ))}
              <Typography.Text type="secondary">{t("detail.logoReview")}</Typography.Text>
            </Space>
          }
        />
      )}
      {favicon && (
        <Alert
          type={favicon.matches.length ? "warning" : "info"}
          showIcon
          style={{ marginBottom: 16 }}
          message={t(favicon.matches.length ? "detail.faviconReference" : "detail.faviconFingerprint")}
          description={
            <Space direction="vertical" size={0}>
              <Typography.Text className="opti-mono">{t("detail.faviconHash", { hash: favicon.hash })}</Typography.Text>
              {favicon.matches.length > 0 && (
                <Typography.Text>{t("detail.faviconNames", { names: favicon.matches.join(", ") })}</Typography.Text>
              )}
              <Typography.Text type="secondary">{t("detail.faviconReview")}</Typography.Text>
            </Space>
          }
        />
      )}
      {terms.length > 0 && (
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 16 }}
          message={t("detail.ocrMatches")}
          description={
            <Space direction="vertical" size={0}>
              <Typography.Text>{terms.join(", ")}</Typography.Text>
              <Typography.Text type="secondary">{t("detail.ocrReview")}</Typography.Text>
            </Space>
          }
        />
      )}
      {evidence.length === 0 ? (
        <Empty description={t("detail.noEvidence")} />
      ) : !canView ? (
        <Typography.Text type="secondary">{t("detail.noScreenshotPerm")}</Typography.Text>
      ) : (
        <List pagination={listPagination}
          dataSource={evidence}
          renderItem={(e) => (
            <List.Item key={e.id}>
              <Space direction="vertical" style={{ width: "100%" }}>
                {e.content_type === "image/png" ? (
                  <Image src={evidenceUrl(e.id)} alt={t("detail.screenshot")} width={480} />
                ) : (
                  <Button href={evidenceUrl(e.id)}>{t("detail.downloadText")}</Button>
                )}
                <Typography.Text type="secondary">
                  {e.kind === "upload"
                    ? t("detail.uploadedBy", { user: e.uploaded_by ?? "-", time: fmtTime(e.captured_at) })
                    : `${e.kind === "screenshot" ? t("detail.screenshot") : t("detail.html")} · ${caption(e)}`}
                </Typography.Text>
                <Typography.Text className="opti-mono" copyable>
                  {e.sha256}
                </Typography.Text>
                {e.original_sha256 && <Typography.Text type="secondary" className="opti-mono">{t("detail.originalSha", { sha: e.original_sha256 })}</Typography.Text>}
              </Space>
            </List.Item>
          )}
        />
      )}
    </Card>
  );
}
