import { listPagination } from "../components/pagination";
import { Alert, Button, Card, Col, Form, Input, List, Row, Space, Table, Tag, Typography } from "antd";
import { useTranslation } from "react-i18next";
import { errorMessage, type Schemas } from "../api/client";
import { useRulesTest } from "../api/hooks";
import HighlightedContext from "../components/HighlightedContext";
import { SeverityTag } from "../components/tags";

interface Values {
  domains?: string;
  text?: string;
  draft?: string;
}

type DomainRow = Schemas["DomainReportOut"];

export default function SandboxPage() {
  const { t } = useTranslation();
  const run = useRulesTest();
  const onFinish = (v: Values) =>
    run.mutate({
      domains: (v.domains ?? "").split("\n").map((d) => d.trim()).filter(Boolean),
      text: v.text ?? "",
      draft_yaml: v.draft?.trim() ? v.draft : null,
    });
  const result = run.data;
  return (
    <Space direction="vertical" size="large" style={{ width: "100%" }}>
      <Card title={t("sandbox.title")}>
        <Form name="sandbox" layout="vertical" onFinish={onFinish}>
          <Row gutter={16}>
            <Col xs={24} md={12}>
              <Form.Item name="domains" label={t("sandbox.domains")}>
                <Input.TextArea rows={6} className="opti-mono" />
              </Form.Item>
              <Form.Item name="text" label={t("sandbox.text")}>
                <Input.TextArea rows={6} maxLength={50_000} />
              </Form.Item>
            </Col>
            <Col xs={24} md={12}>
              <Form.Item name="draft" label={t("sandbox.draft")} extra={t("sandbox.draftHint")}>
                <Input.TextArea rows={14} className="opti-mono" maxLength={200_000} />
              </Form.Item>
            </Col>
          </Row>
          <Button type="primary" htmlType="submit" loading={run.isPending}>{t("sandbox.run")}</Button>
        </Form>
      </Card>
      {run.isError && <Alert type="error" showIcon message={errorMessage(run.error)} />}
      {result && (
        <Card
          title={
            <Space>
              {t("sandbox.usedRules")}
              <Tag color={result.source === "draft" ? "purple" : "blue"}>
                {result.source === "draft" ? t("sandbox.draftRules") : t("sandbox.current")}
              </Tag>
            </Space>
          }
        >
          <Typography.Title level={5}>{t("sandbox.domainResults")}</Typography.Title>
          <Table<DomainRow>
            rowKey="input"
            size="small"
            pagination={listPagination}
            dataSource={result.domains}
            columns={[
              { dataIndex: "input", render: (v: string) => <Typography.Text className="opti-mono">{v}</Typography.Text> },
              { dataIndex: "status", render: (v: string) => t(`sandbox.status.${v}`, { defaultValue: v }) },
              {
                key: "score",
                title: t("sandbox.offlineScore"),
                render: (_: unknown, r: DomainRow) =>
                  r.score ? (
                    <Space>
                      {String(r.score.value)}
                      <SeverityTag value={String(r.score.severity)} />
                    </Space>
                  ) : null,
              },
              {
                key: "reasons",
                render: (_: unknown, r: DomainRow) =>
                  (r.reasons ?? []).map((x, i) => {
                    const code = String((x as { reason?: unknown }).reason ?? "");
                    return <Tag key={`${code}-${i}`}>{t(`reason.${code}`, { defaultValue: code })}</Tag>;
                  }),
              },
            ]}
          />
          <Typography.Title level={5} style={{ marginTop: 24 }}>{t("sandbox.textHits")}</Typography.Title>
          <List pagination={listPagination}
            locale={{ emptyText: t("sandbox.noHits") }}
            dataSource={result.text_hits}
            renderItem={(h) => (
              <List.Item>
                <Space direction="vertical" size={0}>
                  <Space>
                    <Tag>{t(`sandbox.role.${h.role}`, { defaultValue: h.role })}</Tag>
                    <strong>{h.term}</strong>
                    <Typography.Text type="secondary">{h.set_name}</Typography.Text>
                  </Space>
                  <HighlightedContext context={h.context} term={h.term} />
                </Space>
              </List.Item>
            )}
          />
        </Card>
      )}
    </Space>
  );
}
