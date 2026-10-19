import { App, Button, Card, Form, Input, InputNumber, Radio } from "antd";
import { useTranslation } from "react-i18next";
import { errorMessage } from "../api/client";
import { useSubmitFeedback } from "../api/hooks";

const VERDICTS = ["true_positive", "false_positive", "benign_known", "duplicate", "out_of_scope"] as const;
const SUPPRESSIBLE = new Set<string>(["false_positive", "benign_known"]);

interface Values {
  verdict: (typeof VERDICTS)[number];
  reason?: string;
  suppress?: "none" | "domain" | "registered_domain";
  suppress_days?: number | null;
}

export default function FeedbackForm({ alertId, allowSuppress }: { alertId: number; allowSuppress: boolean }) {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const submit = useSubmitFeedback(alertId);
  const [form] = Form.useForm<Values>();
  const verdict = Form.useWatch("verdict", form);
  const onFinish = (v: Values) =>
    submit.mutate(
      {
        verdict: v.verdict,
        reason: v.reason ?? "",
        suppress: allowSuppress && SUPPRESSIBLE.has(v.verdict) ? (v.suppress ?? "none") : "none",
        suppress_days: allowSuppress && SUPPRESSIBLE.has(v.verdict) ? (v.suppress_days ?? null) : null,
      },
      {
        onSuccess: () => {
          void message.success(t("feedback.submitted"));
          form.resetFields();
        },
        onError: (e) => void message.error(t("common.error", { message: errorMessage(e) })),
      },
    );
  return (
    <Card title={t("feedback.title")}>
      <Form form={form} name="feedback" layout="vertical" onFinish={onFinish} initialValues={{ suppress: "none" }}>
        <Form.Item name="verdict" label={t("feedback.verdict")} rules={[{ required: true }]}>
          <Radio.Group options={VERDICTS.map((v) => ({ value: v, label: t(`verdict.${v}`) }))} />
        </Form.Item>
        <Form.Item name="reason" label={t("feedback.reason")}>
          <Input.TextArea rows={2} maxLength={2000} />
        </Form.Item>
        {allowSuppress && verdict && SUPPRESSIBLE.has(verdict) && (
          <>
            <Form.Item name="suppress" label={t("feedback.suppress")} extra={t("feedback.suppressHint")}>
              <Radio.Group
                options={[
                  { value: "none", label: t("feedback.suppressNone") },
                  { value: "domain", label: t("feedback.suppressDomain") },
                  { value: "registered_domain", label: t("feedback.suppressRegistered") },
                ]}
              />
            </Form.Item>
            <Form.Item name="suppress_days" label={t("feedback.suppressDays")}>
              <InputNumber min={1} max={3650} />
            </Form.Item>
          </>
        )}
        <Button type="primary" htmlType="submit" loading={submit.isPending}>
          {t("common.submit")}
        </Button>
      </Form>
    </Card>
  );
}
