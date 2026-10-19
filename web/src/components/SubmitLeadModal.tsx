import { InboxOutlined } from "@ant-design/icons";
import { Alert, App, DatePicker, Form, Input, Modal, Radio, Upload, type UploadFile } from "antd";
import type { Dayjs } from "dayjs";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router";
import { uploadEvidence, usePlatformCheck, useSubmitLead } from "../api/hooks";
import QueryError from "./QueryError";

const CATEGORIES = ["impersonation_account", "fraud_scam", "phishing_site", "clone_site"] as const;
const SEVERITIES = ["medium", "high", "critical"] as const;
const ACCEPT = "image/png,image/jpeg,image/webp";

type Values = {
  url: string;
  category: (typeof CATEGORIES)[number];
  severity: (typeof SEVERITIES)[number];
  description: string;
  observed_at?: Dayjs;
};

/** 停止输入一段时间后才更新，避免每按一次键就请求一次平台名单检查。 */
function useDebounced<T>(value: T, ms: number): T {
  const [settled, setSettled] = useState(value);
  useEffect(() => {
    const id = setTimeout(() => setSettled(value), ms);
    return () => clearTimeout(id);
  }, [value, ms]);
  return settled;
}

/** 人工提交线索（设计文档 4.2）：平台名单内的链接不会被自动访问，证据靠上传截图。url 用于预填（如把冒充账号候选提升为告警）。 */
export default function SubmitLeadModal({ open, onClose, url: initialUrl }: { open: boolean; onClose: () => void; url?: string }) {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const navigate = useNavigate();
  const [form] = Form.useForm<Values>();
  const [files, setFiles] = useState<UploadFile[]>([]);
  const [busy, setBusy] = useState(false);
  const url = useDebounced(Form.useWatch("url", form) ?? "", 300);
  const check = usePlatformCheck(url);
  const submit = useSubmitLead();
  const c = check.data;

  const onFinish = async (v: Values) => {
    setBusy(true);
    try {
      const out = await submit.mutateAsync({
        url: v.url,
        category: v.category,
        severity: v.severity,
        description: v.description,
        ...(v.observed_at ? { observed_at: v.observed_at.toISOString() } : {}),
      });
      let failed = 0;
      for (const f of files) {
        try {
          await uploadEvidence(out.alert_id, f.originFileObj as File);
        } catch {
          failed += 1;
        }
      }
      if (failed > 0) void message.warning(t("submit.uploadFailed", { n: failed }));
      form.resetFields();
      setFiles([]);
      onClose();
      navigate(`/alerts/${out.alert_id}`);
    } catch {
      // 提交失败：错误由 QueryError 显示，保留已填内容
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      open={open}
      title={t("submit.title")}
      okText={t("common.submit")}
      okButtonProps={{ disabled: !!c?.error, loading: busy }}
      onOk={() => form.submit()}
      onCancel={() => {
        // 取消时清空，避免这次选的截图被带到下一条线索
        form.resetFields();
        setFiles([]);
        onClose();
      }}
      destroyOnHidden
    >
      <QueryError error={submit.error} />
      <Form form={form} layout="vertical" initialValues={{ category: "impersonation_account", severity: "high", url: initialUrl }} onFinish={(v) => void onFinish(v)}>
        <Form.Item name="url" label={t("submit.url")} rules={[{ required: true, message: t("submit.urlRequired") }]}>
          <Input placeholder="https://" autoComplete="off" />
        </Form.Item>
        {c?.error && <Alert type="error" showIcon style={{ marginBottom: 16 }} message={t(`submit.error.${c.error}`, { defaultValue: c.error })} />}
        {c && !c.error && (
          <Alert
            type={c.platform ? "warning" : "info"}
            showIcon
            style={{ marginBottom: 16 }}
            message={c.platform ? t("submit.platformHint", { name: c.platform_name }) : t("submit.fetchHint")}
          />
        )}
        <Form.Item name="category" label={t("submit.category")}>
          <Radio.Group options={CATEGORIES.map((k) => ({ value: k, label: t(`category.${k}`) }))} />
        </Form.Item>
        <Form.Item name="severity" label={t("submit.severity")}>
          <Radio.Group options={SEVERITIES.map((k) => ({ value: k, label: t(`severity.${k}`) }))} />
        </Form.Item>
        <Form.Item name="description" label={t("submit.description")} rules={[{ required: true, whitespace: true, message: t("submit.descriptionRequired") }]}>
          <Input.TextArea rows={4} maxLength={2000} showCount />
        </Form.Item>
        <Form.Item name="observed_at" label={t("submit.observedAt")}>
          <DatePicker showTime />
        </Form.Item>
        <Form.Item label={t("submit.screenshots")}>
          <div data-testid="lead-files">
            <Upload.Dragger
              multiple
              accept={ACCEPT}
              fileList={files}
              beforeUpload={() => false}
              onChange={({ fileList }) => setFiles(fileList)}
            >
              <p className="ant-upload-drag-icon"><InboxOutlined /></p>
              <p>{t("submit.dropHint")}</p>
            </Upload.Dragger>
          </div>
        </Form.Item>
      </Form>
    </Modal>
  );
}
