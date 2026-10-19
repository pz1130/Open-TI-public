import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Alert, App, Button, Card, Form, Input, Space, Typography } from "antd";
import { useTranslation } from "react-i18next";
import { api, errorMessage, unwrap } from "../api/client";
import { keys, useLogout } from "../api/hooks";

type Values = { current_password: string; new_password: string; confirm: string };

export default function PasswordPage({ forced = false }: { forced?: boolean }) {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const qc = useQueryClient();
  const logout = useLogout();
  const [form] = Form.useForm<Values>();
  const change = useMutation({ mutationFn: async (v: Values) => unwrap(await api.POST("/api/v1/auth/password", { body: { current_password: v.current_password, new_password: v.new_password } })),
    onSuccess: () => { form.resetFields(); qc.clear(); qc.setQueryData(keys.me, null); void message.success(t("access.passwordChanged")); },
    onError: (e) => void message.error(errorMessage(e)),
  });
  return <Card style={{ width: "min(100%, 520px)", margin: forced ? "10vh auto" : undefined }}>
    <Typography.Title level={3}>{t("access.changePassword")}</Typography.Title>
    {forced && <Alert type="warning" showIcon message={t("access.forcePasswordHint")} style={{ marginBottom: 20 }} />}
    <Form form={form} layout="vertical" onFinish={(v) => change.mutate(v)}>
      <Form.Item name="current_password" label={t("access.currentPassword")} rules={[{ required: true }]}><Input.Password autoComplete="current-password" maxLength={1000} /></Form.Item>
      <Form.Item name="new_password" label={t("access.newPassword")} rules={[{ required: true, min: 12, message: t("access.passwordHint") }]}><Input.Password autoComplete="new-password" maxLength={1000} /></Form.Item>
      <Form.Item name="confirm" label={t("access.confirmPassword")} dependencies={["new_password"]} rules={[{ required: true }, ({ getFieldValue }) => ({ validator: (_, value) => value === getFieldValue("new_password") ? Promise.resolve() : Promise.reject(new Error(t("access.passwordMismatch"))) })]}><Input.Password autoComplete="new-password" /></Form.Item>
      <Space><Button type="primary" htmlType="submit" loading={change.isPending}>{t("access.changePassword")}</Button>
        {forced && <Button onClick={() => logout.mutate()}>{t("app.logout")}</Button>}</Space>
    </Form>
  </Card>;
}
