import { Button, Input, Space, Tag, Typography } from "antd";
import { useTranslation } from "react-i18next";
import type { SecretState } from "../api/hooks";

type Props = {
  label: string;
  state: SecretState | undefined;
  draft: string | null | undefined; // undefined 不改；null 清除；字符串替换
  onChange: (v: string | null | undefined) => void;
  disabled: boolean;
  keyMissing: boolean;
};

export default function SecretInput({ label, state, draft, onChange, disabled, keyMissing }: Props) {
  const { t } = useTranslation();
  const status = !state || !state.set
    ? t("settings.secret.none")
    : state.source === "env"
      ? t("settings.secret.env")
      : t("settings.secret.set", { hint: state.hint ?? "••••" });
  return (
    <Space direction="vertical" size={4} style={{ width: "100%" }}>
      <Space size={6} wrap>
        <Typography.Text type="secondary">{status}</Typography.Text>
        {draft === null && <Tag color="warning">{t("settings.secret.willClear")}</Tag>}
      </Space>
      <Space.Compact style={{ width: "100%" }}>
        <Input.Password
          aria-label={label}
          placeholder={keyMissing ? t("settings.secret.keyMissing") : t("settings.secret.placeholder")}
          disabled={disabled || keyMissing || draft === null}
          value={typeof draft === "string" ? draft : ""}
          onChange={(e) => onChange(e.target.value === "" ? undefined : e.target.value)}
          autoComplete="new-password"
        />
        {!disabled && state?.set && draft !== null && (
          <Button onClick={() => onChange(null)}>{t("settings.secret.clear")}</Button>
        )}
        {!disabled && draft === null && <Button onClick={() => onChange(undefined)}>{t("settings.secret.undo")}</Button>}
      </Space.Compact>
    </Space>
  );
}
