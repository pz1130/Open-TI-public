import { Alert, Button, Space } from "antd";
import { useTranslation } from "react-i18next";
import type { ConfigError } from "../api/hooks";
import type { VersionConflict } from "./useConfigSaver";

type Props = { errors: ConfigError[]; conflict: VersionConflict | null; onReload: () => void; onHistory: () => void };

export default function SaveFeedback({ errors, conflict, onReload, onHistory }: Props) {
  const { t } = useTranslation();
  return (
    <>
      {conflict && (
        <Alert
          type="warning"
          showIcon
          message={t("settings.conflict", { user: conflict.updated_by ?? "?", v: conflict.current_version })}
          action={
            <Space>
              <Button size="small" onClick={onHistory}>{t("settings.history.open")}</Button>
              <Button size="small" danger onClick={onReload}>{t("settings.reload")}</Button>
            </Space>
          }
        />
      )}
      {errors.length > 0 && (
        <Alert
          type="error"
          showIcon
          message={t("settings.invalid")}
          description={
            <ul className="oti-config-errors">
              {errors.map((e, i) => (
                <li key={i}>
                  {e.path && <code>{e.path}</code>} {e.line ? t("settings.line", { n: e.line }) : null} {e.message}
                </li>
              ))}
            </ul>
          }
        />
      )}
    </>
  );
}
