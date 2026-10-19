import { Alert } from "antd";
import { useTranslation } from "react-i18next";
import { errorMessage } from "../api/client";

export default function QueryError({ error }: { error: unknown }) {
  const { t } = useTranslation();
  return error ? <Alert type="error" showIcon style={{ marginBottom: 16 }} message={t("common.error", { message: errorMessage(error) })} /> : null;
}
