import { Alert } from "antd";
import { useTranslation } from "react-i18next";
import { useRematchStatus } from "../api/hooks";

export default function RematchStatus({ kind }: { kind: "vendors" | "software" }) {
  const { t } = useTranslation();
  const query = useRematchStatus(kind);
  const status = query.data;
  if (!status || status.status === "none") return null;
  const type = status.status === "failed" ? "error" : status.status === "queued" ? "info" : "success";
  return <Alert type={type} showIcon message={t(`settings.rematch.${status.status}`, {
    v: status.version, n: status.alerts ?? 0, error: status.error,
  })} />;
}
