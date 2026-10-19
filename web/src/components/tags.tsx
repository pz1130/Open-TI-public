import { Tag } from "antd";
import { useTranslation } from "react-i18next";

const SEVERITY_COLOR: Record<string, string> = {
  critical: "red", high: "volcano", medium: "orange", low: "blue", info: "default",
};
const STATUS_COLOR: Record<string, string> = {
  open: "red", acknowledged: "gold", closed: "green", superseded: "default",
};
const WATCH_COLOR: Record<string, string> = {
  unknown: "default", no_dns: "default", parked: "blue", mx_only: "orange", live: "volcano", phishing: "red",
};

export function SeverityTag({ value }: { value: string }) {
  const { t } = useTranslation();
  return (
    <Tag color={SEVERITY_COLOR[value] ?? "default"} className={`oti-sev oti-sev-${value}`}>
      {t(`severity.${value}`, { defaultValue: value })}
    </Tag>
  );
}

export function AlertStatusTag({ value }: { value: string }) {
  const { t } = useTranslation();
  return <Tag color={STATUS_COLOR[value] ?? "default"}>{t(`alertStatus.${value}`, { defaultValue: value })}</Tag>;
}

export function WatchStateTag({ value }: { value: string }) {
  const { t } = useTranslation();
  return <Tag color={WATCH_COLOR[value] ?? "default"}>{t(`watchState.${value}`, { defaultValue: value })}</Tag>;
}


const TAKEDOWN_COLOR: Record<string, string> = {
  draft: "default", approved: "blue", submitted: "gold", acknowledged: "orange",
  removed: "green", rejected: "red", cancelled: "default", reappeared: "volcano",
};

export function TakedownStateTag({ value }: { value: string }) {
  const { t } = useTranslation();
  return <Tag color={TAKEDOWN_COLOR[value] ?? "default"}>{t(`takedownState.${value}`, { defaultValue: value })}</Tag>;
}

const HEALTH_COLOR: Record<string, string> = { blocked: "orange", ok: "green", failing: "red", stale: "orange", unknown: "purple" };

export function ConnectorHealthTag({ value }: { value: string }) {
  const { t } = useTranslation();
  return <Tag color={HEALTH_COLOR[value] ?? "default"}>{t(`connectors.health.${value}`, { defaultValue: value })}</Tag>;
}

