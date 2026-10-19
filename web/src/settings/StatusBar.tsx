import { Space, Tag, Tooltip, Typography } from "antd";
import { useTranslation } from "react-i18next";
import { useConfigStatus, type ConfigKind, type ConfigOut, type ConfigProcess } from "../api/hooks";
import { fmtTime } from "../components/format";

type State = "applied" | "pending" | "error" | "stale";
const COLOR: Record<State, string> = { applied: "success", pending: "processing", error: "error", stale: "default" };

function stateOf(p: ConfigProcess, current: string | undefined): State {
  if (p.error) return "error";
  if (p.stale) return "stale";
  return p.digest === current ? "applied" : "pending";
}

export default function StatusBar({ kind, config }: { kind: ConfigKind; config: ConfigOut }) {
  const { t } = useTranslation();
  const status = useConfigStatus();
  const current = status.data?.current_digest[kind];
  const procs = (status.data?.processes ?? []).filter((p) => p.kind === kind);
  return (
    <div className="oti-config-status" data-testid={`config-status-${kind}`}>
      <Space wrap>
        <Tag color={config.source === "db" ? "blue" : "default"}>
          {config.source === "db" ? t("settings.versionDb", { v: config.version }) : config.file_path ? t("settings.versionFile", { path: config.file_path }) : t("settings.versionDefault")}
        </Tag>
        {config.created_by && (
          <Typography.Text type="secondary">{t("settings.savedBy", { user: config.created_by, time: fmtTime(config.created_at) })}</Typography.Text>
        )}
        {config.note && <Typography.Text type="secondary">“{config.note}”</Typography.Text>}
      </Space>
      <Space wrap size={4}>
        {procs.map((p) => {
          const state = stateOf(p, current);
          return (
            <Tooltip key={p.process} title={p.error ?? t(`settings.process.${state}`)}>
              <span data-state={state}>
                <Tag color={COLOR[state]}>{`${p.process} · v${p.version}`}</Tag>
              </span>
            </Tooltip>
          );
        })}
      </Space>
    </div>
  );
}
