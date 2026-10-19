import { App, Button, Collapse, Empty, Space, Tag, Typography } from "antd";
import { useTranslation } from "react-i18next";
import { errorMessage } from "../api/client";
import { useConnectorHistory, useRestoreConnector } from "../api/hooks";
import QueryError from "../components/QueryError";
import { fmtTime } from "../components/format";

/** 连接器编辑抽屉的「历史」：只列改动过这个连接器的版本；恢复只改启用、套餐与参数。 */
export default function ConnectorHistory({ id, active, canWrite }: { id: string; active: boolean; canWrite: boolean }) {
  const { t } = useTranslation();
  const { message, modal } = App.useApp();
  const q = useConnectorHistory(id, active);
  const restore = useRestoreConnector(id);

  function confirmRestore(version: number) {
    modal.confirm({
      title: t("connectors.restoreTitle", { version }),
      content: t("connectors.restoreHint"),
      okText: t("connectors.restoreOk"),
      onOk: async () => {
        try {
          const r = await restore.mutateAsync(version);
          message.success(t("connectors.restored", { version: r.version }));
        } catch (e) {
          message.error(errorMessage(e));
        }
      },
    });
  }

  if (q.error) return <QueryError error={q.error} />;
  const rows = q.data ?? [];
  return (
    <Space direction="vertical" style={{ width: "100%" }}>
      {q.data && rows.length === 0 && <Empty description={t("connectors.historyEmpty")} />}
      {rows.length > 0 && <Collapse
        items={rows.map((row) => ({
          key: row.version,
          label: <Space wrap>
            <Typography.Text strong>v{row.version}</Typography.Text>
            <Typography.Text type="secondary">{fmtTime(row.created_at)} · {row.created_by}</Typography.Text>
            {row.changed.map((f) => <Tag key={f}>{t(`connectors.field.${f}`, { defaultValue: f })}</Tag>)}
            {row.restored_from != null && <Tag color="blue">{t("connectors.restoredFrom", { version: row.restored_from })}</Tag>}
          </Space>,
          extra: canWrite && row.restorable
            ? <Button size="small" onClick={(e) => { e.stopPropagation(); confirmRestore(row.version); }}>{t("connectors.restore")}</Button>
            : undefined,
          children: <pre className="opti-mono oti-config-pre">{row.diff}</pre>,
        }))}
      />}
      <Typography.Text type="secondary">{t("connectors.historyNote")}</Typography.Text>
    </Space>
  );
}
