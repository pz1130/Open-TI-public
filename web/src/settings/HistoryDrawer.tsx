import { listPagination } from "../components/pagination";
import { Button, Card, Drawer, Space, Table, Tabs, Tag, Typography } from "antd";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useConfigRevision, useConfigRevisions, type ConfigKind, type ConfigRevision } from "../api/hooks";
import { fmtTime } from "../components/format";

type Props = {
  kind: ConfigKind;
  open: boolean;
  onClose: () => void;
  current: number;
  canWrite: boolean;
  onRestore: (version: number) => void;
};

export default function HistoryDrawer({ kind, open, onClose, current, canWrite, onRestore }: Props) {
  const { t } = useTranslation();
  const revs = useConfigRevisions(kind, open);
  const [viewing, setViewing] = useState<number | null>(null);
  const detail = useConfigRevision(kind, viewing);
  return (
    <Drawer open={open} onClose={onClose} width={760} title={t("settings.history.title")} destroyOnHidden>
      <Table<ConfigRevision>
        rowKey="version"
        size="small"
        pagination={listPagination}
        dataSource={revs.data ?? []}
        columns={[
          {
            title: t("settings.history.version"),
            dataIndex: "version",
            render: (v: number, r) => (
              <Space size={4}>
                {`v${v}`}
                {r.restored_from ? <Tag>{t("settings.history.restoredFrom", { v: r.restored_from })}</Tag> : null}
              </Space>
            ),
          },
          { title: t("settings.history.user"), dataIndex: "created_by" },
          { title: t("settings.history.time"), dataIndex: "created_at", render: (v: string) => fmtTime(v) },
          { title: t("settings.history.note"), dataIndex: "note" },
          {
            key: "actions",
            render: (_: unknown, r) => (
              <Space>
                <Button size="small" onClick={() => setViewing(r.version)}>{t("settings.history.view")}</Button>
                {canWrite && r.version !== current && (
                  <Button size="small" onClick={() => onRestore(r.version)}>{t("settings.history.restore")}</Button>
                )}
              </Space>
            ),
          },
        ]}
      />
      {viewing !== null && detail.data && (
        <Card size="small" style={{ marginTop: 16 }} title={t("settings.history.viewing", { v: viewing })}>
          <Tabs
            items={[
              {
                key: "diff",
                label: t("settings.history.diff", { v: current }),
                children: <pre className="opti-mono oti-config-pre">{detail.data.diff || t("settings.history.noDiff")}</pre>,
              },
              { key: "yaml", label: t("settings.history.content"), children: <pre className="opti-mono oti-config-pre">{detail.data.yaml}</pre> },
            ]}
          />
        </Card>
      )}
      {revs.data?.length === 0 && <Typography.Text type="secondary">{t("settings.history.empty")}</Typography.Text>}
    </Drawer>
  );
}
