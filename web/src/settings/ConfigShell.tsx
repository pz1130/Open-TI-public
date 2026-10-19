import { Button, Input, Space } from "antd";
import { useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import type { ConfigKind, ConfigOut } from "../api/hooks";
import HistoryDrawer from "./HistoryDrawer";
import SaveFeedback from "./SaveFeedback";
import StatusBar from "./StatusBar";
import type { useConfigSaver } from "./useConfigSaver";

type Props = {
  kind: ConfigKind;
  config: ConfigOut;
  canWrite: boolean;
  saver: ReturnType<typeof useConfigSaver>;
  onSave: (note: string | null) => Promise<boolean>;
  onReload: () => void;
  children: ReactNode;
};

/** Shared status, history and save controls for configuration pages. */
export default function ConfigShell({ kind, config, canWrite, saver, onSave, onReload, children }: Props) {
  const { t } = useTranslation();
  const [note, setNote] = useState("");
  const [history, setHistory] = useState(false);
  return (
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      <StatusBar kind={kind} config={config} />
      <SaveFeedback errors={saver.errors} conflict={saver.conflict} onHistory={() => setHistory(true)} onReload={onReload} />
      {children}
      <Space wrap>
        <Button onClick={() => setHistory(true)}>{t("settings.history.open")}</Button>
        {canWrite && (
          <>
            <Input style={{ width: 280 }} placeholder={t("settings.note")} value={note} maxLength={200} onChange={(e) => setNote(e.target.value)} />
            <Button type="primary" loading={saver.pending} onClick={async () => (await onSave(note.trim() || null)) && setNote("")}>
              {t("settings.save")}
            </Button>
          </>
        )}
      </Space>
      <HistoryDrawer kind={kind} open={history} onClose={() => setHistory(false)} current={config.version} canWrite={canWrite}
        onRestore={(v) => saver.restore(v, config.version).then((ok) => ok && setHistory(false))} />
    </Space>
  );
}
