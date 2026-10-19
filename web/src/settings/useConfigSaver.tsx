import { App } from "antd";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { errorMessage, type Schemas } from "../api/client";
import { useRestoreConfig, useSaveConfig, type ConfigError, type ConfigKind, type ConfigSaveDraft } from "../api/hooks";
import { conflictOf, fieldErrors } from "./errors";

/** 保留期预览里只统计了下一轮的项：发现与案件按批次截取，告警、证据、下架记录随之而来。 */
const BATCH_LIMITED = new Set(["findings", "cases", "alerts", "evidence", "takedowns"]);

export type VersionConflict = { current_version: number; updated_by: string | null };

export function useConfigSaver(kind: ConfigKind) {
  const save = useSaveConfig(kind);
  const restoreM = useRestoreConfig(kind);
  const { modal, message } = App.useApp();
  const { t } = useTranslation();
  const [errors, setErrors] = useState<ConfigError[]>([]);
  const [conflict, setConflict] = useState<VersionConflict | null>(null);

  async function run<B extends { confirm_project_change?: boolean; confirm_oidc_change?: boolean; confirm_retention?: boolean }>(send: (b: B) => Promise<unknown>, body: B): Promise<boolean> {
    setErrors([]);
    setConflict(null);
    try {
      await send(body);
      message.success(t("settings.saved"));
      return true;
    } catch (e) {
      const c = conflictOf(e);
      if (c?.reason === "project_change") {
        const ok = await modal.confirm({
          title: t("settings.projectChange.title"),
          content: t("settings.projectChange.body", { from: c.from, to: c.to, count: c.alert_count }),
          okText: t("settings.projectChange.ok"),
          okButtonProps: { danger: true },
        });
        return ok ? run(send, { ...body, confirm_project_change: true }) : false;
      }
      if (c?.reason === "oidc_redirect_change") {
        const ok = await modal.confirm({
          title: t("settings.oidcChange.title"),
          content: t("settings.oidcChange.body", { uri: c.redirect_uri }),
          okText: t("settings.projectChange.ok"),
          okButtonProps: { danger: true },
        });
        return ok ? run(send, { ...body, confirm_oidc_change: true }) : false;
      }
      if (c?.reason === "retention_shortened") {
        const ok = await modal.confirm({
          title: t("settings.retention.confirmTitle"),
          okText: t("settings.retention.confirmOk"),
          okButtonProps: { danger: true },
          content: c.preview ? (
            <>
              <ul className="oti-config-errors">
                {Object.entries(c.preview).filter(([, count]) => count > 0).map(([key, count]) => (
                  <li key={key}>
                    {t(`settings.retention.preview.${key}`)}：{c.preview_capped && BATCH_LIMITED.has(key) ? `≥ ${count}` : count}
                  </li>
                ))}
              </ul>
              {c.preview_capped && <p>{t("settings.retention.previewCapped")}</p>}
            </>
          ) : t("settings.retention.previewTimeout"),
        });
        return ok ? run(send, { ...body, confirm_retention: true }) : false;
      }
      if (c?.reason === "encryption_key_missing") {
        message.error(t("settings.secret.keyMissing"));
        return false;
      }
      if (c?.reason === "version_conflict") {
        setConflict({ current_version: c.current_version, updated_by: c.updated_by });
        return false;
      }
      const fe = fieldErrors(e);
      if (fe.length) setErrors(fe);
      else message.error(errorMessage(e));
      return false;
    }
  }

  return {
    submit: (body: ConfigSaveDraft) => run((b) => save.mutateAsync(b), body),
    restore: (version: number, baseVersion: number) =>
      run((b) => restoreM.mutateAsync({ ...b, version }), { base_version: baseVersion } as Schemas["ConfigRestoreIn"]),
    errors,
    conflict,
    clearConflict: () => setConflict(null),
    pending: save.isPending || restoreM.isPending,
  };
}
