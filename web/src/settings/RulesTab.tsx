import { listPagination } from "../components/pagination";
import { Alert, Button, Card, Form, Input, List, Radio, Space, Spin, Tag } from "antd";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useConfig, useMe, useRulesTest, useValidateConfig, type ConfigError } from "../api/hooks";
import { can } from "../auth/perms";
import QueryError from "../components/QueryError";
import KeywordScanPanel, { publicTextTerms } from "../components/KeywordScanPanel";
import HistoryDrawer from "./HistoryDrawer";
import RulesForm from "./RulesForm.tsx";
import { fromForm, toForm, type RulesFormValues } from "./rulesForm";
import SaveFeedback from "./SaveFeedback";
import StatusBar from "./StatusBar";
import { useConfigSaver } from "./useConfigSaver";

type Mode = "form" | "yaml";

export default function RulesTab() {
  const { t } = useTranslation();
  const me = useMe();
  const q = useConfig("rules");
  const validate = useValidateConfig("rules");
  const saver = useConfigSaver("rules");
  const test = useRulesTest();
  const [form] = Form.useForm<RulesFormValues>();
  const [mode, setMode] = useState<Mode>("form");
  const [yamlText, setYamlText] = useState("");
  const [modeErrors, setModeErrors] = useState<ConfigError[]>([]);
  const [note, setNote] = useState("");
  const [sample, setSample] = useState("");
  const [history, setHistory] = useState(false);
  const canWrite = can(me.data, "rules:write");

  function load(data: Record<string, unknown>, yaml: string) {
    form.setFieldsValue(toForm(data));
    setYamlText(yaml);
  }

  useEffect(() => {
    if (q.data) load(q.data.data, q.data.yaml);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [q.data]);

  if (q.isPending) return <Spin />;
  if (q.isError && !q.data) return <QueryError error={q.error} />;
  const config = q.data;

  const formData = () => fromForm(form.getFieldsValue(true) as RulesFormValues);

  async function draftYaml(): Promise<string | null> {
    if (mode === "yaml") return yamlText;
    const r = await validate.mutateAsync({ data: formData() });
    if (!r.ok) {
      setModeErrors(r.errors ?? []);
      return null;
    }
    return r.yaml ?? null;
  }

  async function switchTo(next: Mode) {
    if (next === mode) return;
    setModeErrors([]);
    const r = await validate.mutateAsync(next === "yaml" ? { data: formData() } : { yaml: yamlText });
    if (!r.ok) {
      setModeErrors(r.errors ?? []);
      return;
    }
    if (next === "yaml") setYamlText(r.yaml ?? "");
    else form.setFieldsValue(toForm(r.data ?? {}));
    setMode(next);
  }

  async function onSave() {
    setModeErrors([]);
    if (mode === "form") await form.validateFields();
    const body = mode === "yaml" ? { yaml: yamlText } : { data: formData() };
    if (await saver.submit({ ...body, note: note.trim() || null, base_version: config.version, confirm_project_change: false, confirm_oidc_change: false })) setNote("");
  }

  async function onTest() {
    setModeErrors([]);
    const draft = await draftYaml();
    if (draft !== null) test.mutate({ draft_yaml: draft, text: sample, domains: [] });
  }

  return (
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      <StatusBar kind="rules" config={config} />
      {canWrite && <KeywordScanPanel version={config.version} textTerms={publicTextTerms(config.data)} domainTerms={((config.data.domains as { brand_tokens?: string[] } | undefined)?.brand_tokens ?? [])} />}
      <SaveFeedback
        errors={[...modeErrors, ...saver.errors]}
        conflict={saver.conflict}
        onHistory={() => setHistory(true)}
        onReload={() =>
          q.refetch().then((r) => {
            if (r.isError || !r.data) return;
            load(r.data.data, r.data.yaml);
            saver.clearConflict();
          })
        }
      />
      {/* 按钮样式把 radio 设成 pointer-events:none 且宽高为 0，user-event 点不到。拉回输入框本身。 */}
      <style>{".oti-rules-mode input[type='radio']{pointer-events:auto !important;position:absolute;inset:0;width:100%;height:100%;opacity:0}"}</style>
      <Radio.Group
        className="oti-rules-mode"
        optionType="button"
        value={mode}
        onChange={(e) => switchTo(e.target.value as Mode)}
        options={[{ value: "form", label: t("settings.rules.modeForm") }, { value: "yaml", label: "YAML" }]}
      />
      {mode === "yaml" ? (
        <>
          <Alert type="info" showIcon message={t("settings.rules.yamlHint")} />
          <Input.TextArea
            aria-label={t("settings.rules.yaml")}
            className="opti-mono"
            rows={24}
            value={yamlText}
            readOnly={!canWrite}
            onChange={(e) => setYamlText(e.target.value)}
          />
        </>
      ) : (
        <Form form={form} layout="vertical" disabled={!canWrite}>
          <RulesForm disabled={!canWrite} canSwitchProject={can(me.data, "projects:write")} />
        </Form>
      )}
      <Card size="small" title={t("settings.rules.test")}>
        <Space direction="vertical" style={{ width: "100%" }}>
          <Input.TextArea aria-label={t("settings.rules.sample")} rows={3} value={sample} maxLength={50_000} onChange={(e) => setSample(e.target.value)} />
          <Button onClick={onTest} loading={test.isPending || validate.isPending}>{t("settings.rules.runTest")}</Button>
          {test.data && (
            <List pagination={listPagination}
              size="small"
              dataSource={test.data.text_hits}
              locale={{ emptyText: t("settings.rules.noHits") }}
              renderItem={(h) => (
                <List.Item>
                  <Space>
                    <Tag>{h.role}</Tag>
                    <span>{`${h.set_name} · ${h.term}`}</span>
                    <span className="opti-mono">{h.context}</span>
                  </Space>
                </List.Item>
              )}
            />
          )}
        </Space>
      </Card>
      <Space wrap>
        <Button onClick={() => setHistory(true)}>{t("settings.history.open")}</Button>
        {canWrite && (
          <>
            <Input style={{ width: 280 }} placeholder={t("settings.note")} value={note} maxLength={200} onChange={(e) => setNote(e.target.value)} />
            <Button type="primary" loading={saver.pending} onClick={onSave}>{t("settings.save")}</Button>
          </>
        )}
      </Space>
      <HistoryDrawer
        kind="rules"
        open={history}
        onClose={() => setHistory(false)}
        current={config.version}
        canWrite={canWrite}
        onRestore={(v) => saver.restore(v, config.version).then((ok) => ok && setHistory(false))}
      />
    </Space>
  );
}
