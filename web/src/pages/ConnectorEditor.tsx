import { Alert, App, Button, Divider, Drawer, Input, InputNumber, Select, Space, Switch, Tabs, Tag, Typography } from "antd";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";
import { errorMessage, type Schemas } from "../api/client";
import { useConnectorConfig, useSaveConnectorApproval, useSaveConnectorConfig } from "../api/hooks";
import QueryError from "../components/QueryError";
import ConnectorHistory from "./ConnectorHistory";

type Config = Schemas["ConnectorConfigOut"];
type Property = { type?: string; title?: string; description?: string; default?: unknown; enum?: unknown[]; items?: Property & { properties?: Record<string, Property> } };

function guidedArray(spec: Property): boolean {
  return spec.type === "array" && !!(spec.items?.enum || spec.items?.type === "string" || (spec.items?.type === "object" && spec.items.properties));
}

export default function ConnectorEditor({ id, name, canWrite, canApprove, onClose }: {
  id: string | null;
  name: string;
  canWrite: boolean;
  canApprove: boolean;
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const { message, modal } = App.useApp();
  const q = useConnectorConfig(id);
  const save = useSaveConnectorConfig(id ?? "");
  const approve = useSaveConnectorApproval(id ?? "");
  const [enabled, setEnabled] = useState(false);
  const [plan, setPlan] = useState("free");
  const [schedule, setSchedule] = useState("");
  const [config, setConfig] = useState<Record<string, unknown>>({});
  const [complex, setComplex] = useState<Record<string, string>>({});
  const [secrets, setSecrets] = useState<Record<string, string | null>>({});
  const [approved, setApproved] = useState(false);
  const [reference, setReference] = useState("");
  const [darkwebReference, setDarkwebReference] = useState("");
  const [error, setError] = useState("");
  const [initialComplex, setInitialComplex] = useState<Record<string, string>>({});
  const [tab, setTab] = useState("settings");

  useEffect(() => {
    const data = q.data;
    if (!data) return;
    setEnabled(data.enabled);
    setPlan(data.plan);
    setSchedule(data.schedule ?? "");
    setConfig(data.config);
    const properties = (data.config_schema as { properties?: Record<string, Property> }).properties ?? {};
    const initial = Object.fromEntries(Object.entries(properties)
      .filter(([, spec]) => spec.type === "object" || (spec.type === "array" && (!guidedArray(spec) || spec.items?.type === "string")))
      .map(([key, spec]) => [key, spec.type === "array" && spec.items?.type === "string"
        ? ((data.config[key] ?? spec.default ?? []) as string[]).join("\n")
        : JSON.stringify(data.config[key] ?? spec.default ?? (spec.type === "array" ? [] : {}), null, 2)]));
    setComplex(initial);
    setInitialComplex(initial);
    setSecrets({});
    setApproved(data.license_approved);
    setReference(data.license_ref ?? "");
    setDarkwebReference(data.darkweb_approval_ref ?? "");
    setError("");
  }, [q.data, id]);

  const data: Config | undefined = q.data;
  const properties = ((data?.config_schema as { properties?: Record<string, Property> } | undefined)?.properties ?? {});
  const setField = (key: string, value: unknown) => setConfig((old) => ({ ...old, [key]: value }));

  async function saveConfig() {
    if (!data) return;
    const merged = { ...config };
    try {
      for (const [key, value] of Object.entries(complex)) {
        const spec = properties[key];
        merged[key] = spec?.type === "array" && spec.items?.type === "string"
          ? value.split("\n").map((v) => v.trim()).filter(Boolean)
          : JSON.parse(value);
      }
    } catch {
      setError(t("connectors.invalidJson"));
      return;
    }
    try {
      setError("");
      const r = await save.mutateAsync({ enabled, plan, config: merged, secrets, ...(data.schedulable ? { schedule: schedule.trim() || null } : {}) });
      setSecrets({});
      message.success(r?.version ? t("connectors.savedVersion", { version: r.version }) : t("connectors.saved"));
    } catch (e) {
      setError(errorMessage(e));
    }
  }

  async function saveApproval() {
    try {
      setError("");
      const r = await approve.mutateAsync({ license_approved: approved, license_ref: reference || null, darkweb_approval_ref: darkwebReference || null });
      message.success(r?.version ? t("connectors.savedVersion", { version: r.version }) : t("connectors.saved"));
    } catch (e) {
      setError(errorMessage(e));
    }
  }

  const dirty = data && (
    enabled !== data.enabled || plan !== data.plan || schedule !== (data.schedule ?? "") ||
    JSON.stringify(config) !== JSON.stringify(data.config) ||
    JSON.stringify(complex) !== JSON.stringify(initialComplex) ||
    Object.keys(secrets).length > 0 || approved !== data.license_approved ||
    reference !== (data.license_ref ?? "") || darkwebReference !== (data.darkweb_approval_ref ?? "")
  );
  function closeEditor() {
    if (!dirty) { onClose(); return; }
    modal.confirm({
      title: t("connectors.unsavedTitle"), content: t("connectors.unsavedHint"),
      okText: t("connectors.discard"), cancelText: t("connectors.keepEditing"), onOk: onClose,
    });
  }

  return (
    <Drawer title={`${t("connectors.configure")} · ${name}`} open={!!id} onClose={closeEditor} width={560} destroyOnHidden
      extra={data && tab === "settings" && <Space>
        {canWrite && <Button type="primary" loading={save.isPending} onClick={() => void saveConfig()}>{t("connectors.save")}</Button>}
        {canApprove && <Button loading={approve.isPending} onClick={() => void saveApproval()}>{t("connectors.saveApproval")}</Button>}
      </Space>}>
      <QueryError error={q.error} />
      {error && <Alert type="error" showIcon message={error} style={{ marginBottom: 16 }} />}
      {data && id && <Tabs activeKey={tab} onChange={setTab} items={[
        { key: "settings", label: t("connectors.tabSettings"), children: <>
        {canWrite && <form onSubmit={(e) => e.preventDefault()}>
          <Space direction="vertical" style={{ width: "100%" }} size="middle">
            <Space><Typography.Text>{t("connectors.enabled")}</Typography.Text><Switch aria-label={t("connectors.enabled")} checked={enabled} onChange={setEnabled} /></Space>
            <label>{t("connectors.plan")}<Select style={{ width: "100%", marginTop: 6 }} value={plan} onChange={setPlan} options={data.plans.map((p) => ({ label: p, value: p }))} /></label>
            {data.schedulable && <label>{t("connectors.schedule")}<Input value={schedule} placeholder={data.default_schedule ?? ""} onChange={(e) => setSchedule(e.target.value)} aria-label={t("connectors.schedule")} /><Typography.Text type="secondary">{t("connectors.scheduleHint")}</Typography.Text></label>}
          </Space>
          <Divider orientation="left">{t("connectors.parameters")}</Divider>
          {Object.keys(properties).length === 0 && <Typography.Text type="secondary">{t("connectors.noParameters")}</Typography.Text>}
          {Object.entries(properties).map(([key, spec]) => {
            const value = config[key] ?? spec.default;
            const items = Array.isArray(value) ? value : [];
            return <div key={key} style={{ marginBottom: 16 }}>
              <Typography.Text strong>{spec.title || key}</Typography.Text>
              {spec.title && <Typography.Text type="secondary"> · {key}</Typography.Text>}
              {spec.description && <div><Typography.Text type="secondary">{spec.description}</Typography.Text></div>}
              {spec.type === "array" && spec.items?.enum ? <Select mode="multiple" style={{ width: "100%", marginTop: 6 }} value={items} onChange={(v) => setField(key, v)} options={spec.items.enum.map((v) => ({ value: v as string, label: String(v) }))} />
                : spec.type === "array" && spec.items?.type === "string" ? <Input.TextArea aria-label={key} rows={3} style={{ marginTop: 6 }} value={complex[key] ?? ""} onChange={(e) => setComplex((old) => ({ ...old, [key]: e.target.value }))} placeholder={t("connectors.onePerLine")} />
                : spec.type === "array" && spec.items?.type === "object" && spec.items.properties ? <Space direction="vertical" style={{ width: "100%", marginTop: 6 }}>
                  {items.map((entry, index) => <div key={index} style={{ padding: 12, border: "1px solid #8884", borderRadius: 6 }}>
                    {Object.entries(spec.items!.properties!).map(([subkey, sub]) => <div key={subkey} style={{ marginBottom: 8 }}>
                      <Typography.Text>{sub.title || subkey}</Typography.Text>
                      {sub.type === "boolean" ? <Switch style={{ marginLeft: 8 }} checked={Boolean((entry as Record<string, unknown>)[subkey] ?? sub.default)} onChange={(v) => setField(key, items.map((x, i) => i === index ? { ...x, [subkey]: v } : x))} />
                        : sub.type === "integer" || sub.type === "number" ? <InputNumber style={{ width: "100%" }} value={(entry as Record<string, unknown>)[subkey] as number | undefined} onChange={(v) => setField(key, items.map((x, i) => i === index ? { ...x, [subkey]: v } : x))} />
                        : <Input value={String((entry as Record<string, unknown>)[subkey] ?? "")} onChange={(e) => setField(key, items.map((x, i) => i === index ? { ...x, [subkey]: e.target.value } : x))} />}
                    </div>)}
                    <Button size="small" onClick={() => setField(key, items.filter((_, i) => i !== index))}>{t("connectors.removeItem")}</Button>
                  </div>)}
                  <Button type="dashed" onClick={() => setField(key, [...items, {}])}>{t("connectors.addItem")}</Button>
                </Space>
                : spec.enum ? <Select style={{ width: "100%", marginTop: 6 }} value={value as string} onChange={(v) => setField(key, v)} options={spec.enum.map((v) => ({ value: v as string, label: String(v) }))} />
                : spec.type === "boolean" ? <div><Switch checked={Boolean(value)} onChange={(v) => setField(key, v)} /></div>
                : spec.type === "integer" || spec.type === "number" ? <InputNumber style={{ width: "100%", marginTop: 6 }} value={value as number | undefined} onChange={(v) => setField(key, v)} />
                : spec.type === "array" || spec.type === "object" ? <Input.TextArea aria-label={key} rows={4} style={{ marginTop: 6, fontFamily: "monospace" }} value={complex[key] ?? ""} onChange={(e) => setComplex((old) => ({ ...old, [key]: e.target.value }))} />
                : <Input style={{ marginTop: 6 }} value={value == null ? "" : String(value)} onChange={(e) => setField(key, e.target.value)} />}
            </div>;
          })}
          <Divider orientation="left">{t("connectors.credentials")}</Divider>
          {!data.encryption_key && data.credentials.length > 0 && <Alert type="warning" showIcon message={t("connectors.noEncryptionKey")} description={canWrite && <Link to="/settings/master_key" onClick={onClose}>{t("settings.masterKey.open")}</Link>} style={{ marginBottom: 12 }} />}
          {data.credentials.length === 0 && <Typography.Text type="secondary">{t("connectors.noCredentials")}</Typography.Text>}
          {data.credentials.map((credential) => <div key={credential.name} style={{ marginBottom: 16 }}>
            <Space><Typography.Text strong>{credential.name}</Typography.Text><Tag color={credential.configured === null ? "purple" : credential.configured ? "green" : "default"}>{credential.configured === null ? t("connectors.credNode") : credential.configured ? t("connectors.credSet") : t("connectors.credUnset")}</Tag>{credential.required && <Tag color="orange">{t("connectors.required")}</Tag>}{credential.problem && <Tag color="red">{t("connectors.credProblem")}</Tag>}</Space>
            <Space.Compact style={{ width: "100%", marginTop: 6 }}>
              <Input.Password autoComplete="new-password" aria-label={credential.name} placeholder={t("connectors.secretPlaceholder")} value={secrets[credential.name] ?? ""} onChange={(e) => setSecrets((old) => ({ ...old, [credential.name]: e.target.value || null }))} />
              <Button onClick={() => setSecrets((old) => ({ ...old, [credential.name]: null }))}>{t("connectors.clear")}</Button>
            </Space.Compact>
          </div>)}
        </form>}
        {canApprove && <>
          <Divider orientation="left">{t("connectors.license")}</Divider>
          <Space><Typography.Text>{t("connectors.approved")}</Typography.Text><Switch aria-label={t("connectors.approved")} checked={approved} onChange={setApproved} /></Space>
          <div style={{ marginTop: 14 }}><Typography.Text>{t("connectors.approvalRef")}</Typography.Text><Input aria-label={t("connectors.approvalRef")} value={reference} onChange={(e) => setReference(e.target.value)} /></div>
          {data.darkweb && <div style={{ marginTop: 14 }}><Typography.Text>{t("connectors.darkwebApprovalRef")}</Typography.Text><Input aria-label={t("connectors.darkwebApprovalRef")} value={darkwebReference} onChange={(e) => setDarkwebReference(e.target.value)} /></div>}
        </>}
        <Typography.Paragraph type="secondary" style={{ marginTop: 20 }}>{t("connectors.effectNote")}</Typography.Paragraph>
        </> },
        { key: "history", label: t("connectors.tabHistory"), children: <ConnectorHistory id={id} active={tab === "history"} canWrite={canWrite} /> },
      ]} />}
    </Drawer>
  );
}
