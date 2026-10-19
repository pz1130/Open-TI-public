import { Alert, Collapse, Input, InputNumber, Select, Space, Spin, Switch, Typography } from "antd";
import { useQuery } from "@tanstack/react-query";
import { useEffect, useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { api, unwrap } from "../api/client";
import { useConfig, useConfigSecrets } from "../api/hooks";
import QueryError from "../components/QueryError";
import ConfigShell from "./ConfigShell";
import SecretInput from "./SecretInput";
import { useConfigSaver } from "./useConfigSaver";

type Schema = { $ref?: string; $defs?: Record<string, Schema>; type?: string; properties?: Record<string, Schema>; additionalProperties?: Schema | boolean; anyOf?: Schema[]; enum?: string[]; items?: Schema; minimum?: number; maximum?: number };
type Data = Record<string, unknown>;

export default function BusinessSettingsTab({ kind }: { kind: "identity" | "operations" }) {
  const { t } = useTranslation();
  const q = useConfig(kind);
  const schema = useQuery({ queryKey: ["business-settings-schema"], queryFn: async () => unwrap(await api.GET("/api/v1/admin/settings-schema")) });
  const secrets = useConfigSecrets(kind, kind === "identity");
  const saver = useConfigSaver(kind);
  const [data, setData] = useState<Data>({});
  const [drafts, setDrafts] = useState<Record<string, string>>({});
  const [secret, setSecret] = useState<string | null | undefined>();
  const [error, setError] = useState("");
  useEffect(() => { if (q.data) { setData(q.data.data); setDrafts({}); setSecret(undefined); setError(""); } }, [q.data]);
  if (q.isPending || schema.isPending) return <Spin />;
  if (q.isError || schema.isError) return <QueryError error={q.error ?? schema.error} />;
  const root = schema.data[kind] as Schema;
  function resolve(spec: Schema): Schema {
    if (spec.$ref) return resolve(root.$defs?.[spec.$ref.split("/").pop()!] ?? {});
    if (spec.anyOf) return resolve(spec.anyOf.find((s) => s.type !== "null") ?? {});
    return spec;
  }
  function set(path: string[], value: unknown) {
    setData((old) => {
      const next = structuredClone(old);
      let obj = next;
      for (const p of path.slice(0, -1)) obj = obj[p] as Data;
      obj[path.at(-1)!] = value;
      return next;
    });
  }
  function fields(props: Record<string, Schema>, value: Data, path: string[] = []): ReactNode {
    return Object.entries(props).map(([name, source]) => {
      const spec = resolve(source), full = [...path, name], key = full.join("."), current = value[name];
      const label = t(`settings.business.fields.${name}`, { defaultValue: name });
      let input: ReactNode;
      if (spec.properties) return <Collapse key={key} defaultActiveKey={path.length ? [] : [key]} items={[{ key, label, children: fields(spec.properties, (current ?? {}) as Data, full) }]} />;
      if (name === "schedules") return <Collapse key={key} items={[{ key, label, children: <Space direction="vertical" style={{ width: "100%" }}><Typography.Paragraph>{t("settings.business.scheduleHint")}</Typography.Paragraph>{Object.entries((current ?? {}) as Record<string, string>).map(([task, cron]) => <label key={task}>{t(`settings.business.tasks.${task}`, { defaultValue: task })}<Input value={cron} aria-label={t(`settings.business.tasks.${task}`, { defaultValue: task })} onChange={(e) => set([...full, task], e.target.value)} /></label>)}</Space> }]} />;
      if (spec.enum) input = <Select value={current} options={spec.enum.map((v) => ({ value: v, label: t(`settings.business.values.${v}`, { defaultValue: v }) }))} onChange={(v) => {
        set(full, v);
        if (name === "provider" && v === "entra") { set(["roles_claim"], "roles"); set(["label"], "Microsoft Entra ID"); }
      }} style={{ width: "100%" }} aria-label={label} />;
      else if (spec.type === "boolean") input = <Switch checked={!!current} onChange={(v) => set(full, v)} aria-label={label} />;
      else if (spec.type === "integer" || spec.type === "number") input = <InputNumber value={current as number} min={spec.minimum} max={spec.maximum} precision={spec.type === "integer" ? 0 : undefined} onChange={(v) => set(full, v)} aria-label={label} style={{ width: 200 }} />;
      else if (spec.type === "array" && spec.items?.type === "string") input = <Input.TextArea value={drafts[key] ?? ((current ?? []) as string[]).join("\n")} onChange={(e) => { setDrafts((old) => ({ ...old, [key]: e.target.value })); set(full, e.target.value.split("\n").map((v) => v.trim()).filter(Boolean)); }} autoSize={{ minRows: 2, maxRows: 8 }} aria-label={label} placeholder={t("settings.business.onePerLine")} />;
      else if (spec.type === "object" || spec.type === "array") input = <Input.TextArea value={drafts[key] ?? JSON.stringify(current, null, 2)} onChange={(e) => setDrafts((old) => ({ ...old, [key]: e.target.value }))} autoSize={{ minRows: 2, maxRows: 10 }} aria-label={label} />;
      else input = <Input value={(current ?? "") as string} onChange={(e) => set(full, e.target.value || (source.anyOf?.some((s) => s.type === "null") ? null : ""))} aria-label={label} />;
      return <div key={key} style={{ marginBottom: 16 }}><Typography.Text strong style={{ display: "block", marginBottom: 6 }}>{label}</Typography.Text>{input}</div>;
    });
  }
  async function save(note: string | null) {
    const result = structuredClone(data);
    try {
      for (const [path, text] of Object.entries(drafts)) {
        let obj = result, spec = root;
        const names = path.split(".");
        for (const name of names) spec = resolve(spec.properties?.[name] ?? {});
        if (spec.type === "array" && spec.items?.type === "string") continue;
        for (const name of names.slice(0, -1)) obj = obj[name] as Data;
        obj[names.at(-1)!] = JSON.parse(text);
      }
      setError("");
    } catch { setError(t("settings.business.invalidJson")); return false; }
    return saver.submit({ data: result, base_version: q.data!.version, note, ...(secret !== undefined ? { secrets: { client_secret: secret } } : {}) });
  }
  return <ConfigShell kind={kind} config={q.data} canWrite saver={saver} onSave={save} onReload={() => void q.refetch()}>
    <Alert type="info" showIcon message={t(`settings.business.${kind}Hint`)} />
    {error && <Alert type="error" showIcon message={error} />}
    <form className="oti-config-form" onSubmit={(e) => e.preventDefault()}>
      {fields(root.properties ?? {}, data)}
      {kind === "identity" && <Space direction="vertical" style={{ width: "100%" }}>
        <Typography.Text strong>{t("settings.business.clientSecret")}</Typography.Text>
        <SecretInput label={t("settings.business.clientSecret")} state={secrets.data?.secrets.find((s) => s.name === "client_secret")} draft={secret} onChange={setSecret} disabled={false} keyMissing={secrets.data?.encryption_key !== true} />
      </Space>}
    </form>
  </ConfigShell>;
}
