import { Alert, Button, Card, Col, Input, Row, Segmented, Select, Space, Spin, Tag, Typography } from "antd";
import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { useConfig, useMe, useTemplatePreview } from "../api/hooks";
import { can } from "../auth/perms";
import QueryError from "../components/QueryError";
import ConfigShell from "./ConfigShell";
import { useConfigSaver } from "./useConfigSaver";

const LANGS = ["zh-CN", "en-US"] as const;
const KINDS = ["registrar", "hosting", "cdn", "report", "platform"] as const;
const PLACEHOLDERS = ["domain", "url", "ips", "category", "first_seen", "evidence", "detail", "target_name",
  "org_name", "org_short_name", "org_website", "org_contact", "legal_statement", "signature", "date"];
type Drafts = Record<string, Record<string, string>>;

export default function TemplatesTab() {
  const { t } = useTranslation();
  const me = useMe();
  const query = useConfig("takedown_templates");
  const saver = useConfigSaver("takedown_templates");
  const preview = useTemplatePreview();
  const [drafts, setDrafts] = useState<Drafts>({});
  const [lang, setLang] = useState<(typeof LANGS)[number]>("zh-CN");
  const [kind, setKind] = useState<(typeof KINDS)[number]>("registrar");
  const ref = useRef<HTMLTextAreaElement | null>(null);
  const canWrite = can(me.data, "config:write");
  const saved = (query.data?.data ?? {}) as Drafts;
  const text = drafts[lang]?.[kind] ?? "";

  useEffect(() => { if (query.data) setDrafts(structuredClone(query.data.data as Drafts)); }, [query.data]);
  useEffect(() => {
    if (!query.data) return;
    const timer = setTimeout(() => preview.mutate({ language: lang, kind, text }), 500);
    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [text, lang, kind, query.data]);

  if (query.isPending) return <Spin />;
  if (query.isError) return <QueryError error={query.error} />;
  const config = query.data;
  const builtin = (config.builtin ?? {}) as Drafts;
  const setText = (value: string) => setDrafts((current) => ({ ...current, [lang]: { ...current[lang], [kind]: value } }));
  const insert = (name: string) => {
    const el = ref.current;
    const start = el?.selectionStart ?? text.length;
    setText(`${text.slice(0, start)}$${name}${text.slice(el?.selectionEnd ?? start)}`);
  };
  const dirty = (language: string, templateKind: string) => drafts[language]?.[templateKind] !== saved[language]?.[templateKind];

  return <ConfigShell kind="takedown_templates" config={config} canWrite={canWrite} saver={saver}
    onReload={() => { void query.refetch(); }}
    onSave={async (note) => saver.submit({ data: drafts, note, base_version: config.version })}>
    <Space wrap>
      <Select value={lang} onChange={setLang} style={{ width: 120 }} options={LANGS.map((value) => ({ value, label: value }))} />
      <Segmented value={kind} onChange={(value) => setKind(value as (typeof KINDS)[number])}
        options={KINDS.map((value) => ({ value, label: `${t(`settings.takedown.slaKind.${value}`).replace(/ SLA.*$/, "")}${dirty(lang, value) ? " ●" : ""}` }))} />
    </Space>
    <Row gutter={16}>
      <Col xs={24} lg={12}>
        <Input.TextArea ref={(element) => { ref.current = element?.resizableTextArea?.textArea ?? null; }}
          aria-label={t("settings.templates.editor")} className="opti-mono" rows={22}
          value={text} readOnly={!canWrite} onChange={(event) => setText(event.target.value)} />
        {canWrite && <Space wrap size={4} style={{ marginTop: 8 }}>
          {PLACEHOLDERS.map((name) => <Button key={name} size="small" onClick={() => insert(name)}>{`$${name}`}</Button>)}
          <Button size="small" danger onClick={() => setText(builtin[lang]?.[kind] ?? "")}>{t("settings.templates.restore")}</Button>
        </Space>}
      </Col>
      <Col xs={24} lg={12}>
        <Card size="small" title={t("settings.templates.preview")}>
          {preview.data?.errors.map((error) => <Alert key={error} type="error" showIcon message={error} style={{ marginBottom: 8 }} />)}
          {preview.data && <>
            <Typography.Text strong>{t("settings.templates.subject")}：</Typography.Text>
            <Typography.Text>{preview.data.subject}</Typography.Text>
            <pre className="oti-config-pre" style={{ marginTop: 8 }}>{preview.data.body}</pre>
            <Tag>{t("settings.templates.sample")}</Tag>
          </>}
        </Card>
      </Col>
    </Row>
  </ConfigShell>;
}
