import type { FormInstance } from "antd";
import { useState } from "react";
import { useValidateConfig, type ConfigError, type ConfigKind } from "../api/hooks";

type Json = Record<string, unknown>;

/** Let the server validate and convert every transition between form and YAML. */
export function useYamlMode<V>(kind: ConfigKind, form: FormInstance<V>, conv: { toForm: (data: Json) => V; fromForm: (value: V) => Json }) {
  const validate = useValidateConfig(kind);
  const [mode, setMode] = useState<"form" | "yaml">("form");
  const [yamlText, setYamlText] = useState("");
  const [errors, setErrors] = useState<ConfigError[]>([]);
  const formData = () => conv.fromForm(form.getFieldsValue(true) as V);

  return {
    mode, yamlText, setYamlText, errors, pending: validate.isPending,
    load(data: Json, yaml: string) {
      form.setFieldsValue(conv.toForm(data) as Parameters<FormInstance<V>["setFieldsValue"]>[0]);
      setYamlText(yaml);
      setErrors([]);
    },
    async switchTo(next: "form" | "yaml") {
      if (next === mode) return;
      setErrors([]);
      const result = await validate.mutateAsync(next === "yaml" ? { data: formData() } : { yaml: yamlText });
      if (!result.ok) { setErrors(result.errors ?? []); return; }
      if (next === "yaml") setYamlText(result.yaml ?? "");
      else form.setFieldsValue(conv.toForm(result.data ?? {}) as Parameters<FormInstance<V>["setFieldsValue"]>[0]);
      setMode(next);
    },
    async body(): Promise<{ yaml: string } | { data: Json }> {
      if (mode === "yaml") return { yaml: yamlText };
      await form.validateFields();
      return { data: formData() };
    },
  };
}
