import { Space, Tag } from "antd";
import { useTranslation } from "react-i18next";
import type { Schemas } from "../api/client";

type Technique = Schemas["AttackTechnique"];

export default function AttackTags({ techniques }: { techniques: Technique[] }) {
  const { t } = useTranslation();
  if (!techniques.length) return <span>—</span>;
  return (
    <Space wrap>
      {techniques.map((item) => {
        const label = <Tag color="blue">{item.id} {item.name} · {item.tactics.map((tactic) => t(`attack.tactics.${tactic}`, { defaultValue: tactic })).join(", ")}</Tag>;
        if (!/^T\d{4}(?:\.\d{3})?$/.test(item.id)) return <span key={item.id}>{label}</span>;
        const href = `https://attack.mitre.org/techniques/${item.id.replace(".", "/")}/`;
        return <a key={item.id} href={href} target="_blank" rel="noopener noreferrer" onClick={(event) => event.stopPropagation()}>{label}</a>;
      })}
    </Space>
  );
}
