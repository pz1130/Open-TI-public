import { Alert, Card, Descriptions, Space, Tag, Typography } from "antd";
import { useTranslation } from "react-i18next";
import DomainText from "./DomainText";
import { fmtTime } from "./format";

interface LeakPost {
  group: string;
  victim: string;
  domain: string | null;
  country: string | null;
  activity: string | null;
  discovered: string;
  published: string | null;
  sources: string[];
  links: string[];
  other_links: string[];
  description: string;
}

interface MatchedParty {
  kind: string;
  id: string;
  name: string;
  tier: string;
  owner: string;
  how: string;
  detail: string;
}

function safeLink(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "https:" && !url.username && !url.password;
  } catch {
    return false;
  }
}

/** 勒索泄露站帖子（设计文档 4.6）。只有白名单聚合站链接可点击；泄露站地址只作为文本显示。 */
export default function LeakPostCard({ match }: { match: Record<string, unknown> }) {
  const { t } = useTranslation();
  const post = match.post as LeakPost | undefined;
  if (!post) return null;
  const parties = (match.parties as MatchedParty[] | undefined) ?? [];
  return (
    <Card title={t("leak.title")}>
      <Space direction="vertical" style={{ width: "100%" }}>
        {parties.map((p) => (
          <Alert
            key={`${p.kind}:${p.id}`}
            type={p.kind === "self" ? "error" : "warning"}
            showIcon
            message={
              p.kind === "self"
                ? t("leak.self", { name: p.name })
                : t("leak.vendor", { name: p.name, tier: t(`leak.tier.${p.tier}`, { defaultValue: p.tier }) })
            }
            description={`${t(`leak.how.${p.how}`, { defaultValue: p.how })}：${p.detail}${p.owner ? ` · ${t("leak.owner")}：${p.owner}` : ""}`}
          />
        ))}
        <Descriptions
          column={{ xs: 1, md: 2 }}
          items={[
            { key: "victim", label: t("leak.victim"), children: post.victim },
            { key: "group", label: t("leak.group"), children: <Tag color="red">{post.group}</Tag> },
            { key: "discovered", label: t("leak.discovered"), children: fmtTime(post.discovered) },
            { key: "domain", label: t("leak.domain"), children: post.domain ? <DomainText value={post.domain} /> : "-" },
            { key: "profile", label: t("leak.profile"), children: [post.country, post.activity].filter(Boolean).join(" · ") || "-" },
            { key: "sources", label: t("leak.sources"), children: post.sources.join(", ") },
          ]}
        />
        {post.description && (
          <Typography.Paragraph ellipsis={{ rows: 4, expandable: true }}>{post.description}</Typography.Paragraph>
        )}
        {post.links.filter(safeLink).map((u) => (
          <a key={u} href={u} target="_blank" rel="noopener noreferrer">
            {u}
          </a>
        ))}
        {post.other_links.map((u) => (
          <Typography.Text key={u} type="secondary" className="opti-mono">
            {u}
          </Typography.Text>
        ))}
        <Typography.Text type="secondary">{t("leak.policy")}</Typography.Text>
      </Space>
    </Card>
  );
}
