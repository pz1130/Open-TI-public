import { Card, Tabs } from "antd";
import { useTranslation } from "react-i18next";
import { useSearchParams } from "react-router";
import KeywordsTab from "../watchlist/KeywordsTab";
import WatchedDomains from "../watchlist/WatchedDomains";

const TABS = ["keywords", "domains"] as const;
type Tab = (typeof TABS)[number];

export default function WatchlistPage() {
  const { t } = useTranslation();
  const [params, setParams] = useSearchParams();
  const raw = params.get("tab");
  const tab: Tab = TABS.includes(raw as Tab) ? (raw as Tab) : "keywords";
  return (
    <Card title={t("watchlist.title")}>
      <Tabs
        activeKey={tab}
        onChange={(key) => setParams((p) => { p.set("tab", key); return p; }, { replace: true })}
        destroyOnHidden
        items={[
          { key: "keywords", label: t("watchlist.tabs.keywords"), children: <KeywordsTab /> },
          { key: "domains", label: t("watchlist.tabs.domains"), children: <WatchedDomains /> },
        ]}
      />
    </Card>
  );
}
