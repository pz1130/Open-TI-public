import { Layout, Menu, Select, Spin, Typography } from "antd";
import { useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { useLocation, useNavigate } from "react-router";
import { useMe } from "../api/hooks";
import { can } from "../auth/perms";
import { SECTIONS } from "../settings/sections";

export default function SettingsPage() {
  const { t } = useTranslation();
  const me = useMe();
  const location = useLocation();
  const navigate = useNavigate();
  const [visited, setVisited] = useState<string[]>([]);
  const visible = useMemo(
    () => SECTIONS.map((section) => ({ ...section, items: section.items.filter((item) => can(me.data, item.perm ?? "config:read")) })).filter((section) => section.items.length),
    [me.data],
  );
  const all = visible.flatMap((section) => section.items);
  const requested = location.pathname.split("/")[2];
  const active = all.find((item) => item.kind === requested) ?? all[0];
  useEffect(() => {
    if (active && !visited.includes(active.kind)) setVisited((items) => [...items, active.kind]);
  }, [active, visited]);
  if (me.isPending) return <Spin />;
  if (!me.data || !active) return null;
  const mounted = new Set([...visited, active.kind]);
  return (
    <>
      <Typography.Title level={3}>{t("settings.title")}</Typography.Title>
      <Layout className="oti-settings">
        <Layout.Sider width={200} theme="light">
          <Menu mode="inline" selectedKeys={[active.kind]}
            onClick={(e) => navigate(`/settings/${e.key}`)}
            items={visible.map((section) => ({
              type: "group" as const, key: section.group, label: t(`settings.groups.${section.group}`),
              children: section.items.map((item) => ({ key: item.kind, label: t(`settings.tabs.${item.kind}`) })),
            }))} />
        </Layout.Sider>
        <Select className="oti-settings-mobile-nav" value={active.kind} aria-label={t("settings.chooseSection")}
          onChange={(kind) => navigate(`/settings/${kind}`)}
          options={visible.map((section) => ({ label: t(`settings.groups.${section.group}`),
            options: section.items.map((item) => ({ value: item.kind, label: t(`settings.tabs.${item.kind}`) })),
          }))} />
        <Layout.Content className="oti-settings-content">
          {all.filter((item) => mounted.has(item.kind)).map((item) => (
            <div key={item.kind} hidden={item.kind !== active.kind} data-testid={item.kind === active.kind ? "settings-active" : undefined}>{item.element}</div>
          ))}
        </Layout.Content>
      </Layout>
    </>
  );
}
