import { Alert, App, Button, Empty, Popconfirm, Segmented, Space, Spin, Tag, Typography } from "antd";
import { useMemo, useRef, useState } from "react";
import { useContainerWidth } from "react-grid-layout";
import { useTranslation } from "react-i18next";
import { errorMessage } from "../api/client";
import {
  useClearDefaultLayout,
  useDashboardLayout,
  useDefaultLayout,
  useMe,
  useResetLayout,
  useSaveDefaultLayout,
  useSaveLayout,
} from "../api/hooks";
import { can } from "../auth/perms";
import { BUILTIN_LAYOUT, CATALOG, CATALOG_BY_TYPE, DAY_OPTIONS, MAX_WIDGETS, type Layout, type Widget, type WidgetDef } from "../dashboard/catalog";
import { DashboardGrid, WidgetFrame } from "../dashboard/DashboardGrid";
import { AddWidgetDrawer, ParamsModal } from "../dashboard/editors";
import { addWidget, applyGrid, normalize, removeWidget, setParams, starterLayout } from "../dashboard/layout";
import { WIDGETS } from "../dashboard/widgets";
import Radar from "../shell/Radar";

/** 窄于此宽度时单列显示、不能编辑。 */
const NARROW_WIDTH = 768;

/** daysBefore：进入编辑前页面上的天数，取消编辑时还原。 */
type Editing = { target: "user" | "default"; draft: Layout; daysBefore: number | null };

/** 总览（设计文档 14）：卡片布局可按人自定义，platform_admin 可设置机构默认布局。域名只作为文本显示。 */
export default function DashboardPage() {
  const { t } = useTranslation();
  const { message } = App.useApp();
  const me = useMe().data;
  const layoutQ = useDashboardLayout();
  const canDefault = can(me, "dashboard:default");
  const defaultQ = useDefaultLayout(canDefault);
  const saveLayout = useSaveLayout();
  const resetLayout = useResetLayout();
  const saveDefault = useSaveDefaultLayout();
  const clearDefault = useClearDefaultLayout();
  // 先量出容器宽度再渲染网格，避免首屏按窄屏单列闪一下
  const { width, containerRef, mounted } = useContainerWidth({ measureBeforeMount: true });

  const [days, setDays] = useState<number | null>(null); // null：用布局里保存的天数
  const [editing, setEditing] = useState<Editing | null>(null);
  const [paramsFor, setParamsFor] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);

  const allowed = (d: WidgetDef) => can(me, d.perm);
  const saved = layoutQ.data?.layout ?? BUILTIN_LAYOUT;
  const source = layoutQ.data?.source;
  const view = useMemo(() => {
    const own = normalize(saved, allowed);
    // 个人布局清空是用户自己的选择；内置 / 机构默认对他一张不剩时给出有权限的起步卡片
    return own.widgets.length === 0 && source !== "user" ? starterLayout(allowed) : own;
  }, [saved, me, source]);
  const shown = editing?.draft ?? view;
  const effectiveDays = days ?? shown.days;
  const narrow = width < NARROW_WIDTH;
  // 拿到过布局就一直按它显示；只有从没拿到过时才提示并退回内置布局（后台刷新失败不算）
  const ready = layoutQ.data !== undefined;
  const layoutFailed = layoutQ.isError && !ready;
  const onError = (e: unknown) => void message.error(t("common.error", { message: errorMessage(e) }));
  const edit = (fn: (l: Layout) => Layout) =>
    setEditing((e) => {
      if (!e) return e;
      const draft = fn(e.draft);
      return draft === e.draft ? e : { ...e, draft };
    });
  const finish = (text: string) => {
    setEditing(null);
    setDays(null);
    void message.success(text);
  };

  const cancel = () => {
    if (editing) setDays(editing.daysBefore);
    setEditing(null);
  };

  // 天数随个人布局保存：同一时间只发一个请求，保存中再切换的只记下最新值，上一个完成后再保存，避免乱序
  const savingDays = useRef(false);
  const queuedDays = useRef<number | null>(null);
  const persistDays = (n: number) => {
    if (savingDays.current) {
      queuedDays.current = n;
      return;
    }
    savingDays.current = true;
    saveLayout.mutate(
      { ...view, days: n },
      {
        onError,
        onSettled: () => {
          savingDays.current = false;
          const next = queuedDays.current;
          queuedDays.current = null;
          if (next !== null && next !== n) persistDays(next);
        },
      },
    );
  };

  const changeDays = (n: number) => {
    setDays(n);
    if (editing) edit((l) => ({ ...l, days: n }));
    else if (source === "user") persistDays(n);
  };

  const renderWidget = (w: Widget) => {
    const def = CATALOG_BY_TYPE[w.type];
    const Body = WIDGETS[w.type];
    return (
      <WidgetFrame widget={w} editing={!!editing} onSettings={() => setParamsFor(w.id)} onRemove={() => edit((l) => removeWidget(l, w.id))}>
        {/* 编辑机构默认时可能有自己看不到数据的卡片：只显示占位，不发请求 */}
        {def && Body && allowed(def) ? <Body widget={w} days={effectiveDays} /> : <Typography.Text type="secondary">{t("dashboard.edit.noPermission")}</Typography.Text>}
      </WidgetFrame>
    );
  };

  const range = (
    <Segmented
      className="opti-range-picker"
      // 布局加载完之前不知道天数要不要随个人布局保存，先不让切换
      disabled={layoutQ.isPending}
      value={effectiveDays}
      onChange={(v) => changeDays(Number(v))}
      options={DAY_OPTIONS.map((n) => ({ value: n, label: t("dashboard.days", { n }) }))}
    />
  );

  let toolbar;
  if (!editing) {
    toolbar = (
      <Space wrap>
        {range}
        {ready && !narrow && (
          <Button onClick={() => setEditing({ target: "user", draft: { ...view, days: effectiveDays }, daysBefore: days })}>{t("dashboard.edit.edit")}</Button>
        )}
        {ready && !narrow && canDefault && (
          <Button
            disabled={!defaultQ.isSuccess}
            onClick={() => {
              // 保留机构默认原来的天数，不能用管理员自己页面上的天数覆盖
              setDays(null);
              setEditing({ target: "default", draft: normalize(defaultQ.data?.layout ?? BUILTIN_LAYOUT, () => true), daysBefore: days });
            }}
          >
            {t("dashboard.edit.editDefault")}
          </Button>
        )}
      </Space>
    );
  } else if (editing.target === "user") {
    toolbar = (
      <Space wrap>
        {range}
        <Button onClick={() => setAdding(true)}>{t("dashboard.edit.add")}</Button>
        <Button type="primary" loading={saveLayout.isPending} onClick={() => saveLayout.mutate(editing.draft, { onSuccess: () => finish(t("dashboard.edit.saved")), onError })}>
          {t("dashboard.edit.save")}
        </Button>
        <Button onClick={cancel}>{t("dashboard.edit.cancel")}</Button>
        <Popconfirm title={t("dashboard.edit.resetConfirm")} onConfirm={() => resetLayout.mutate(undefined, { onSuccess: () => finish(t("dashboard.edit.resetDone")), onError })}>
          <Button danger loading={resetLayout.isPending}>{t("dashboard.edit.reset")}</Button>
        </Popconfirm>
      </Space>
    );
  } else {
    toolbar = (
      <Space wrap>
        <Tag color="purple">{t("dashboard.edit.editingDefault")}</Tag>
        {range}
        <Button onClick={() => setAdding(true)}>{t("dashboard.edit.add")}</Button>
        <Popconfirm title={t("dashboard.edit.saveDefaultConfirm")} onConfirm={() => saveDefault.mutate(editing.draft, { onSuccess: () => finish(t("dashboard.edit.defaultSaved")), onError })}>
          <Button type="primary" loading={saveDefault.isPending}>{t("dashboard.edit.saveDefault")}</Button>
        </Popconfirm>
        <Button onClick={cancel}>{t("dashboard.edit.cancel")}</Button>
        <Popconfirm title={t("dashboard.edit.clearDefaultConfirm")} onConfirm={() => clearDefault.mutate(undefined, { onSuccess: () => finish(t("dashboard.edit.defaultCleared")), onError })}>
          <Button danger loading={clearDefault.isPending}>{t("dashboard.edit.clearDefault")}</Button>
        </Popconfirm>
      </Space>
    );
  }

  const target = paramsFor ? shown.widgets.find((w) => w.id === paramsFor) ?? null : null;
  return (
    <div className="oti-dashboard" style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <section className={editing ? "oti-hero is-editing" : "oti-hero"}>
        <div className="oti-hero-scope" aria-hidden="true">
          <Radar className="oti-radar-hero" blips={6} period={5} />
        </div>
        <div className="oti-hero-text">
          <div className="oti-eyebrow">{t("dashboardHero.eyebrow")}</div>
          <h1 className="oti-hero-title">{t("dashboard.title")}</h1>
          <div className="oti-hero-sub">
            {me && <span>{t("dashboardHero.greeting", { name: me.display_name || me.username })}</span>}
            <span className="oti-hero-range opti-mono">{t("dashboardHero.range", { n: effectiveDays })}</span>
          </div>
        </div>
        <div className="oti-hero-tools">{toolbar}</div>
      </section>
      {layoutFailed && <Alert type="warning" showIcon message={t("dashboard.edit.layoutError")} />}
      <div ref={containerRef}>
        {layoutQ.isPending || !mounted ? (
          <Spin />
        ) : shown.widgets.length === 0 ? (
          <Empty description={t("dashboard.edit.empty")} />
        ) : (
          <DashboardGrid layout={shown} width={width} narrow={narrow} editing={!!editing} onLayout={(items) => edit((l) => applyGrid(l, items))} renderWidget={renderWidget} />
        )}
      </div>
      <ParamsModal
        widget={target}
        onCancel={() => setParamsFor(null)}
        onOk={(params) => {
          if (paramsFor) edit((l) => setParams(l, paramsFor, params));
          setParamsFor(null);
        }}
      />
      <AddWidgetDrawer
        open={adding}
        full={(editing?.draft.widgets.length ?? 0) >= MAX_WIDGETS}
        defs={editing?.target === "default" ? CATALOG : CATALOG.filter(allowed)}
        onClose={() => setAdding(false)}
        onAdd={(d) => {
          edit((l) => addWidget(l, d));
          setAdding(false);
        }}
      />
    </div>
  );
}
