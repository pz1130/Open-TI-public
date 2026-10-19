import { useEffect, useLayoutEffect, useRef, useState, useSyncExternalStore, type KeyboardEvent as ReactKeyboardEvent } from "react";
import { Dropdown, Tooltip, type MenuProps } from "antd";
import { CloseOutlined, DownOutlined, LogoutOutlined, MenuFoldOutlined, MenuOutlined, MenuUnfoldOutlined, SearchOutlined } from "@ant-design/icons";
import dayjs from "dayjs";
import { useTranslation } from "react-i18next";
import { Outlet, useLocation, useNavigate } from "react-router";
import { useLogout, type Me } from "../api/hooks";
import { can } from "../auth/perms";
import { PAGES, type PageDef } from "../pages/registry";
import CommandPalette from "../shell/CommandPalette";
import { groupOf, groupPages } from "../shell/navGroups";
import { useCardSpotlight, useClock } from "../shell/motion";
import ScopeEmblem from "../shell/ScopeEmblem";
import QueryError from "./QueryError";
import LanguageSwitch from "./LanguageSwitch";
import ThemeSwitch from "./ThemeSwitch";
import ProjectStatus from "../shell/ProjectStatus";

const COLLAPSE_KEY = "opti.nav.collapsed";
const NARROW_NAV = "(max-width: 900px)";
function subscribeNavigationSize(listener: () => void) {
  const media = window.matchMedia(NARROW_NAV);
  media.addEventListener("change", listener);
  return () => media.removeEventListener("change", listener);
}
const isNarrowNavigation = () => window.matchMedia(NARROW_NAV).matches;

function readCollapsed(): boolean {
  try {
    return localStorage.getItem(COLLAPSE_KEY) === "1";
  } catch {
    return false;
  }
}

/** 本地时区偏移，如 UTC+8、UTC−5:30。 */
function utcOffset(d: Date): string {
  const m = -d.getTimezoneOffset();
  const sign = m >= 0 ? "+" : "−";
  const h = Math.floor(Math.abs(m) / 60);
  const mm = Math.abs(m) % 60;
  return `UTC${sign}${h}${mm ? `:${String(mm).padStart(2, "0")}` : ""}`;
}

function Clock() {
  const { t } = useTranslation();
  const now = useClock();
  return (
    <div className="oti-clock" title={t("shell.localTime")}>
      <span className="oti-clock-dot" />
      <span className="oti-clock-time">{dayjs(now).format("HH:mm:ss")}</span>
      <span className="oti-clock-zone">{utcOffset(now)}</span>
    </div>
  );
}

/**
 * 应用外壳：左侧分组导航（可收起，窄屏变为抽屉）+ 顶栏（当前位置、快速跳转、时钟、主题 / 语言、账号）。
 * 内容区按路由切换做入场动画；背景是静态网格加缓慢漂移的光斑，动效始终播放，不受系统「减少动态效果」设置影响。
 */
export default function AppLayout({ me }: { me: Me }) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const location = useLocation();
  const logout = useLogout();
  useCardSpotlight(true);

  const [collapsed, setCollapsed] = useState(readCollapsed);
  const [drawer, setDrawer] = useState(false);
  const [palette, setPalette] = useState(false);
  const narrow = useSyncExternalStore(subscribeNavigationSize, isNarrowNavigation);
  const sideRef = useRef<HTMLElement>(null);
  const mainRef = useRef<HTMLElement>(null);
  const burgerRef = useRef<HTMLButtonElement>(null);
  const drawerReturnFocus = useRef<"trigger" | "content" | null>(null);
  const drawerOpen = narrow && drawer;

  const closeDrawer = () => {
    drawerReturnFocus.current = "trigger";
    setDrawer(false);
  };

  const navPages = PAGES.filter((p) => p.nav && can(me, p.perm));
  const groups = groupPages(navPages);
  const selected = navPages.find((p) => location.pathname === `/${p.path}` || location.pathname.startsWith(`/${p.path}/`));
  const isDetail = !!selected && location.pathname !== `/${selected.path}`;

  const toggleCollapsed = () => {
    setCollapsed((c) => {
      try {
        localStorage.setItem(COLLAPSE_KEY, c ? "0" : "1");
      } catch {
        // ignore
      }
      return !c;
    });
  };

  const go = (p: PageDef) => {
    if (drawerOpen) drawerReturnFocus.current = "content";
    navigate(`/${p.path}`);
    setDrawer(false);
    setPalette(false);
  };

  // Ctrl/⌘ + K 打开快速跳转
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        if (drawerOpen) closeDrawer();
        setPalette((o) => !o);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [drawerOpen]);

  useLayoutEffect(() => {
    if (drawerOpen) {
      sideRef.current?.removeAttribute("aria-hidden");
      const current = sideRef.current?.querySelector<HTMLButtonElement>(".oti-nav-item[aria-current='page']");
      (current ?? sideRef.current?.querySelector<HTMLButtonElement>(".oti-nav-item"))?.focus();
    } else {
      if (drawerReturnFocus.current === "content") mainRef.current?.focus();
      else if (narrow && (drawerReturnFocus.current === "trigger" || sideRef.current?.contains(document.activeElement))) burgerRef.current?.focus();
      drawerReturnFocus.current = null;
      // Hide only after focus has left the drawer; otherwise Chrome rejects aria-hidden.
      if (narrow) sideRef.current?.setAttribute("aria-hidden", "true");
      else sideRef.current?.removeAttribute("aria-hidden");
    }
    if (!narrow) setDrawer(false);
  }, [drawerOpen, narrow]);

  useEffect(() => {
    if (!drawerOpen) return;
    const previous = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => { document.body.style.overflow = previous; };
  }, [drawerOpen]);

  const handleDrawerKey = (e: ReactKeyboardEvent<HTMLElement>) => {
    if (!drawerOpen) return;
    if (e.key === "Escape") {
      e.preventDefault();
      closeDrawer();
    } else if (e.key === "Tab") {
      const controls = sideRef.current?.querySelectorAll<HTMLElement>("button:not(.oti-collapse):not(:disabled), a[href]");
      const first = controls?.[0], last = controls?.[controls.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last?.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first?.focus(); }
    }
  };

  // 换页后关掉抽屉、回到顶部
  useEffect(() => {
    if (drawerOpen) drawerReturnFocus.current = "content";
    setDrawer(false);
    document.documentElement.scrollTop = 0;
  }, [location.pathname]);

  // 侧栏当前项的滑动指示条：量出当前按钮的位置，用 transform 平移过去
  const navRef = useRef<HTMLElement>(null);
  const [ink, setInk] = useState<{ top: number; height: number } | null>(null);
  useLayoutEffect(() => {
    const el = navRef.current?.querySelector<HTMLElement>(".oti-nav-item.active");
    setInk(el ? { top: el.offsetTop, height: el.offsetHeight } : null);
  }, [selected?.path, collapsed, t, navPages.length]);

  const userMenuItems: MenuProps["items"] = [
    {
      key: "user-info",
      disabled: true,
      className: "oti-user-head",
      label: (
        <div className="oti-user-head-inner">
          <div className="oti-user-head-name">{me.display_name || me.username}</div>
          <div className="oti-user-head-handle">@{me.username}</div>
          <div className="oti-user-head-roles">
            {me.roles.map((r) => (
              <span key={r} className="oti-role-chip">
                {t(`shell.role.${r}`, { defaultValue: r })}
              </span>
            ))}
          </div>
        </div>
      ),
    },
    { type: "divider" },
    ...(me.auth_source === "local" ? [{ key: "password", label: t("access.changePassword"), onClick: () => navigate("/account/password") }] : []),
    {
      key: "logout",
      icon: <LogoutOutlined />,
      label: t("app.logout"),
      danger: true,
      onClick: () => logout.mutate(),
      disabled: logout.isPending,
    },
  ];

  const name = me.display_name || me.username;
  const initial = name.trim().charAt(0).toUpperCase() || "?";
  const pageLabel = selected ? t(selected.labelKey ?? selected.path) : t("app.title");

  return (
    <div className={`oti-shell${collapsed ? " is-collapsed" : ""}${drawerOpen ? " is-drawer" : ""}`}>
      <a className="oti-skip" href="#oti-main">
        {t("shell.skip")}
      </a>
      <div className="oti-ambient" aria-hidden="true">
        <span className="oti-orb oti-orb-a" />
        <span className="oti-orb oti-orb-b" />
        <span className="oti-orb oti-orb-c" />
      </div>

      <aside className="oti-side" id="oti-side-navigation" ref={sideRef}
        inert={narrow && !drawerOpen}
        role={narrow ? "dialog" : undefined} aria-modal={drawerOpen ? true : undefined}
        aria-label={t("nav.menu")} onKeyDown={handleDrawerKey}>
        <div className="oti-side-inner">
          <button type="button" className="oti-brand" onClick={() => navPages[0] && go(navPages[0])} aria-label={t("app.title")}>
            <ScopeEmblem size={34} blips={false} />
            <span className="oti-brand-text">
              <span className="oti-brand-name">{t("app.title")}</span>
              <span className="oti-brand-sub">Threat Intelligence</span>
            </span>
          </button>
          <button type="button" hidden={!narrow} className="oti-icon-btn oti-drawer-close" onClick={closeDrawer} aria-label={t("shell.closeNav")}><CloseOutlined /></button>

          <nav className="oti-nav" ref={navRef} aria-label={t("nav.menu")}>
            {ink && <span className="oti-nav-ink" style={{ transform: `translateY(${ink.top}px)`, height: ink.height }} aria-hidden="true" />}
            {groups.map((g, gi) => (
              <div className="oti-nav-group" key={g.group} style={{ ["--g" as string]: gi }}>
                <div className="oti-nav-group-label">{t(`shell.group.${g.group}`)}</div>
                {g.pages.map((p, i) => {
                  const active = selected?.path === p.path;
                  const label = t(p.labelKey ?? p.path);
                  const btn = (
                    <button
                      key={p.path}
                      type="button"
                      className={`oti-nav-item${active ? " active" : ""}`}
                      aria-current={active ? "page" : undefined}
                      aria-label={label}
                      style={{ ["--i" as string]: i }}
                      onClick={() => { if (!narrow || drawerOpen) go(p); }}
                    >
                      <span className="oti-nav-icon">{p.icon}</span>
                      <span className="oti-nav-label">{label}</span>
                    </button>
                  );
                  return collapsed ? (
                    <Tooltip key={p.path} title={label} placement="right">
                      {btn}
                    </Tooltip>
                  ) : (
                    btn
                  );
                })}
              </div>
            ))}
          </nav>

          <div className="oti-side-foot">
            <div className="oti-session">
              <span className="oti-session-label">{t("shell.session")}</span>
              <span className="oti-session-roles">{me.roles.map((r) => t(`shell.role.${r}`, { defaultValue: r })).join(" · ")}</span>
            </div>
            <button
              type="button"
              hidden={narrow}
              className="oti-collapse"
              onClick={toggleCollapsed}
              aria-label={collapsed ? t("shell.expand") : t("shell.collapse")}
              title={collapsed ? t("shell.expand") : t("shell.collapse")}
            >
              {collapsed ? <MenuUnfoldOutlined /> : <MenuFoldOutlined />}
            </button>
          </div>
        </div>
      </aside>
      <div className="oti-scrim" onClick={closeDrawer} aria-hidden="true" />

      <div className="oti-main" inert={drawerOpen}>
        <header className="oti-topbar">
          <button type="button" ref={burgerRef} hidden={!narrow} className="oti-icon-btn oti-burger" onClick={() => { if (narrow) setDrawer(true); }} aria-label={t("shell.openNav")}
            aria-expanded={drawerOpen} aria-controls="oti-side-navigation" aria-haspopup="dialog">
            <MenuOutlined />
          </button>
          <div className="oti-crumbs" key={location.pathname}>
            {selected && <span className="oti-crumb-group">{t(`shell.group.${groupOf(selected)}`)}</span>}
            {selected && <span className="oti-crumb-sep">/</span>}
            <span className={isDetail ? "oti-crumb-page is-link" : "oti-crumb-page"} onClick={isDetail && selected ? () => go(selected) : undefined}>
              {pageLabel}
            </span>
            {isDetail && (
              <>
                <span className="oti-crumb-sep">/</span>
                <span className="oti-crumb-detail opti-mono">{location.pathname.startsWith("/settings/")
                  ? t(`settings.tabs.${location.pathname.split("/").pop()}`, { defaultValue: location.pathname.split("/").pop() })
                  : location.pathname.split("/").pop()}</span>
              </>
            )}
          </div>

          <button type="button" className="oti-jump" onClick={() => setPalette(true)}>
            <SearchOutlined />
            <span className="oti-jump-text">{t("shell.palette.trigger")}</span>
            <kbd>Ctrl K</kbd>
          </button>

          <div className="oti-top-right">
            <ProjectStatus admin={can(me, "projects:write")} />
            <Clock />
            <ThemeSwitch />
            <LanguageSwitch />
            <Dropdown menu={{ items: userMenuItems }} trigger={["click"]} placement="bottomRight" overlayClassName="oti-user-menu">
              <button type="button" className="oti-operator" title={t("app.accountMenu")}>
                <span className="oti-avatar">{initial}</span>
                <span className="oti-operator-name">{name}</span>
                <DownOutlined className="oti-operator-caret" />
              </button>
            </Dropdown>
          </div>
          <span className="oti-route-bar" key={`bar-${location.pathname}`} aria-hidden="true" />
        </header>

        <main className="oti-content" id="oti-main" ref={mainRef} tabIndex={-1}>
          <QueryError error={logout.error} />
          <div className="oti-page" key={location.pathname}>
            <Outlet />
          </div>
        </main>
      </div>

      <CommandPalette open={palette} pages={navPages} onClose={() => setPalette(false)} onGo={go} />
    </div>
  );
}
