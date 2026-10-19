import { Button, Result, Spin } from "antd";
import { Component, lazy, Suspense, type ComponentType, type ReactNode } from "react";
import { useTranslation } from "react-i18next";

/** 本标签页已经因分块加载失败自动刷新过一次（避免新版本也缺文件时无限刷新）。 */
const RELOADED = "oti-chunk-reload";

function flag(action: "get" | "set" | "clear"): boolean {
  try {
    if (action === "get") return sessionStorage.getItem(RELOADED) !== null;
    if (action === "set") sessionStorage.setItem(RELOADED, "1");
    else sessionStorage.removeItem(RELOADED);
  } catch {
    // 存储不可用时不自动刷新，直接显示加载失败
  }
  return false;
}

const reloadPage = () => window.location.reload();

/**
 * 按需加载页面。发布新版本后，旧页面去取旧文件名的分块会失败：自动刷新一次拿到新版本；
 * 刷新后仍然失败就交给 PageSuspense 显示加载失败。
 */
export function lazyPage<T extends ComponentType>(
  load: () => Promise<{ default: T }>,
  reload: () => void = reloadPage,
) {
  return lazy(async () => {
    try {
      const mod = await load();
      flag("clear");
      return mod;
    } catch (e) {
      if (!flag("get")) {
        flag("set");
        reload();
        return new Promise<never>(() => {}); // 等待刷新，期间保持加载状态
      }
      throw e;
    }
  });
}

function LoadFailed({ reload }: { reload: () => void }) {
  const { t } = useTranslation();
  return (
    <Result
      status="warning"
      title={t("common.pageLoadFailed")}
      subTitle={t("common.pageLoadFailedHint")}
      extra={<Button type="primary" onClick={reload}>{t("common.reloadPage")}</Button>}
    />
  );
}

class Boundary extends Component<{ reload: () => void; children: ReactNode }, { failed: boolean }> {
  state = { failed: false };

  static getDerivedStateFromError() {
    return { failed: true };
  }

  render() {
    return this.state.failed ? <LoadFailed reload={this.props.reload} /> : this.props.children;
  }
}

/** 页面内容区的加载与失败兜底：外壳（菜单、顶栏）不受影响。 */
export function PageSuspense({ children, reload = reloadPage }: { children: ReactNode; reload?: () => void }) {
  return (
    <Boundary reload={reload}>
      <Suspense fallback={<Spin style={{ display: "block", margin: "64px auto" }} />}>{children}</Suspense>
    </Boundary>
  );
}
