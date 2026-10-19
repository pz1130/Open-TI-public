import { CloseOutlined, SettingOutlined } from "@ant-design/icons";
import { Button, Card, Space } from "antd";
import type { ReactNode } from "react";
import GridLayout from "react-grid-layout";
import "react-grid-layout/css/styles.css";
import { useTranslation } from "react-i18next";
import { CATALOG_BY_TYPE, GRID_COLS, GRID_MARGIN, ROW_HEIGHT, widgetTitle, type Layout, type Widget } from "./catalog";
import { stackOrder, type GridItem } from "./layout";

export function WidgetFrame({
  widget,
  editing,
  onSettings,
  onRemove,
  children,
}: {
  widget: Widget;
  editing: boolean;
  onSettings: () => void;
  onRemove: () => void;
  children: ReactNode;
}) {
  const { t } = useTranslation();
  const title = widgetTitle(t, widget);
  return (
    <Card
      size="small"
      className="opti-widget"
      data-widget={widget.id}
      title={title}
      extra={
        editing ? (
          <Space size={0} className="opti-widget-actions">
            {(CATALOG_BY_TYPE[widget.type]?.params.length ?? 0) > 0 && (
              <Button type="text" size="small" icon={<SettingOutlined />} aria-label={`${t("dashboard.edit.settings")} ${title}`} onClick={onSettings} />
            )}
            <Button type="text" size="small" danger icon={<CloseOutlined />} aria-label={`${t("dashboard.edit.remove")} ${title}`} onClick={onRemove} />
          </Space>
        ) : undefined
      }
      style={{ height: "100%", display: "flex", flexDirection: "column" }}
      // 指标卡只有 2 行高：收紧上下内边距，不出现滚动条
      styles={{ body: widget.type === "stat" ? { flex: 1, minHeight: 0, overflow: "hidden", paddingBlock: 8 } : { flex: 1, minHeight: 0, overflow: "auto" } }}
    >
      {children}
    </Card>
  );
}

const heightOf = (h: number) => h * ROW_HEIGHT + (h - 1) * GRID_MARGIN;

/**
 * 宽屏用 12 列网格（编辑时可拖动标题栏、拖右下角改大小）；窄屏按行列顺序排成单列，不可编辑。
 * width 由页面用 useContainerWidth 量出。
 */
export function DashboardGrid({
  layout,
  width,
  narrow,
  editing,
  onLayout,
  renderWidget,
}: {
  layout: Layout;
  width: number;
  narrow: boolean;
  editing: boolean;
  /** 网格给出的新坐标；由调用方套到最新的草稿上（applyGrid），不依赖渲染时的 layout。 */
  onLayout: (items: readonly GridItem[]) => void;
  renderWidget: (w: Widget) => ReactNode;
}) {
  if (narrow) {
    return (
      <Space direction="vertical" size={GRID_MARGIN} style={{ width: "100%" }}>
        {stackOrder(layout).map((w) => (
          <div key={w.id} style={{ height: heightOf(w.h) }}>
            {renderWidget(w)}
          </div>
        ))}
      </Space>
    );
  }
  const items = layout.widgets.map((w) => ({
    i: w.id, x: w.x, y: w.y, w: w.w, h: w.h,
    minW: CATALOG_BY_TYPE[w.type]?.minW, minH: CATALOG_BY_TYPE[w.type]?.minH,
  })); // prettier-ignore
  return (
    <GridLayout
      className={editing ? "opti-dashboard-grid opti-dashboard-editing" : "opti-dashboard-grid"}
      width={width}
      layout={items}
      gridConfig={{ cols: GRID_COLS, rowHeight: ROW_HEIGHT, margin: [GRID_MARGIN, GRID_MARGIN], containerPadding: [0, 0] }}
      dragConfig={{ enabled: editing, handle: ".ant-card-head", cancel: ".opti-widget-actions" }}
      resizeConfig={{ enabled: editing, handles: ["se"] }}
      onLayoutChange={(next) => {
        if (editing) onLayout(next);
      }}
    >
      {layout.widgets.map((w) => (
        <div key={w.id}>{renderWidget(w)}</div>
      ))}
    </GridLayout>
  );
}
