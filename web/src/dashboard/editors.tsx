import { listPagination } from "../components/pagination";
import { Alert, Button, Drawer, Form, InputNumber, List, Modal, Select } from "antd";
import { useTranslation } from "react-i18next";
import { CATALOG_BY_TYPE, CATEGORIES, DAY_OPTIONS, METRICS, type Widget, type WidgetDef } from "./catalog";

/** 下拉框不能直接用 null 作值，"跟随全局"在表单里用空字符串表示。 */
const FOLLOW = "";

type FormValues = { days?: number | ""; category?: string; limit?: number | null; metric?: string };

function toForm(params: Widget["params"]): FormValues {
  return {
    days: typeof params.days === "number" ? params.days : FOLLOW,
    category: typeof params.category === "string" ? params.category : FOLLOW,
    limit: typeof params.limit === "number" ? params.limit : null,
    metric: typeof params.metric === "string" ? params.metric : undefined,
  };
}

function fromForm(d: WidgetDef, v: FormValues): Widget["params"] {
  const value = (name: string) => {
    switch (name) {
      case "days":
        return v.days === FOLLOW || v.days === undefined ? null : v.days;
      case "category":
        return v.category ? v.category : null;
      case "limit":
        return v.limit == null ? null : Math.min(v.limit, d.maxLimit);
      default:
        return v.metric ?? "open_critical";
    }
  };
  return Object.fromEntries(d.params.map((p) => [p, value(p)]));
}

export function ParamsModal({ widget, onCancel, onOk }: { widget: Widget | null; onCancel: () => void; onOk: (params: Widget["params"]) => void }) {
  const { t } = useTranslation();
  const [form] = Form.useForm<FormValues>();
  const d = widget ? CATALOG_BY_TYPE[widget.type] : undefined;
  return (
    <Modal open={!!widget && !!d} title={t("dashboard.edit.settings")} onCancel={onCancel} onOk={() => form.submit()} destroyOnHidden>
      {widget && d && (
        <Form form={form} layout="vertical" initialValues={toForm(widget.params)} onFinish={(v) => onOk(fromForm(d, v))}>
          {d.params.includes("metric") && (
            <Form.Item name="metric" label={t("dashboard.edit.paramMetric")}>
              <Select options={METRICS.map((m) => ({ value: m, label: t(`dashboard.metric.${m}`) }))} />
            </Form.Item>
          )}
          {d.params.includes("days") && (
            <Form.Item name="days" label={t("dashboard.edit.paramDays")}>
              <Select
                options={[
                  { value: FOLLOW, label: t("dashboard.edit.followGlobal") },
                  ...DAY_OPTIONS.map((n) => ({ value: n, label: t("dashboard.days", { n }) })),
                ]}
              />
            </Form.Item>
          )}
          {d.params.includes("category") && (
            <Form.Item name="category" label={t("dashboard.edit.paramCategory")}>
              <Select
                options={[
                  { value: FOLLOW, label: t("dashboard.edit.allCategories") },
                  ...CATEGORIES.map((c) => ({ value: c, label: t(`category.${c}`, { defaultValue: c }) })),
                ]}
              />
            </Form.Item>
          )}
          {d.params.includes("limit") && (
            <Form.Item name="limit" label={t("dashboard.edit.paramLimit")}>
              <InputNumber min={1} max={d.maxLimit} precision={0} placeholder={t("dashboard.edit.defaultLimit")} style={{ width: "100%" }} />
            </Form.Item>
          )}
        </Form>
      )}
    </Modal>
  );
}

/** full：已达 30 张上限，所有"添加"按钮不可用。 */
export function AddWidgetDrawer({ open, full, defs, onClose, onAdd }: { open: boolean; full: boolean; defs: WidgetDef[]; onClose: () => void; onAdd: (d: WidgetDef) => void }) {
  const { t } = useTranslation();
  return (
    <Drawer open={open} title={t("dashboard.edit.library")} onClose={onClose}>
      {full && <Alert type="warning" showIcon message={t("dashboard.edit.full")} style={{ marginBottom: 12 }} />}
      <List pagination={listPagination}
        dataSource={defs}
        renderItem={(d) => (
          <List.Item
            data-widget-type={d.type}
            actions={[
              <Button key="add" size="small" disabled={full} onClick={() => onAdd(d)}>
                {t("dashboard.edit.addThis")}
              </Button>,
            ]}
          >
            {t(d.titleKey)}
          </List.Item>
        )}
      />
    </Drawer>
  );
}
