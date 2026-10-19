import { Table } from "antd";
import { useTranslation } from "react-i18next";

export default function ScoreBreakdown({ breakdown, total }: { breakdown: Record<string, number>; total: number }) {
  const { t } = useTranslation();
  const rows = Object.entries(breakdown).map(([factor, value]) => ({ factor, value }));
  return (
    <Table
      size="small"
      rowKey="factor"
      pagination={false}
      dataSource={rows}
      columns={[
        { dataIndex: "factor", render: (f: string) => t(`factor.${f}`, { defaultValue: f }) },
        { dataIndex: "value", align: "right", render: (v: number) => (v > 0 ? `+${v}` : String(v)) },
      ]}
      showHeader={false}
      summary={() => (
        <Table.Summary.Row>
          <Table.Summary.Cell index={0}>{t("detail.currentScore")}</Table.Summary.Cell>
          <Table.Summary.Cell index={1} align="right">
            <strong>{total}</strong>
          </Table.Summary.Cell>
        </Table.Summary.Row>
      )}
    />
  );
}
