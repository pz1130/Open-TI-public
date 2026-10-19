import { Space, Typography } from "antd";

/** 严重级别配色（总览与月报趋势共用）。 */
export const SEVERITY_COLORS = { critical: "#f43f5e", high: "#fb7f3c", medium: "#eab541", low: "#34b98a" };

export interface Series {
  key: string;
  color: string;
}

/** 按日堆叠柱状图（自绘 SVG，不依赖图表库）；每根柱子带 title，悬停可看数值。 */
export function StackedBars({
  data,
  series,
  label,
  height = 160,
}: {
  data: Array<Record<string, number | string>>;
  series: Series[];
  label: string;
  height?: number;
}) {
  const totals = data.map((d) => series.reduce((sum, s) => sum + Number(d[s.key] ?? 0), 0));
  const max = Math.max(1, ...totals);
  const width = 100 / Math.max(1, data.length);
  return (
    <div className="opti-chart-container" style={{ position: "relative", width: "100%" }}>
      <svg
        role="img"
        aria-label={label}
        viewBox={`0 0 100 ${height}`}
        preserveAspectRatio="none"
        width="100%"
        height={height}
        style={{ overflow: "visible" }}
      >
        {data.map((d, i) => {
          const bars = series
            .map((s) => ({ s, h: (Number(d[s.key] ?? 0) / max) * (height - 4) }))
            .filter((b) => b.h > 0);
          const tops = bars.map((_, j) => height - bars.slice(0, j + 1).reduce((acc, b) => acc + b.h, 0));
          return (
            <g key={String(d.day ?? i)} className="opti-chart-bar-group" style={{ ["--i" as string]: i }}>
              <title>{`${String(d.day ?? "")}: ${totals[i]}`}</title>
              {bars.map((b, j) => (
                <rect
                  key={b.s.key}
                  x={i * width + width * 0.12}
                  y={tops[j]}
                  width={width * 0.76}
                  height={b.h}
                  fill={b.s.color}
                  rx={1}
                />
              ))}
            </g>
          );
        })}
      </svg>
    </div>
  );
}

/** 横向排行条。 */
export function BarList({ items, empty }: { items: { name: string; label?: string; count: number }[]; empty: string }) {
  if (!items.length) return <Typography.Text type="secondary">{empty}</Typography.Text>;
  const max = Math.max(1, ...items.map((i) => i.count));
  return (
    <Space direction="vertical" style={{ width: "100%" }} size={8} className="oti-barlist">
      {items.map((i, idx) => (
        <div key={i.name} className="oti-bar-row" style={{ ["--i" as string]: idx }}>
          <span className="oti-bar-label" title={i.label ?? i.name}>
            {i.label ?? i.name}
          </span>
          <div className="oti-bar-track">
            <div className="oti-bar-fill" style={{ width: `${(i.count / max) * 100}%` }} />
          </div>
          <span className="oti-bar-count opti-mono">{i.count}</span>
        </div>
      ))}
    </Space>
  );
}
