import { useId } from "react";

/**
 * 「信号示波镜」徽标：同心刻度环 + 旋转扫描扇区 + 依次亮起的回波点。
 * 纯 SVG + CSS 动画（见 index.css 的 .oti-scope*），减少动态效果时静止。
 * blips 为 false 时只画环与扫描（用于侧栏小图标）。
 */
export default function ScopeEmblem({ size = 40, blips = true, className = "" }: { size?: number; blips?: boolean; className?: string }) {
  const id = useId().replace(/:/g, "");
  const ticks = Array.from({ length: 48 }, (_, i) => i);
  const points: [number, number, number][] = [
    [62, 34, 0],
    [30, 58, 1],
    [70, 66, 2],
    [44, 26, 3],
    [56, 78, 4],
  ];
  return (
    <svg className={`oti-scope ${className}`} width={size} height={size} viewBox="0 0 100 100" aria-hidden="true" focusable="false">
      <defs>
        <radialGradient id={`g${id}`} cx="50%" cy="50%" r="50%">
          <stop offset="0%" stopColor="var(--ion)" stopOpacity="0.22" />
          <stop offset="100%" stopColor="var(--ion)" stopOpacity="0" />
        </radialGradient>
        <linearGradient id={`s${id}`} x1="0" y1="0" x2="1" y2="0">
          <stop offset="0%" stopColor="var(--ion)" stopOpacity="0" />
          <stop offset="100%" stopColor="var(--ion)" stopOpacity="0.55" />
        </linearGradient>
      </defs>
      <circle cx="50" cy="50" r="49" fill={`url(#g${id})`} />
      {[46, 34, 22, 10].map((r) => (
        <circle key={r} cx="50" cy="50" r={r} className="oti-scope-ring" />
      ))}
      <line x1="4" y1="50" x2="96" y2="50" className="oti-scope-axis" />
      <line x1="50" y1="4" x2="50" y2="96" className="oti-scope-axis" />
      {size >= 80 &&
        ticks.map((i) => (
          <line key={i} x1="50" y1={i % 4 === 0 ? 1.5 : 2.5} x2="50" y2="4.5" className="oti-scope-tick" transform={`rotate(${i * 7.5} 50 50)`} />
        ))}
      <g className="oti-scope-sweep">
        <path d="M50 50 L50 4 A46 46 0 0 1 82.5 17.5 Z" fill={`url(#s${id})`} />
        <line x1="50" y1="50" x2="82.5" y2="17.5" className="oti-scope-beam" />
      </g>
      {blips &&
        points.map(([x, y, i]) => (
          <g key={i} className="oti-scope-blip" style={{ ["--i" as string]: i }}>
            <circle cx={x} cy={y} r="5" className="oti-scope-blip-halo" />
            <circle cx={x} cy={y} r="1.8" className={i === 2 ? "oti-scope-blip-dot hot" : "oti-scope-blip-dot"} />
          </g>
        ))}
      <circle cx="50" cy="50" r="2.4" className="oti-scope-core" />
    </svg>
  );
}
