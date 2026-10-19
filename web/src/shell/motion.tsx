import { useEffect, useState, type ReactNode } from "react";

/**
 * 数字逐位滚入：文字始终是最终值（读屏与测试读到的就是真实数字），
 * 只用 CSS 让每一位从下方错峰滚上来。
 */
export function RollingNumber({ value }: { value: ReactNode }) {
  if (typeof value !== "string" && typeof value !== "number") return <>{value}</>;
  const chars = String(value).split("");
  return (
    <span className="oti-roll">
      {chars.map((c, i) => (
        <span key={i} className="oti-roll-digit" style={{ ["--i" as string]: i }}>
          {c}
        </span>
      ))}
    </span>
  );
}

/**
 * 卡片聚光：指针在 .ant-card 上移动时写入 --mx/--my，CSS 用它画一圈跟随指针的柔光。
 * 全局只挂一个监听器，按帧节流。
 */
export function useCardSpotlight(enabled: boolean) {
  useEffect(() => {
    if (!enabled) return;
    let frame = 0;
    let last: PointerEvent | null = null;
    const apply = () => {
      frame = 0;
      const e = last;
      if (!e) return;
      const card = (e.target as Element | null)?.closest?.(".ant-card") as HTMLElement | null;
      if (!card) return;
      const r = card.getBoundingClientRect();
      card.style.setProperty("--mx", `${e.clientX - r.left}px`);
      card.style.setProperty("--my", `${e.clientY - r.top}px`);
    };
    const onMove = (e: PointerEvent) => {
      last = e;
      if (!frame) frame = requestAnimationFrame(apply);
    };
    window.addEventListener("pointermove", onMove, { passive: true });
    return () => {
      window.removeEventListener("pointermove", onMove);
      if (frame) cancelAnimationFrame(frame);
    };
  }, [enabled]);
}

/** 每秒更新的本地时间（状态栏时钟）。 */
export function useClock(): Date {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const id = window.setInterval(() => setNow(new Date()), 1000);
    return () => window.clearInterval(id);
  }, []);
  return now;
}
