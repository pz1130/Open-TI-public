import { useEffect, useRef, type CSSProperties } from "react";
import { startRadar, type RadarOptions } from "./radarEngine";

/**
 * Animated radar scope (canvas). Decorative: aria-hidden.
 * Size comes from CSS (width/height on the className or style).
 * Colours: --radar-accent / --radar-hot / --radar-line on the element or an ancestor.
 */
export default function Radar({ className = "", style, ...opts }: RadarOptions & { className?: string; style?: CSSProperties }) {
  const ref = useRef<HTMLCanvasElement>(null);
  const key = JSON.stringify(opts);
  useEffect(() => {
    const el = ref.current;
    // jsdom (unit tests) has no canvas implementation
    if (!el || /jsdom/i.test(navigator.userAgent)) return;
    return startRadar(el, opts);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);
  return <canvas ref={ref} className={`radar ${className}`} style={style} aria-hidden="true" />;
}
