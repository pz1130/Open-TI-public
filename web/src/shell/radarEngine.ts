/**
 * Radar scope renderer — canvas + requestAnimationFrame, no dependencies.
 *
 * - continuous sweep with a fading conic trail and a glowing beam
 * - concentric range rings, rings pulsing outward from the centre
 * - contacts ("blips") that light up when the beam passes and then fade;
 *   faded contacts occasionally re-acquire at a new position
 * - crosshair, bearing ticks, optional faint range labels
 * - colours come from CSS custom properties on the canvas (theme aware):
 *   --radar-accent, --radar-hot, --radar-line
 * - pauses while the tab is hidden or the canvas is off-screen;
 *   it always animates, regardless of the OS reduced-motion setting.
 */

export interface RadarOptions {
  blips?: number;
  labels?: string[] | null;
  /** seconds per revolution */
  period?: number;
  /** fraction of blips drawn in the "hot" colour */
  hotRatio?: number;
  /** draw bearing ticks / labels (turn off for tiny emblems) */
  detail?: boolean;
}

interface Blip { a: number; r: number; hot: boolean; size: number; seen: number }

const TAU = Math.PI * 2;

function rng(seed: number) {
  let s = seed >>> 0;
  return () => {
    s = (s * 1664525 + 1013904223) >>> 0;
    return s / 4294967296;
  };
}

export function startRadar(canvas: HTMLCanvasElement, opts: RadarOptions = {}): () => void {
  const { blips: nBlips = 7, labels = null, period = 4.2, hotRatio = 0.25, detail = true } = opts;
  const ctx = canvas.getContext("2d");
  if (!ctx) return () => {};
  const rand = rng(0x5eed + nBlips * 97);
  const omega = TAU / period;

  const place = (b: Partial<Blip>, hot: boolean): Blip => ({
    a: rand() * TAU,
    r: 0.22 + rand() * 0.68,
    hot,
    size: 0.9 + rand() * 0.8,
    seen: b.seen ?? 0,
  });
  const blips: Blip[] = Array.from({ length: nBlips }, (_, i) => place({}, i < Math.round(nBlips * hotRatio)));

  // --- colours -------------------------------------------------------------
  let accent = [139, 147, 255];
  let hot = [244, 63, 94];
  let line = [139, 147, 255];
  const toRgb = (css: string, fallback: number[]) => {
    if (!css) return fallback;
    ctx.fillStyle = "#000";
    ctx.fillStyle = css.trim();
    const v = String(ctx.fillStyle);
    if (v.startsWith("#")) return [1, 3, 5].map((i) => parseInt(v.slice(i, i + 2), 16));
    const m = v.match(/[\d.]+/g);
    return m ? m.slice(0, 3).map(Number) : fallback;
  };
  const readColours = () => {
    const cs = getComputedStyle(canvas);
    accent = toRgb(cs.getPropertyValue("--radar-accent"), accent);
    hot = toRgb(cs.getPropertyValue("--radar-hot"), hot);
    line = toRgb(cs.getPropertyValue("--radar-line") || cs.getPropertyValue("--radar-accent"), line);
  };
  const rgba = (c: number[], a: number) => `rgba(${c[0]},${c[1]},${c[2]},${Math.max(0, Math.min(1, a))})`;

  // --- sizing --------------------------------------------------------------
  let W = 0, H = 0, dpr = 1;
  const resize = () => {
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    const w = canvas.clientWidth, h = canvas.clientHeight;
    if (!w || !h) return;
    if (w * dpr !== W || h * dpr !== H) {
      W = canvas.width = Math.round(w * dpr);
      H = canvas.height = Math.round(h * dpr);
    }
  };

  // --- drawing -------------------------------------------------------------
  const draw = (t: number, still: boolean) => {
    if (!W) resize();
    if (!W) return;
    const cx = W / 2, cy = H / 2;
    const R = Math.min(W, H) / 2 - 2 * dpr;
    const beam = still ? -Math.PI / 4 : (t * omega) % TAU - Math.PI / 2;
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.clearRect(0, 0, W, H);

    // backdrop glow
    const bg = ctx.createRadialGradient(cx, cy, 0, cx, cy, R);
    bg.addColorStop(0, rgba(accent, 0.10));
    bg.addColorStop(0.7, rgba(accent, 0.03));
    bg.addColorStop(1, rgba(accent, 0));
    ctx.fillStyle = bg;
    ctx.beginPath(); ctx.arc(cx, cy, R, 0, TAU); ctx.fill();

    // crosshair + diagonals
    ctx.lineWidth = dpr;
    ctx.strokeStyle = rgba(line, 0.14);
    ctx.beginPath();
    ctx.moveTo(cx - R, cy); ctx.lineTo(cx + R, cy);
    ctx.moveTo(cx, cy - R); ctx.lineTo(cx, cy + R);
    ctx.stroke();
    if (detail) {
      ctx.strokeStyle = rgba(line, 0.06);
      ctx.setLineDash([2 * dpr, 6 * dpr]);
      ctx.beginPath();
      const d = R * Math.SQRT1_2;
      ctx.moveTo(cx - d, cy - d); ctx.lineTo(cx + d, cy + d);
      ctx.moveTo(cx + d, cy - d); ctx.lineTo(cx - d, cy + d);
      ctx.stroke();
      ctx.setLineDash([]);
    }

    // range rings
    const rings = 4;
    for (let i = 1; i <= rings; i++) {
      ctx.strokeStyle = rgba(line, i === rings ? 0.42 : 0.2);
      ctx.lineWidth = (i === rings ? 1.2 : 1) * dpr;
      ctx.beginPath(); ctx.arc(cx, cy, (R * i) / rings, 0, TAU); ctx.stroke();
    }

    // bearing ticks
    if (detail) {
      for (let deg = 0; deg < 360; deg += 5) {
        const a = (deg * Math.PI) / 180;
        const major = deg % 30 === 0;
        const len = (major ? 9 : 4) * dpr;
        ctx.strokeStyle = rgba(line, major ? 0.45 : 0.2);
        ctx.beginPath();
        ctx.moveTo(cx + Math.cos(a) * R, cy + Math.sin(a) * R);
        ctx.lineTo(cx + Math.cos(a) * (R - len), cy + Math.sin(a) * (R - len));
        ctx.stroke();
      }
    }

    // range labels
    if (labels && labels.length) {
      ctx.font = `${10 * dpr}px "JetBrains Mono", ui-monospace, monospace`;
      ctx.fillStyle = rgba(line, 0.42);
      ctx.textBaseline = "bottom";
      labels.slice(0, rings).forEach((txt, i) => {
        const r = (R * (i + 1)) / rings;
        ctx.fillText(txt, cx + 4 * dpr, cy - r - 2 * dpr);
      });
    }

    // outward pulses
    if (!still) {
      const pulsePeriod = 3.2;
      for (let k = 0; k < 2; k++) {
        const p = (((t / pulsePeriod) + k / 2) % 1 + 1) % 1;
        const eased = 1 - Math.pow(1 - p, 2);
        ctx.strokeStyle = rgba(accent, 0.32 * (1 - p));
        ctx.lineWidth = (1.5 - p) * dpr;
        ctx.beginPath(); ctx.arc(cx, cy, Math.max(0, R * eased), 0, TAU); ctx.stroke();
      }
    }

    // sweep trail (conic) + beam
    const trail = Math.PI * 0.55;
    ctx.save();
    ctx.beginPath(); ctx.moveTo(cx, cy); ctx.arc(cx, cy, R, beam - trail, beam); ctx.closePath();
    const anyCtx = ctx as CanvasRenderingContext2D & { createConicGradient?: (a: number, x: number, y: number) => CanvasGradient };
    if (anyCtx.createConicGradient) {
      const g = anyCtx.createConicGradient(beam - trail, cx, cy);
      const f = trail / TAU;
      g.addColorStop(0, rgba(accent, 0));
      g.addColorStop(f * 0.55, rgba(accent, 0.1));
      g.addColorStop(f * 0.97, rgba(accent, 0.42));
      g.addColorStop(f, rgba(accent, 0.55));
      g.addColorStop(Math.min(1, f + 0.001), rgba(accent, 0));
      ctx.fillStyle = g;
      ctx.fill();
    } else {
      const steps = 24;
      for (let i = 0; i < steps; i++) {
        const a0 = beam - trail + (trail * i) / steps;
        ctx.fillStyle = rgba(accent, 0.3 * ((i + 1) / steps) ** 2);
        ctx.beginPath(); ctx.moveTo(cx, cy); ctx.arc(cx, cy, R, a0, a0 + trail / steps + 0.01); ctx.closePath(); ctx.fill();
      }
    }
    ctx.restore();
    ctx.save();
    ctx.shadowColor = rgba(accent, 0.9);
    ctx.shadowBlur = 10 * dpr;
    ctx.strokeStyle = rgba(accent, 0.95);
    ctx.lineWidth = 1.6 * dpr;
    ctx.lineCap = "round";
    ctx.beginPath(); ctx.moveTo(cx, cy); ctx.lineTo(cx + Math.cos(beam) * R, cy + Math.sin(beam) * R); ctx.stroke();
    ctx.restore();

    // contacts
    for (const b of blips) {
      const a = b.a - Math.PI / 2;
      let delta = (beam - a) % TAU;
      if (delta < 0) delta += TAU;
      const age = delta / omega; // seconds since the beam crossed this contact
      if (!still && age > period * 0.92 && b.seen !== Math.floor(t / period)) {
        // contact lost: sometimes re-acquire somewhere else (out of the beam's way)
        b.seen = Math.floor(t / period);
        if (rand() < 0.35) Object.assign(b, place(b, b.hot), { a: ((beam + Math.PI / 2 + 0.6 + rand() * 3.5) % TAU + TAU) % TAU });
      }
      const glow = Math.exp(-age / (period * 0.38));
      const x = cx + Math.cos(a) * b.r * R;
      const y = cy + Math.sin(a) * b.r * R;
      const col = b.hot ? hot : accent;
      const base = 0.12;
      // halo ring that expands right after the hit
      if (age < 0.9) {
        const p = age / 0.9;
        ctx.strokeStyle = rgba(col, 0.6 * (1 - p));
        ctx.lineWidth = dpr;
        ctx.beginPath(); ctx.arc(x, y, (3 + p * 12) * dpr * b.size, 0, TAU); ctx.stroke();
      }
      const rad = (2 + glow * 1.6) * dpr * b.size;
      const halo = ctx.createRadialGradient(x, y, 0, x, y, rad * 4);
      halo.addColorStop(0, rgba(col, 0.55 * glow));
      halo.addColorStop(1, rgba(col, 0));
      ctx.fillStyle = halo;
      ctx.beginPath(); ctx.arc(x, y, rad * 4, 0, TAU); ctx.fill();
      ctx.fillStyle = rgba(col, base + 0.88 * glow);
      ctx.beginPath(); ctx.arc(x, y, rad, 0, TAU); ctx.fill();
    }

    // hub
    ctx.fillStyle = rgba(accent, 0.95);
    ctx.beginPath(); ctx.arc(cx, cy, 2.6 * dpr, 0, TAU); ctx.fill();
    ctx.strokeStyle = rgba(accent, 0.35);
    ctx.beginPath(); ctx.arc(cx, cy, 6 * dpr, 0, TAU); ctx.stroke();
  };

  // --- loop & lifecycle ----------------------------------------------------
  let raf = 0;
  let visible = true;
  let t0 = performance.now();
  let pausedAt = 0;
  let lastColour = 0;

  const frame = (now: number) => {
    raf = 0;
    const t = Math.max(0, (now - t0) / 1000);
    if (now - lastColour > 600) { readColours(); lastColour = now; }
    draw(t, false);
    schedule();
  };
  const running = () => !document.hidden && visible;
  const schedule = () => {
    if (!raf && running()) raf = requestAnimationFrame(frame);
  };
  const update = () => {
    if (running()) {
      if (pausedAt) { t0 += performance.now() - pausedAt; pausedAt = 0; }
      schedule();
    } else {
      if (raf) { cancelAnimationFrame(raf); raf = 0; }
      if (!pausedAt) pausedAt = performance.now();
    }
  };

  resize();
  readColours();
  draw(0, false);

  const ro = typeof ResizeObserver !== "undefined" ? new ResizeObserver(() => { resize(); if (!running()) { readColours(); draw(0, true); } }) : null;
  ro?.observe(canvas);
  const io = typeof IntersectionObserver !== "undefined"
    ? new IntersectionObserver((entries) => { visible = entries.some((e) => e.isIntersecting); update(); })
    : null;
  io?.observe(canvas);
  document.addEventListener("visibilitychange", update);
  // theme switches: repaint the static frame too
  const mo = new MutationObserver(() => { readColours(); if (!running()) draw(0, true); });
  mo.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme", "class"] });
  update();

  return () => {
    if (raf) cancelAnimationFrame(raf);
    ro?.disconnect();
    io?.disconnect();
    mo.disconnect();
    document.removeEventListener("visibilitychange", update);
  };
}
