// Canvas 2D runtime for the flow field ([data-field] in the hero, and a quiet one on the 404 page).
// - Trails are redrawn from a short position history on a cleared canvas every frame: additive ("lighter") inks on
//   dark, multiplied inks on light, from CSS custom properties that are re-read when the theme changes.
// - The fade at the field's edges is a mask inside the canvas (destination-in), and the canvas box itself sits
//   beside or below the copy, so no motion ever reaches the text.
// - It stops when offscreen or when the tab is hidden, caps the pixel ratio at 2, draws one still frame under
//   reduced motion or when paused (the pause choice lasts for the session), and plays its intro gesture, a line
//   unfurling into the two currents, at most once per session.
import { createField, step, warm, setIntro, BUCKETS, LEVELS, K } from "./sim.js";

const root = document.documentElement;
const reduced = window.matchMedia("(prefers-reduced-motion: reduce)");
const PAUSE_KEY = "motion-paused";
const INTRO_KEY = "field-intro";
const INTRO_MS = 700;

// [first point, last point, alpha, width]: the trail tapers from its head to its tail.
const BANDS = [[0, 3, 0.5, 1.25], [3, 6, 0.32, 1], [6, 9, 0.17, 1], [9, K, 0.07, 1]];
const MODES = {
  hero: { density: 13, speed: 1, alpha: 1 },
  quiet: { density: 7, speed: 0.7, alpha: 0.6 },
};

const storage = (fn) => { try { return fn(sessionStorage); } catch { return null; } };
const isPaused = () => storage((s) => s.getItem(PAUSE_KEY)) === "1";

// CSS colour -> [r, g, b]. Hex (#rgb, #rgba, #rrggbb, #rrggbbaa) and rgb()/rgba() in comma or space syntax are
// parsed directly; anything else (named colours, hsl(), color-mix()) is normalised by a 2D context first.
export function parseColor(value, ctx) {
  const s = String(value || "").trim();
  let m = /^#([0-9a-f]{3,8})$/i.exec(s);
  if (m && m[1].length !== 5 && m[1].length !== 7) {
    let h = m[1];
    if (h.length <= 4) h = h.replace(/./g, "$&$&");
    return [0, 2, 4].map((i) => parseInt(h.slice(i, i + 2), 16));
  }
  m = /^rgba?\(\s*([\d.]+)(%?)[\s,]+([\d.]+)(%?)[\s,]+([\d.]+)(%?)/i.exec(s);
  if (m) {
    return [1, 3, 5].map((i) => Math.round(Math.min(255, parseFloat(m[i]) * (m[i + 1] ? 2.55 : 1))));
  }
  if (s && ctx) {
    ctx.fillStyle = "#010203";
    ctx.fillStyle = s;
    const n = ctx.fillStyle;
    if (n !== "#010203" && n !== s) return parseColor(n, null);
  }
  return null;
}

function mount(host) {
  performance.mark("field:boot");
  const mode = MODES[host.dataset.field] || MODES.hero;
  const canvas = document.createElement("canvas");
  const ctx = canvas.getContext("2d", { alpha: true });
  if (!ctx) return; // no canvas: the still stays
  host.append(canvas);
  const scope = host.closest("section") || document.body;
  const button = scope.querySelector("[data-motion-toggle]");

  let f = null, w = 0, h = 0, dpr = 1, band = false;
  let mask = null, raf = 0, last = 0, onScreen = true, live = false;
  let introStart = -1;
  const inks = { rgb: new Array(BUCKETS).fill("0,0,0"), blend: "lighter", dark: true };

  // Pointer wake: a critically damped follower of the pointer; its velocity drives the wake.
  const ptr = { has: false, tx: 0, ty: 0, x: { x: 0, v: 0 }, y: { x: 0, v: 0 }, r: 140 };

  function readInks() {
    const cs = getComputedStyle(host);
    const get = (name, fallback) => parseColor(cs.getPropertyValue(name), ctx) || fallback;
    const love = get("--field-love", [235, 111, 146]);
    const iris = get("--field-iris", [196, 167, 231]);
    const foam = get("--field-foam", [156, 207, 216]);
    const mix = (a, b, k) => a.map((c, i) => Math.round(c + (b[i] - c) * k)).join(",");
    for (let q = 0; q < LEVELS; q++) {
      const k = q / (LEVELS - 1);
      inks.rgb[q] = mix(love, iris, k);
      inks.rgb[BUCKETS - 1 - q] = mix(foam, iris, k);
    }
    inks.blend = cs.getPropertyValue("--field-blend").trim() === "multiply" ? "multiply" : "lighter";
    inks.dark = inks.blend === "lighter";
  }

  // The edge fade, drawn once per size: a long ramp on the side facing the copy, short ones elsewhere.
  function buildMask() {
    mask = document.createElement("canvas");
    mask.width = canvas.width;
    mask.height = canvas.height;
    const m = mask.getContext("2d");
    const W = mask.width, H = mask.height;
    const ramp = (x0, y0, x1, y1, stops) => {
      const g = m.createLinearGradient(x0, y0, x1, y1);
      for (const [o, a] of stops) g.addColorStop(o, `rgba(0,0,0,${a})`);
      return g;
    };
    m.fillStyle = band
      ? ramp(0, 0, W, 0, [[0, 0], [0.12, 1], [0.88, 1], [1, 0]])
      : ramp(0, 0, W, 0, [[0, 0], [0.28, 1], [1, 1]]);
    m.fillRect(0, 0, W, H);
    m.globalCompositeOperation = "destination-in";
    m.fillStyle = band
      ? ramp(0, 0, 0, H, [[0, 0], [0.22, 1], [0.8, 1], [1, 0]])
      : ramp(0, 0, 0, H, [[0, 0], [0.08, 1], [0.9, 1], [1, 0]]);
    m.fillRect(0, 0, W, H);
  }

  function layout() {
    const r = host.getBoundingClientRect();
    const nw = Math.max(1, Math.round(r.width)), nh = Math.max(1, Math.round(r.height));
    const ndpr = Math.min(2, window.devicePixelRatio || 1);
    if (f && nw === w && nh === h && ndpr === dpr) return false;
    w = nw; h = nh; dpr = ndpr;
    band = w / h > 1.25;
    canvas.width = Math.round(w * dpr);
    canvas.height = Math.round(h * dpr);
    f = createField(w, h, { seed: 7, density: mode.density, speed: mode.speed });
    warm(f);
    buildMask();
    return true;
  }

  // Particles sorted by colour bucket (counting sort into preallocated arrays), so each ink is one path per band.
  let order = null;
  const counts = new Int32Array(BUCKETS + 1);
  function sortByBucket() {
    const { n, B } = f;
    if (!order || order.length !== n) order = new Int32Array(n);
    counts.fill(0);
    for (let i = 0; i < n; i++) counts[B[i] + 1]++;
    for (let b = 0; b < BUCKETS; b++) counts[b + 1] += counts[b];
    const next = counts.slice(0, BUCKETS);
    for (let i = 0; i < n; i++) order[next[B[i]]++] = i;
  }

  // Trail segment [s0, s1] of particle i as a sub-path; point 0 is the head, 1..K walk back through history.
  function segment(i, s0, s1) {
    const { RX, RY, HX, HY, ring } = f;
    const base = i * K;
    let j = s0;
    if (j === 0) { ctx.moveTo(RX[i], RY[i]); j = 1; }
    else { const o = base + ((ring - j + 1 + K) % K); ctx.moveTo(HX[o], HY[o]); j++; }
    for (; j <= s1; j++) {
      const o = base + ((ring - j + 1 + K) % K);
      ctx.lineTo(HX[o], HY[o]);
    }
  }

  function draw(fade) {
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.globalCompositeOperation = "source-over";
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.globalCompositeOperation = inks.blend;
    ctx.lineCap = "butt"; // a drained (zero-length) trail draws nothing
    ctx.lineJoin = "round";
    const a = fade * mode.alpha * (inks.dark ? 1.3 : 1.75);
    sortByBucket();
    for (let b = 0; b < BUCKETS; b++) {
      const from = counts[b], to = counts[b + 1];
      if (from === to) continue;
      const rgb = inks.rgb[b];
      if (inks.dark && fade === 1) {
        // A faint, wide pass under the newest segments gives the dark field some depth.
        ctx.strokeStyle = `rgba(${rgb},${(0.06 * a).toFixed(3)})`;
        ctx.lineWidth = 3.5;
        ctx.beginPath();
        for (let k = from; k < to; k++) segment(order[k], 0, 3);
        ctx.stroke();
      }
      for (const [s0, s1, alpha, lw] of BANDS) {
        ctx.strokeStyle = `rgba(${rgb},${(alpha * a).toFixed(3)})`;
        ctx.lineWidth = lw;
        ctx.beginPath();
        for (let k = from; k < to; k++) segment(order[k], s0, s1);
        ctx.stroke();
      }
    }
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.globalCompositeOperation = "destination-in";
    ctx.drawImage(mask, 0, 0);
    ctx.globalCompositeOperation = "source-over";
    if (!live) {
      live = true;
      host.classList.add("is-live");
      performance.mark("field:first-frame");
    }
  }

  const running = () => !reduced.matches && !isPaused();
  const allowed = () => running() && onScreen && !document.hidden;

  function tick(now) {
    raf = 0;
    const dt = Math.min(0.05, last ? (now - last) / 1000 : 1 / 60);
    last = now;
    let fade = 1;
    if (introStart >= 0) {
      const p = Math.min(1, (now - introStart) / INTRO_MS);
      f.intro = p;
      fade = 0.3 + 0.7 * p;
      if (p >= 1) introStart = -1;
    }
    let wake = null;
    if (ptr.has || Math.abs(ptr.x.v) + Math.abs(ptr.y.v) > 1) {
      spring(ptr.x, ptr.tx, 14, dt);
      spring(ptr.y, ptr.ty, 14, dt);
      wake = { x: ptr.x.x, y: ptr.y.x, vx: ptr.x.v, vy: ptr.y.v, r: ptr.r };
    }
    step(f, dt, wake);
    draw(fade);
    if (allowed()) raf = requestAnimationFrame(tick);
    else last = 0;
  }
  let booted = false;
  const start = () => { if (booted && !raf && allowed()) raf = requestAnimationFrame(tick); };
  const stop = () => { if (raf) cancelAnimationFrame(raf); raf = 0; last = 0; };

  // One settled, static frame (reduced motion, paused, or a repaint while not running).
  function still() {
    introStart = -1;
    if (f.intro < 1) setIntro(f, 1);
    draw(1);
  }

  function syncButton() {
    if (!button) return;
    const paused = isPaused();
    button.hidden = reduced.matches;
    button.toggleAttribute("data-paused", paused);
    button.querySelector("span").textContent = paused ? "Play motion" : "Pause motion";
  }

  // Boot: size and inks now; the first frame (intro, animated or still) one frame after the page's first paint,
  // so the page, the script and the first canvas raster never share a task. Until then the still shows.
  layout();
  readInks();
  let pendingIntro = false;
  if (running() && root.hasAttribute("data-intro") && storage((s) => s.getItem(INTRO_KEY)) !== "1") {
    storage((s) => s.setItem(INTRO_KEY, "1"));
    setIntro(f, 0, true);
    pendingIntro = true;
    host.classList.add("is-intro");
    const skip = () => { if (introStart >= 0) introStart -= INTRO_MS; };
    for (const ev of ["keydown", "pointerdown", "wheel", "touchstart"]) window.addEventListener(ev, skip, { once: true, passive: true });
  }
  root.removeAttribute("data-intro");
  syncButton();
  requestAnimationFrame(() => requestAnimationFrame((now) => {
    booted = true;
    if (pendingIntro) introStart = now;
    if (allowed()) tick(now);
    else still();
  }));

  new IntersectionObserver(([e]) => {
    onScreen = e.isIntersecting;
    if (onScreen) start(); else stop();
  }).observe(host);
  document.addEventListener("visibilitychange", () => (document.hidden ? stop() : start()));
  reduced.addEventListener("change", () => {
    syncButton();
    if (reduced.matches) { stop(); still(); } else start();
  });
  document.addEventListener("themechange", () => {
    readInks();
    if (booted && !raf) still();
  });
  let resizeTimer = 0;
  new ResizeObserver(() => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(() => { if (layout() && booted && !raf) still(); }, 60);
  }).observe(host);

  button?.addEventListener("click", () => {
    const paused = !isPaused();
    storage((s) => s.setItem(PAUSE_KEY, paused ? "1" : "0"));
    syncButton();
    if (paused) { stop(); still(); } else start();
  });

  // Pointer (mouse and pen) anywhere over the section; the field only reacts where it has particles.
  const move = (e) => {
    if (e.pointerType === "touch") return;
    const r = host.getBoundingClientRect();
    ptr.tx = e.clientX - r.left;
    ptr.ty = e.clientY - r.top;
    if (!ptr.has) {
      // Snap in where the pointer enters: no sweep from the last position, no jump in velocity.
      ptr.x.x = ptr.tx; ptr.y.x = ptr.ty; ptr.x.v = ptr.y.v = 0;
      ptr.has = true;
    }
  };
  scope.addEventListener("pointermove", move, { passive: true });
  scope.addEventListener("pointerleave", () => { ptr.has = false; });
}

// Critically damped spring step (as in util.js; duplicated to keep this bundle self-contained).
function spring(s, target, w, dt) {
  const d = s.x - target, e = Math.exp(-w * dt), c = s.v + w * d;
  s.x = target + (d + c * dt) * e;
  s.v = (s.v - w * c * dt) * e;
}

for (const host of document.querySelectorAll("[data-field]")) {
  try {
    mount(host);
  } catch (err) {
    console.warn(err);
  }
}
