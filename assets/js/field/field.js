// Canvas 2D runtime for the flow field ([data-field] in the hero, and a quiet one on the 404 page).
// - Trails are redrawn from a short position history on a cleared canvas every frame: additive ("lighter") inks on
//   dark, multiplied inks on light, from CSS custom properties that are re-read when the theme changes.
// - The fade at the field's edges is a mask inside the canvas (an inverted mask, destination-out), and the canvas box
//   itself sits beside or below the copy, so no motion ever reaches the text.
// - It stops when offscreen or when the tab is hidden, caps the pixel ratio at 2, draws one still frame under
//   reduced motion or when paused (the pause choice lasts for the session), and plays its intro gesture, a line
//   unfurling into the two currents, at most once per session.
// - It lowers its own quality, down to the still, where frames are too slow (see QUALITY).
import { createField, step, warm, setIntro, introY, BUCKETS, LEVELS, K } from "./sim.js";

const root = document.documentElement;
const reduced = window.matchMedia("(prefers-reduced-motion: reduce)");
const PAUSE_KEY = "motion-paused";
const INTRO_KEY = "field-intro";
const QUALITY_KEY = "field-quality";
const RAISED_KEY = "field-quality-raised";
const INTRO_MS = 700;

// Trail bands, head to tail: [first point, last point, point stride, alpha, width]; the trail tapers from its head to
// its tail. Where 2D canvas is not GPU-accelerated, it is rastered on the main thread, so the drawing is kept cheap
// for a software rasteriser:
// - every band is 1 px wide, which Skia draws as a hairline rather than stroking an outline (the head band used to
//   be 1.25 px at alpha 0.5, the same ink);
// - the faint tail bands take every other history sample (as the stills do), and the wide, faint glow under the
//   head (dark only) is one chord per particle; the trails curve so gently that neither shows.
const BANDS = [[0, 3, 1, 0.625, 1], [3, 6, 1, 0.32, 1], [6, 9, 2, 0.17, 1], [9, K, 2, 0.07, 1]];
const GLOW = [0, 3, 3, 0.06, 3.5];
// The reduced set (quality level 2): one strided tail band for the two, the same overall taper. With half the
// particles and no glow the field would look thin, so its inks are LOW_GAIN times stronger.
const LOW_BANDS = [BANDS[0], BANDS[1], [6, K, 3, 0.12, 1]];
const LOW_GAIN = 2;

// QUALITY: where 2D canvas is rastered in software (VMs, remote desktops, blocklisted GPUs) a frame can take longer
// than the display allows, and the main thread stays busy. Over each window of SAMPLES frames (a quarter of a second
// at 60 fps) the field takes the median interval between frames and the median time each frame keeps the main thread
// busy (the callback through the rendering update, marked by a message posted from the callback). When both are
// slow, it steps down a level: 1, a pixel ratio of 1; 2, half the particles, the lighter bands and no glow; 3, the
// still frame. Requiring the busy time too keeps a browser that caps animations at 30 fps to save power from
// looking slow. When the busy time over the last FAST_FOR ms (the median of its windows, none of them slow) is
// under FAST_BUSY, it steps back up one level, at most once per level per session, so a passing hiccup (a burst of screenshots, a long GC) does not pin
// a capable machine low, and a machine on the edge cannot flip back and forth. The still has no frames to judge, so
// FAST_FOR ms after it the field tries level 2 again, once: one window decides whether it stays there (and may then
// step up as usual) or returns to the still for good. The level lasts for the session, so the next page starts
// where this one ended up.
const SLOW_INTERVAL = 25, SLOW_BUSY = 20, SAMPLES = 15, SETTLE = 3, FAST_BUSY = 8, FAST_FOR = 5000;
// Edge fades as gradient stops along x and y: "side" (beside the copy, a long ramp toward it) and "band" (below the
// copy, short ramps on every side). The same ramps are baked into the stills (still.mjs).
const FADES = {
  side: { x: [[0, 0], [0.28, 1], [1, 1]], y: [[0, 0], [0.08, 1], [0.9, 1], [1, 0]] },
  band: { x: [[0, 0], [0.12, 1], [0.88, 1], [1, 0]], y: [[0, 0], [0.22, 1], [0.8, 1], [1, 0]] },
};
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

  let f = null, w = 0, h = 0, dpr = 1, band = false, density = 0;
  let level = Math.min(3, Math.max(0, +storage((s) => s.getItem(QUALITY_KEY)) || 0));
  const raised = new Set((storage((s) => s.getItem(RAISED_KEY)) || "").split("")); // levels already stepped up from
  host.dataset.quality = level;
  let mask = null, maskRects = [], raf = 0, last = 0, onScreen = true, live = false;
  let introStart = -1;
  const inks = { rgb: new Array(BUCKETS).fill("0,0,0"), blend: "lighter", dark: true };
  let styles = []; // stroke styles at full strength, [bucket][band], the glow last; rebuilt with the inks

  // Pointer wake: a critically damped follower of the pointer; its velocity drives the wake.
  const ptr = { has: false, tx: 0, ty: 0, x: { x: 0, v: 0 }, y: { x: 0, v: 0 }, r: 140 };
  const wake = { x: 0, y: 0, vx: 0, vy: 0, r: ptr.r };

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
    styles = strokeStyles(1);
  }

  const bands = () => (level >= 2 ? LOW_BANDS : BANDS);
  function strokeStyles(fade) {
    const a = fade * mode.alpha * (inks.dark ? 1.3 : 1.75) * (level >= 2 ? LOW_GAIN : 1);
    return inks.rgb.map((rgb) => [...bands(), GLOW].map((band) => `rgba(${rgb},${(band[3] * a).toFixed(3)})`));
  }

  // The edge fade, drawn once per size: a long ramp on the side facing the copy, short ones elsewhere. It is kept
  // inverted (alpha = how much to remove) and applied with destination-out, which only touches the pixels it is
  // drawn over, so only the strips where the fade is below 1 are composited: well under half of the canvas.
  function buildMask() {
    mask = document.createElement("canvas");
    mask.width = canvas.width;
    mask.height = canvas.height;
    const m = mask.getContext("2d");
    const W = mask.width, H = mask.height;
    const fade = band ? FADES.band : FADES.side;
    const ramp = (x1, y1, stops) => {
      const g = m.createLinearGradient(0, 0, x1, y1);
      for (const [o, a] of stops) g.addColorStop(o, `rgba(0,0,0,${a})`);
      return g;
    };
    m.fillStyle = ramp(W, 0, fade.x);
    m.fillRect(0, 0, W, H);
    m.globalCompositeOperation = "destination-in";
    m.fillStyle = ramp(0, H, fade.y);
    m.fillRect(0, 0, W, H);
    m.globalCompositeOperation = "xor"; // with opaque black over it: alpha becomes 1 - fade
    m.fillStyle = "#000";
    m.fillRect(0, 0, W, H);
    // The fully opaque middle of each axis, in whole device pixels (rounded inwards, so the strips cover every
    // pixel the fade touches).
    const inner = (stops, size) => {
      const full = stops.filter(([, a]) => a === 1).map(([o]) => o);
      return [Math.ceil(full[0] * size), Math.floor(full.at(-1) * size)];
    };
    const [x0, x1] = inner(fade.x, W), [y0, y1] = inner(fade.y, H);
    maskRects = [[0, 0, x0, H], [x1, 0, W - x1, H], [x0, 0, x1 - x0, y0], [x0, y1, x1 - x0, H - y1]].filter(([, , rw, rh]) => rw > 0 && rh > 0);
  }

  function layout() {
    const r = host.getBoundingClientRect();
    const nw = Math.max(1, Math.round(r.width)), nh = Math.max(1, Math.round(r.height));
    const ndpr = level >= 1 ? 1 : naturalDpr();
    const nd = level >= 2 ? mode.density / 2 : mode.density;
    if (f && nw === w && nh === h && ndpr === dpr && nd === density) return false;
    w = nw; h = nh; dpr = ndpr; density = nd;
    // "band" (own band below the copy, fades on all sides) or "side" (beside the copy, long fade toward it).
    band = getComputedStyle(host).getPropertyValue("--field-layout").trim() === "band";
    canvas.width = Math.round(w * dpr);
    canvas.height = Math.round(h * dpr);
    f = createField(w, h, { seed: 7, density, speed: mode.speed });
    warm(f);
    buildMask();
    return true;
  }

  // Particles sorted by colour bucket (counting sort into preallocated arrays), so each ink is one path per band.
  let order = null;
  const counts = new Int32Array(BUCKETS + 1), next = new Int32Array(BUCKETS);
  function sortByBucket() {
    const { n, B } = f;
    if (!order || order.length !== n) order = new Int32Array(n);
    counts.fill(0);
    for (let i = 0; i < n; i++) counts[B[i] + 1]++;
    for (let b = 0; b < BUCKETS; b++) { counts[b + 1] += counts[b]; next[b] = counts[b]; }
    for (let i = 0; i < n; i++) order[next[B[i]]++] = i;
  }

  // Trail points s0..s1 of particle i, every stride-th one (s1 always included), as a sub-path. Point 0 is the head,
  // 1..K walk back through the history ring, which holds true positions: during the intro they are squashed like
  // the heads (introY), so the whole trail opens with the field.
  function segment(i, s0, s1, stride) {
    const { HX, HY, ring } = f;
    const sq = f.intro < 1;
    const base = i * K;
    let j = s0;
    if (j === 0) ctx.moveTo(f.RX[i], f.RY[i]);
    else { const o = base + ((ring - j + 1 + K) % K); ctx.moveTo(HX[o], sq ? introY(f, HX[o], HY[o]) : HY[o]); }
    do {
      j = Math.min(s1, j + stride);
      const o = base + ((ring - j + 1 + K) % K);
      ctx.lineTo(HX[o], sq ? introY(f, HX[o], HY[o]) : HY[o]);
    } while (j < s1);
  }

  // One band of every trail in one colour bucket: a single path, a single stroke.
  function stroke(style, band, from, to) {
    ctx.strokeStyle = style;
    ctx.lineWidth = band[4];
    ctx.beginPath();
    for (let k = from; k < to; k++) segment(order[k], band[0], band[1], band[2]);
    ctx.stroke();
  }

  function draw(fade) {
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.globalCompositeOperation = "source-over";
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.globalCompositeOperation = inks.blend;
    ctx.lineCap = "butt"; // a drained (zero-length) trail draws nothing
    ctx.lineJoin = "round";
    const st = fade === 1 ? styles : strokeStyles(fade); // the intro fades in; after it, no strings per frame
    // A faint, wide pass under the newest segments gives the dark field depth.
    const glow = inks.dark && fade === 1 && level < 2, set = bands();
    sortByBucket();
    for (let b = 0; b < BUCKETS; b++) {
      const from = counts[b], to = counts[b + 1];
      if (from === to) continue;
      if (glow) stroke(st[b][set.length], GLOW, from, to);
      for (let k = 0; k < set.length; k++) stroke(st[b][k], set[k], from, to);
    }
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.globalCompositeOperation = "destination-out";
    for (let r = 0; r < maskRects.length; r++) {
      const [x, y, rw, rh] = maskRects[r];
      ctx.drawImage(mask, x, y, rw, rh, x, y, rw, rh);
    }
    ctx.globalCompositeOperation = "source-over";
    if (!live) {
      live = true;
      host.classList.add("is-live");
      performance.mark("field:first-frame");
    }
  }

  const running = () => !reduced.matches && !isPaused() && level < 3;
  const allowed = () => running() && onScreen && !document.hidden;

  // Frame timing for QUALITY: intervals between frames and busy time per frame, a window at a time.
  const intervals = new Float32Array(SAMPLES), busy = new Float32Array(SAMPLES);
  let sampled = 0, settle = SETTLE, frameStart = 0, busyAt = 0, fast = 0, fastN = 0;
  const fastBusy = new Float32Array(64); // window medians since the last slow window (FAST_FOR ms fits in 64 windows)
  const done = new MessageChannel();
  done.port1.onmessage = () => { busy[busyAt] = performance.now() - frameStart; busyAt = (busyAt + 1) % SAMPLES; };
  const median = (a) => { a.sort(); return a[SAMPLES >> 1]; };
  function sample(interval) {
    if (introStart >= 0) { settle = SETTLE; return; } // judge the field, not its intro
    if (settle > 0) { settle--; return; }
    intervals[sampled++] = interval;
    if (sampled < SAMPLES) return;
    sampled = 0;
    let span = 0;
    for (let i = 0; i < SAMPLES; i++) span += intervals[i];
    const slowFrames = median(intervals) > SLOW_INTERVAL, b = median(busy);
    if (slowFrames && b > SLOW_BUSY) { setLevel(level === 0 && naturalDpr() <= 1 ? 2 : level + 1); return; }
    if (level === 0) return;
    fast += span;
    if (fastN < fastBusy.length) fastBusy[fastN++] = b;
    if (fast < FAST_FOR) return;
    // Back to the full pixel ratio (1 to 0) means four times the pixels, so that step asks for half the busy time.
    const all = fastBusy.subarray(0, fastN).sort();
    const good = all[fastN >> 1] < (level === 1 ? FAST_BUSY / 2 : FAST_BUSY);
    fast = 0; fastN = 0;
    if (good) raise();
  }
  const naturalDpr = () => Math.min(2, window.devicePixelRatio || 1);
  function raise() {
    if (level === 0 || raised.has(String(level))) return;
    raised.add(String(level));
    storage((s) => s.setItem(RAISED_KEY, [...raised].join("")));
    setLevel(level === 2 && naturalDpr() <= 1 ? 0 : level - 1);
  }
  function setLevel(next) {
    level = next;
    storage((s) => s.setItem(QUALITY_KEY, String(level)));
    host.dataset.quality = level;
    settle = SETTLE;
    sampled = 0;
    fast = 0;
    fastN = 0;
    if (level >= 3) { stop(); syncButton(); still(); probeLater(); return; }
    layout(); // the still keeps the level 2 field, so 3 to 2 does not rebuild it
    styles = strokeStyles(1);
    syncButton();
  }
  // From the still, one try at level 2 (see QUALITY).
  function probeLater() {
    if (raised.has("3")) return;
    setTimeout(() => {
      if (level !== 3 || raised.has("3") || reduced.matches || isPaused()) return;
      raised.add("3");
      storage((s) => s.setItem(RAISED_KEY, [...raised].join("")));
      setLevel(2);
      start();
    }, FAST_FOR);
  }

  function tick(now) {
    raf = 0;
    frameStart = performance.now();
    if (last) sample(now - last);
    if (level >= 3) return; // fell back to the still
    const dt = Math.min(0.05, last ? (now - last) / 1000 : 1 / 60);
    last = now;
    let fade = 1;
    if (introStart >= 0) {
      const p = Math.min(1, (now - introStart) / INTRO_MS);
      f.intro = p;
      fade = 0.3 + 0.7 * p;
      if (p >= 1) introStart = -1;
    }
    let pointer = null;
    if (ptr.has || Math.abs(ptr.x.v) + Math.abs(ptr.y.v) > 1) {
      spring(ptr.x, ptr.tx, 14, dt);
      spring(ptr.y, ptr.ty, 14, dt);
      wake.x = ptr.x.x; wake.y = ptr.y.x; wake.vx = ptr.x.v; wake.vy = ptr.y.v;
      pointer = wake;
    }
    step(f, dt, pointer);
    draw(fade);
    done.port2.postMessage(0); // arrives after this frame's rendering update
    if (allowed()) raf = requestAnimationFrame(tick);
    else last = 0;
  }
  let booted = false;
  const start = () => { if (booted && !raf && allowed()) { settle = SETTLE; sampled = 0; raf = requestAnimationFrame(tick); } };
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
    button.hidden = reduced.matches || level >= 3;
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
    setIntro(f, 0);
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
    if (level === 3) probeLater(); // the session's earlier pages ended at the still
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
