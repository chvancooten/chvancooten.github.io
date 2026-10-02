// The scene: one WebGL2 canvas behind the home page, rendering views of the world (v1.js): the landing and the
// windows between the chapters (windows.js), each in its own frame.
//
//   const scene = mount(container, { intro, reduced, views, visible, vignette, onFrame, onIntroEnd, onReady, onFail,
//                                    onQuality });
//   scene.setScroll(progress)  the page has scrolled (in viewport heights): the frames follow the live scroll
//                              position (read, never changed), and past a few pixels the intro skips to its end
//   scene.setFocus(0..1)       1 sharp (default), 0 racked out of focus
//   scene.setIntensity(0..1)   1 full (default), 0 dimmed to the page
//   scene.pause() / resume()   stop on a composed still frame (an intro jumps to its end) / run again
//   scene.restyle()            re-read the colours from CSS, after a theme change
//   scene.destroy()            release the context, listeners and canvas
// mount() returns null where WebGL2 is missing or only rendered in software (SwiftShader, llvmpipe: there every frame
// stalls the main thread while the compositor reads the canvas back); onFail() reports a later failure (shaders, a
// lost context). In all these cases the page keeps its CSS stills.
//
// Views (opts.views(env), every frame; env: { it, ft, T, W, H, theme }, W and H the canvas size in CSS px): a list of
// { id, rect: { x0, y0, x1, y1, f } (where it shows, in canvas CSS px, feathered inside by f), veil, pose (a fixed
// camera; without one, the landing's camera), form (0 the braid, 1 the strands), glows, trail }. Without opts.views
// the whole canvas is the landing. opts.visible() says whether any view is on screen (otherwise the scene stops
// after one empty frame); opts.vignette(theme, H) sets the background's vignette.
//
// Colours come from the container's CSS: --scene-bg, --scene-red, --scene-red-2, --scene-blue, --scene-blue-2,
// --scene-purple, --scene-dust, and --scene-ink ("add" for light on dark, "ink" for ink on paper).
//
// Time: two clocks. The intro clock drives the landing's camera path and the assembly; it runs on real time (a slow
// device still plays the intro in about T seconds; a stall of more than 0.25 s holds it). The flow clock drives the
// particles; it only ever moves forward (scrolling moves cameras, never time), by at most 50 ms a frame.
// - Intro (opts.intro): T seconds from the first rendered frame. A deliberate input skips it (fast-forward in 0.42 s
//   to the end): a key other than a lone modifier, a press, a wheel, a touch, or a scroll. Pointer moves do not.
//   opts.onIntroEnd(reason) reports its end: "played", "skipped" or "stopped" (motion was turned off).
// - At rest the currents flow, the landing's camera drifts slowly and follows the pointer or touch a little.
// - Motion off (opts.reduced: .matches and "change" events, e.g. the site-wide motion preference, or the browser's
//   prefers-reduced-motion by default): no intro, no loop and no parallax: one composed still frame, redrawn as the
//   page scrolls (a picture moving with the page, not an animation) or the theme changes.
// - It renders only while a frame is on screen and the tab is visible.
// - Adaptive quality, judged on frame intervals and kept for the session (sessionStorage "scene-quality"): level 0
//   is full (pixel ratio up to 2, at most MAX_PIXELS), 1 a pixel ratio of 1, 2 to 7 a half down to 1/32 of the
//   particles (drawn larger and stronger) at a render scale from 1 down to 0.4, 8 a still frame. A level already
//   stored for the session is kept, and also lets a software renderer run (for screenshots and measurements).
import { createRenderer, VERTS_PER_PARTICLE, GLOW_SLOTS } from "./gl.js";
import { createWorld } from "./v1.js";
import { clamp, mix, smooth, easeOutCubic, viewProj, project } from "./math.js";
import { spring } from "../util.js";

const QUALITY_KEY = "scene-quality";
const MAX_PIXELS = 2560 * 1600;
const DENS = [1, 1, 0.5, 0.25, 0.125, 0.0625, 0.03125, 0.03125];
const SCALE = [1, 1, 1, 0.85, 0.75, 0.65, 0.55, 0.4];
export const STILL = 8;
const sizeK = (L) => Math.min(2.8, (1 / DENS[L]) ** 0.3);
const gainK = (L) => Math.min(2.6, (1 / DENS[L]) ** 0.32);
// Frames are judged after WARMUP (they carry compiles and uploads): in windows of 4 for the first 8, then of 20.
// A window whose median interval is over SLOW_MS steps down by as many halvings of the particles as the median asks
// for (28 ms a step). A 30 fps power-saving cap (33 ms) never steps down; stalls over 1 s are ignored.
const WARMUP = 2, SLOW_MS = 45;
const SKIP_MS = 420;
const SHUTTER = 1 / 30; // heads streak over the last 1/30 s
const FLOW_START = 12; // the flow is warm from the first frame
const INKS = ["red", "red-2", "blue", "blue-2", "purple", "dust"];
const MODIFIERS = new Set(["Shift", "Control", "Alt", "Meta", "CapsLock", "Fn", "OS"]);

const store = (fn) => { try { return fn(sessionStorage); } catch { return null; } };
// User Timing marks ("scene:ready", "scene:first-frame", "scene:intro-end:played", ...), for measurements.
const mark = (name) => { try { performance.mark("scene:" + name); } catch { /* no User Timing */ } };

// "#rgb", "#rrggbb", "rgb(r g b)" or "rgb(r, g, b)" to sRGB components in 0..1 (null for anything else).
export function parseColor(value) {
  const s = String(value || "").trim();
  let m = /^#([0-9a-f]{3}|[0-9a-f]{6})$/i.exec(s);
  if (m) {
    const h = m[1].length === 3 ? m[1].replace(/./g, "$&$&") : m[1];
    return [0, 2, 4].map((i) => parseInt(h.slice(i, i + 2), 16) / 255);
  }
  m = /^rgba?\(\s*([\d.]+)[\s,]+([\d.]+)[\s,]+([\d.]+)/i.exec(s);
  return m ? [m[1], m[2], m[3]].map((v) => clamp(parseFloat(v) / 255, 0, 1)) : null;
}

// Software rasterisers, by the unmasked renderer name where the browser gives it.
function isSoftware(gl) {
  const ext = gl.getExtension("WEBGL_debug_renderer_info");
  const name = ext ? gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) : "";
  return /swiftshader|llvmpipe|softpipe|software|basic render/i.test(String(name));
}

// Mask and veil uniforms (device px, y up) for a view's rectangles and veil (CSS px, y down), and the scissor box
// around the rectangles (the whole W x H render size without them): the mask is 0 outside them.
const newMask = () => ({ only: 0, n: 0, rects: new Float32Array(32), feather: new Float32Array(8), veil: new Float32Array(4), veil2: new Float32Array(4), box: new Int32Array(4) });
function setMask(m, rects, veil, dpr, W, H) {
  m.rects.fill(0);
  m.feather.fill(0);
  m.only = rects ? 1 : 0;
  m.n = rects ? Math.min(8, rects.length) : 0;
  let x0 = rects ? W : 0, y0 = rects ? H : 0, x1 = rects ? 0 : W, y1 = rects ? 0 : H;
  for (let i = 0; i < m.n; i++) {
    const r = rects[i];
    const q = [r.x0 * dpr, H - r.y1 * dpr, r.x1 * dpr, H - r.y0 * dpr];
    m.rects.set(q, i * 4);
    m.feather[i] = (r.f ?? 120) * dpr;
    x0 = Math.min(x0, q[0]); y0 = Math.min(y0, q[1]); x1 = Math.max(x1, q[2]); y1 = Math.max(y1, q[3]);
  }
  x0 = clamp(Math.floor(x0), 0, W); y0 = clamp(Math.floor(y0), 0, H);
  m.box.set([x0, y0, Math.max(0, clamp(Math.ceil(x1), 0, W) - x0), Math.max(0, clamp(Math.ceil(y1), 0, H) - y0)]);
  const v = veil || {};
  m.veil.set([(v.colX ?? 0) * dpr, v.colS ?? 0, H - (v.bottomY ?? 0) * dpr, v.bottomS ?? 0]);
  m.veil2.set([(v.topH ?? 0) * dpr, v.topS ?? 0, (v.f ?? 160) * dpr, H]);
}

export function mount(container, opts = {}) {
  const canvas = document.createElement("canvas");
  canvas.setAttribute("aria-hidden", "true");
  const gl = canvas.getContext("webgl2", {
    alpha: false, antialias: false, depth: false, stencil: false, premultipliedAlpha: true,
    preserveDrawingBuffer: false, powerPreference: "high-performance",
  });
  if (!gl) return null;
  const stored = store((s) => s.getItem(QUALITY_KEY));
  if (stored === null && isSoftware(gl)) {
    gl.getExtension("WEBGL_lose_context")?.loseContext();
    return null;
  }

  const world = createWorld();
  const T = world.T, SETTLED = T + 2.2; // the idle drift has faded in by SETTLED
  const reduced = opts.reduced || window.matchMedia("(prefers-reduced-motion: reduce)");
  let renderer = createRenderer(gl, world.glsl);
  let ready = false, failed = false, destroyed = false, appended = false;
  let level = clamp(Math.round(+stored || 0), 0, STILL);
  let paused = false;
  // OW x OH: the canvas (device px); W x H: the render size for the particle passes (the canvas at the level's
  // render scale), dpr: render px per CSS px
  let OW = 1, OH = 1, W = 1, H = 1, dpr = 1, cssW = 1, cssH = 1, aspect = 1;
  let raf = 0, last = 0, seeking = false, emptyShown = false;
  let flowT = FLOW_START;
  let introT = opts.intro && !reduced.matches ? 0 : SETTLED;
  let skip = null, skipped = false; // { from, at } while the intro fast-forwards; whether it was skipped
  let introOpen = introT < T; // the intro has not yet been reported as ended
  const ptr = { x: { x: 0, v: 0 }, y: { x: 0, v: 0 }, tx: 0, ty: 0 };
  const focus = { x: 1, v: 0, t: 1 };
  const intensity = { x: 1, v: 0, t: 1 };
  const f = {
    W, H, OW, OH, dpr, light: 0, n: 0, vignette: 0.5, seed: 0, comp: [1, 0],
    bg: new Float32Array(3), inks: new Float32Array(18), glows: new Float32Array(GLOW_SLOTS * 4),
    glowInks: new Float32Array(GLOW_SLOTS * 3), bgMask: newMask(), views: [],
  };
  const slots = [];
  const slot = (i) => slots[i] || (slots[i] = {
    VP: new Float32Array(16), VPp: new Float32Array(16), focal: 1, gain: 1, time: new Float32Array(4),
    lens: new Float32Array(4), fog: new Float32Array(4), trail: new Float32Array(3), params: new Float32Array(4), mask: newMask(),
  });
  let theme = "dark", lastViews = [];
  const stats = { frames: 0, js: [], level, vertices: 0 };
  const listeners = [];
  const on = (t, ev, fn, o) => { t.addEventListener(ev, fn, o); listeners.push([t, ev, fn, o]); };
  const introRunning = () => introT < T;
  const count = () => Math.max(64, Math.round(world.N * DENS[Math.min(level, STILL - 1)]));

  function restyle() {
    const cs = getComputedStyle(container);
    const get = (name, fb) => parseColor(cs.getPropertyValue(name)) || fb;
    const light = cs.getPropertyValue("--scene-ink").trim() === "ink";
    theme = light ? "light" : "dark";
    f.light = light ? 1 : 0;
    f.bg.set(get("--scene-bg", light ? [1, 0.988, 0.941] : [0.063, 0.059, 0.059]));
    INKS.forEach((k, i) => f.inks.set(get(`--scene-${k}`, [0.55, 0.5, 0.75]), i * 3));
  }

  function resize() {
    const r = container.getBoundingClientRect();
    const native = window.devicePixelRatio || 1;
    let nd = level >= 1 ? Math.min(1, native) : Math.min(2, native);
    nd = Math.min(nd, Math.sqrt(MAX_PIXELS / Math.max(1, r.width * r.height)));
    const ow = Math.max(1, Math.round(r.width * nd)), oh = Math.max(1, Math.round(r.height * nd));
    const sc = SCALE[Math.min(level, STILL - 1)];
    const w = Math.max(1, Math.round(ow * sc)), h = Math.max(1, Math.round(oh * sc));
    cssW = Math.max(1, r.width);
    cssH = Math.max(1, r.height);
    aspect = cssW / cssH;
    if (w === W && h === H && ow === OW && oh === OH) return false;
    OW = ow; OH = oh; W = w; H = h; dpr = W / cssW;
    canvas.width = OW;
    canvas.height = OH;
    world.layout(1 - smooth(0.62, 1.25, aspect));
    return true;
  }

  // One frame at intro time it and flow time ft.
  function frame() {
    const it = introT, ft = flowT, p = [ptr.x.x, ptr.y.x];
    const env = { it, ft, T, W: cssW, H: cssH, theme };
    const list = opts.views ? opts.views(env) : [{ id: "hero" }];
    const df = 1 - focus.x, dim = clamp(intensity.x, 0, 1);
    const n = count();
    f.W = W; f.H = H; f.OW = OW; f.OH = OH; f.dpr = dpr; f.n = n;
    f.vignette = opts.vignette ? opts.vignette(theme, cssH) : world.vignette[theme];
    f.comp = world.composite[theme];
    f.seed = (ft * 60) % 97;
    f.glows.fill(0);
    f.views.length = 0;
    let gi = 0;
    lastViews = [];
    list.forEach((v, i) => {
      const s = slot(i);
      let pose = v.pose, poseP = v.pose;
      if (!pose) {
        pose = world.pose({}, it, ft, p);
        poseP = world.pose({}, it - SHUTTER, ft - SHUTTER, p);
      }
      for (const q of pose === poseP ? [pose] : [pose, poseP]) {
        // out of focus: the focus distance comes close and the aperture opens
        q.focus = mix(q.focus, 1.6, df);
        q.ap = mix(q.ap, 7, df);
        q.blur = mix(q.blur, 15, df);
      }
      viewProj(s.VP, pose, aspect);
      if (poseP === pose) s.VPp.set(s.VP); else viewProj(s.VPp, poseP, aspect);
      const exposure = (pose.exp ?? 1) * dim;
      const tr = v.trail || world.trail;
      s.focal = (0.5 * H) / Math.tan((pose.fov * Math.PI) / 360);
      s.gain = world.gain[theme] * exposure * gainK(Math.min(level, STILL - 1));
      s.time.set([ft, it, ft - SHUTTER, it - SHUTTER]);
      s.lens.set([pose.focus, pose.ap * dpr, pose.blur * dpr, dpr * sizeK(Math.min(level, STILL - 1))]);
      s.fog.set(world.fog);
      s.trail.set([tr.time, tr.width, tr.alpha[theme]]);
      s.params.set([0, 0, v.form || 0, 0]);
      setMask(s.mask, v.rect ? [v.rect] : null, v.veil, dpr, W, H);
      f.views.push(s);
      for (const g of v.glows || world.glows(it)) {
        const q = gi < GLOW_SLOTS && project(s.VP, g.p, W, H);
        if (!q) continue;
        f.glows.set([q[0], q[1], g.r * H, g.a[theme] * exposure], gi * 4);
        f.glowInks.set(f.inks.subarray(g.ink * 3, g.ink * 3 + 3), gi * 3);
        gi++;
      }
      lastViews.push({ id: v.id ?? null, pos: pose.pos.map((x) => Math.round(x * 1000) / 1000) });
    });
    const rects = list.map((v) => v.rect).filter(Boolean);
    setMask(f.bgMask, opts.views ? rects : null, list[0]?.veil, dpr, W, H);
    return { it, T };
  }

  function draw() {
    if (!ready || destroyed) return 0;
    const t0 = performance.now();
    const info = frame();
    stats.vertices = renderer.draw(f);
    if (!appended) {
      appended = true;
      container.append(canvas);
      mark(introRunning() ? "first-frame:intro" : "first-frame");
      // one frame later the canvas is on screen with its first frame: CSS crossfades it in from there
      requestAnimationFrame(() => { if (!destroyed && !failed) container.classList.add("is-shown"); });
    }
    opts.onFrame?.(info);
    const js = performance.now() - t0;
    stats.frames++;
    stats.js.push(js);
    if (stats.js.length > 600) stats.js.shift();
    return js;
  }

  function endIntro(reason) {
    if (!introOpen) return;
    introOpen = false;
    mark("intro-end:" + reason);
    opts.onIntroEnd?.(reason);
  }
  // The settled state: no intro, springs at their targets.
  function settle() {
    if (introRunning()) endIntro("stopped");
    introT = Math.max(introT, SETTLED);
    skip = null;
    for (const s of [focus, intensity]) { s.x = s.t; s.v = 0; }
    if (reduced.matches) ptr.tx = ptr.ty = 0;
    ptr.x.x = ptr.tx; ptr.y.x = ptr.ty; ptr.x.v = ptr.y.v = 0;
  }
  // A still frame (motion off, paused, the still level, or a repaint while not running).
  function still() {
    if (!ready || destroyed) return;
    settle();
    draw();
  }

  const running = () => ready && !destroyed && !seeking && !paused && !reduced.matches && level < STILL;
  const visible = () => (opts.visible ? opts.visible() : true);
  const canRun = () => running() && !document.hidden && visible();

  // Adaptive quality, on frame intervals.
  const intervals = [];
  let judged = 0;
  function judge(interval) {
    if (level >= STILL - 1 || judged++ < WARMUP || interval > 1000) return;
    intervals.push(interval);
    if (intervals.length < (judged <= WARMUP + 8 ? 4 : 20)) return;
    const med = intervals.slice().sort((a, b) => a - b)[intervals.length >> 1];
    intervals.length = 0;
    if (med <= SLOW_MS) return;
    const base = level === 0 && (window.devicePixelRatio || 1) <= 1 ? 1 : level; // at a pixel ratio of 1 already
    level = Math.min(STILL - 1, Math.max(level + 1, base + Math.max(1, Math.ceil(Math.log2(med / 28)))));
    stats.level = level;
    store((s) => s.setItem(QUALITY_KEY, String(level)));
    mark(`quality:${level}:${Math.round(med)}ms`);
    resize();
    opts.onQuality?.(level);
  }

  function introClock(dt) {
    if (introT >= SETTLED) return;
    if (skip) {
      const k = easeOutCubic((performance.now() - skip.at) / SKIP_MS);
      introT = mix(skip.from, T, k);
      if (k >= 1) skip = null;
    } else {
      introT = Math.min(SETTLED, introT + dt);
    }
    if (introT >= T) endIntro(skipped ? "skipped" : "played");
  }

  function tick(now) {
    raf = 0;
    if (!canRun()) {
      last = 0;
      // nothing on screen: one empty frame, so no stale frame is left where the page has moved on
      if (running() && !document.hidden && !emptyShown) { emptyShown = true; draw(); }
      return;
    }
    emptyShown = false;
    const interval = last ? now - last : 0;
    const rdt = last ? Math.min(0.25, interval / 1000) : 1 / 60;
    last = now;
    introClock(rdt);
    flowT += Math.min(0.05, rdt);
    spring(focus, focus.t, 6, rdt);
    spring(intensity, intensity.t, 6, rdt);
    spring(ptr.x, ptr.tx, 3.2, rdt);
    spring(ptr.y, ptr.ty, 3.2, rdt);
    draw();
    if (interval) judge(interval);
    if (canRun()) raf = requestAnimationFrame(tick);
  }
  const kick = () => {
    if (!raf && ready && running() && !document.hidden) raf = requestAnimationFrame(tick);
  };
  const stop = () => {
    if (raf) cancelAnimationFrame(raf);
    raf = 0;
    last = 0;
  };
  // Not running: show the right still; running: make sure the loop is on.
  const refresh = () => (running() ? kick() : still());
  // Static frames follow the page while it scrolls, one per animation frame.
  let stillRaf = 0;
  const stillSoon = () => { if (!stillRaf) stillRaf = requestAnimationFrame(() => { stillRaf = 0; still(); }); };

  const skipIntro = () => {
    if (introRunning() && !skip) { skip = { from: introT, at: performance.now() }; skipped = true; mark("intro-skip"); }
  };

  // Boot: poll the shader programs once a frame until they are ready.
  let pollRaf = 0;
  function boot() {
    pollRaf = 0;
    if (destroyed) return;
    const st = renderer.poll();
    if (st === "pending") { pollRaf = requestAnimationFrame(boot); return; }
    if (st === "failed") { fail("shaders"); return; }
    ready = true;
    mark("ready");
    restyle();
    resize();
    container.classList.add("is-live");
    opts.onQuality?.(level);
    // The first frame now, even while the tab is hidden: the intro clock only runs while frames render, so the
    // intro waits rather than being marked as played.
    if (running()) { draw(); kick(); } else still();
    opts.onReady?.();
  }
  function fail(why) {
    failed = true;
    ready = false;
    stop();
    container.classList.remove("is-live", "is-shown");
    opts.onFail?.(why);
  }
  restyle();
  boot();

  // Input: skip on a deliberate input, from the next frame on (so the click that started the page does not).
  const skipOn = (e) => { if (e.type !== "keydown" || !MODIFIERS.has(e.key)) skipIntro(); };
  const arm = requestAnimationFrame(() => {
    if (destroyed) return;
    for (const ev of ["keydown", "pointerdown", "wheel", "touchstart"]) on(window, ev, skipOn, { passive: true });
  });
  // Parallax: the pointer (mouse, pen) or a touch, relative to the viewport, in -1..1.
  const aim = (x, y) => {
    if (reduced.matches) return;
    ptr.tx = clamp((x / window.innerWidth) * 2 - 1, -1, 1);
    ptr.ty = clamp(-((y / window.innerHeight) * 2 - 1), -1, 1);
    kick();
  };
  const rest = () => { ptr.tx = 0; ptr.ty = 0; kick(); };
  on(window, "pointermove", (e) => { if (e.pointerType !== "touch") aim(e.clientX, e.clientY); }, { passive: true });
  on(window, "touchmove", (e) => { const t = e.touches[0]; if (t) aim(t.clientX, t.clientY); }, { passive: true });
  on(window, "touchend", rest, { passive: true });
  on(document, "pointerleave", rest);
  on(document, "visibilitychange", () => (document.hidden ? stop() : kick()));
  const onReduce = () => (reduced.matches ? (stop(), still()) : kick());
  reduced.addEventListener("change", onReduce);
  let rt = 0;
  const ro = new ResizeObserver(() => {
    clearTimeout(rt);
    rt = setTimeout(() => {
      if (!ready || !resize()) return;
      if (!running()) still();
      else if (!raf) { draw(); kick(); }
    }, 60);
  });
  ro.observe(container);
  on(canvas, "webglcontextlost", (e) => { e.preventDefault(); fail("context lost"); });
  on(canvas, "webglcontextrestored", () => {
    if (destroyed) return;
    renderer = createRenderer(gl, world.glsl);
    failed = false;
    boot();
  });

  return {
    setScroll(progress) {
      if ((+progress || 0) * window.innerHeight > 8) skipIntro();
      if (running()) kick(); else if (ready) stillSoon();
    },
    setFocus(v) { focus.t = clamp(+v, 0, 1); refresh(); },
    setIntensity(v) { intensity.t = clamp(+v, 0, 1); refresh(); },
    pause() { paused = true; stop(); still(); },
    resume() { paused = false; refresh(); },
    restyle() {
      restyle();
      if (!raf) still();
    },
    destroy() {
      destroyed = true;
      stop();
      cancelAnimationFrame(pollRaf);
      cancelAnimationFrame(arm);
      cancelAnimationFrame(stillRaf);
      clearTimeout(rt);
      for (const [t, ev, fn, o] of listeners) t.removeEventListener(ev, fn, o);
      reduced.removeEventListener("change", onReduce);
      ro.disconnect();
      renderer.dispose();
      gl.getExtension("WEBGL_lose_context")?.loseContext();
      canvas.remove();
      container.classList.remove("is-live", "is-shown");
    },
    get failed() { return failed; },
    get level() { return level; },
    // Deterministic captures (stills, design reviews): the frame at intro time t (s), with the pointer ([-1..1,
    // -1..1]) given, and the loop stopped until live(). Real-time measurements never use it.
    seek(t, o = {}) {
      if (!ready) return false;
      stop();
      seeking = true;
      introT = Math.min(Math.max(0, t), SETTLED);
      flowT = FLOW_START + t;
      skip = null;
      const p = o.ptr || [0, 0];
      ptr.x.x = ptr.tx = p[0]; ptr.y.x = ptr.ty = p[1]; ptr.x.v = ptr.y.v = 0;
      resize();
      draw();
      return true;
    },
    live() { seeking = false; kick(); },
    // Read-only state for measurements: the clocks, the quality level, the frame count and each view's camera.
    clock: () => ({ introT, flowT, introRunning: introRunning(), level, density: count() / world.N, frames: stats.frames, views: lastViews }),
    stats: () => ({ ...stats, level, js: stats.js.slice(), N: count(), perParticle: VERTS_PER_PARTICLE, composite: renderer.composite }),
  };
}
