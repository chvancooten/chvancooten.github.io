// The hero scene: a WebGL2 canvas inside a container, rendering V1 (the pass-through; see v1.js).
//
//   const scene = mount(container, { intro, paused, reduced, onFrame, onReady, onFail, onQuality });
//   scene.setScroll(progress)  page scroll in viewport heights; the camera travels with it (never the other way)
//   scene.setFocus(0..1)       1 sharp (default), 0 racked out of focus, e.g. behind content
//   scene.setIntensity(0..1)   1 full (default), 0 dimmed to the background
//   scene.pause() / resume()   stop on the current frame (an intro jumps to its end) / run again
//   scene.restyle()            re-read the colours from CSS, after a theme change
//   scene.destroy()            release the context, listeners and canvas
// mount() returns null where WebGL2 is missing or only rendered in software (SwiftShader, llvmpipe: there every frame
// stalls the main thread while the compositor reads the canvas back); onFail() reports a later failure (shaders, a
// lost context). In all these cases the container keeps its CSS still. Focus, intensity and scroll changes ease in with critically damped
// springs. Colours come from the container's CSS: --scene-bg, --scene-love, --scene-rose, --scene-foam,
// --scene-pine, --scene-iris, --scene-subtle, and --scene-ink ("add" for light on dark, "ink" for ink on paper).
//
// Behaviour:
// - Intro (opts.intro): the fly-through, scene.T seconds; any key, pointer press, wheel, touch or scroll skips it
//   (it fast-forwards to the end in 0.42 s). Then the scene idles: the currents flow, the camera drifts slowly and
//   follows the pointer or touch a little.
// - Reduced motion: no intro, no loop and no parallax; one composed still frame, redrawn only when needed.
//   opts.reduced (a MediaQueryList-like source: .matches and "change" events) replaces the browser's
//   prefers-reduced-motion as the switch, e.g. a site-wide motion preference that a visitor can turn on or off.
// - It renders only while the container is on screen and the tab is visible.
// - Adaptive quality (kept for the session): 0 full (pixel ratio up to 2, at most MAX_PIXELS), 1 pixel ratio 1,
//   2 half the particles with stronger inks, 3 a still frame. It steps down when frames are slow. A level already
//   stored for the session (sessionStorage "scene-quality") is kept, and also lets a software renderer run.
import { createRenderer, VERTS_PER_TRAIL } from "./gl.js";
import { createV1 } from "./v1.js";
import { clamp, mix, smooth, easeOutCubic, viewProj, project } from "./math.js";
import { spring } from "../util.js";

const QUALITY_KEY = "scene-quality";
const MAX_PIXELS = 2560 * 1600;
// Quality windows: WINDOW frames after WARMUP; a window is slow when its median frame interval is over SLOW_MS, or
// over BUSY_INTERVAL_MS while the script also took over BUSY_MS a frame. (A browser that caps animation at 30 fps to
// save power gives 33 ms intervals with little script time, so it is not mistaken for a slow one.)
const WINDOW = 24, WARMUP = 8, SLOW_MS = 42, BUSY_INTERVAL_MS = 26, BUSY_MS = 10;
// Very slow frames (STALL_MS apart, STALLS in a row) step down at once, without waiting for a window.
const STALL_MS = 120, STALLS = 4;
const SKIP_MS = 420;
const FLOW_START = 12; // the flow is warm from the first frame
const INKS = ["love", "rose", "foam", "pine", "iris", "subtle"];

const store = (fn) => { try { return fn(sessionStorage); } catch { return null; } };

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

  const scene = createV1();
  const T = scene.T, SETTLED = T + 2.2; // the idle drift has faded in by SETTLED
  const reduced = opts.reduced || window.matchMedia("(prefers-reduced-motion: reduce)");
  let renderer = createRenderer(gl, scene);
  let ready = false, failed = false, destroyed = false, shown = false;
  let level = clamp(Math.round(+stored || 0), 0, 3);
  let paused = !!opts.paused;
  let W = 1, H = 1, dpr = 1, aspect = 1;
  let raf = 0, last = 0, onScreen = true, seeking = false;
  let flowT = FLOW_START;
  let introT = opts.intro && !reduced.matches && !paused ? 0 : SETTLED;
  let skip = null; // { from, at } while the intro fast-forwards
  const ptr = { x: { x: 0, v: 0 }, y: { x: 0, v: 0 }, tx: 0, ty: 0 };
  const scr = { x: 0, v: 0, t: 0 };
  const focus = { x: 1, v: 0, t: 1 };
  const intensity = { x: 1, v: 0, t: 1 };
  const pose = {}, poseP = {};
  const VP = new Float32Array(16), VPp = new Float32Array(16);
  const f = {
    W, H, dpr, VP, VPp, focal: 1, light: 0, n: 0, gain: 1, vignette: 0.5,
    time: new Float32Array(4), lens: new Float32Array(4), fog: new Float32Array(4), trail: new Float32Array(3),
    bg: new Float32Array(3), inks: new Float32Array(18), glows: new Float32Array(12), glowInks: new Float32Array(9),
  };
  let theme = "dark", glowInk = [];
  const stats = { frames: 0, js: [], level, vertices: 0 };
  const listeners = [];
  const on = (t, ev, fn, o) => { t.addEventListener(ev, fn, o); listeners.push([t, ev, fn, o]); };
  const introRunning = () => introT < T;

  function restyle() {
    const cs = getComputedStyle(container);
    const get = (name, fb) => parseColor(cs.getPropertyValue(name)) || fb;
    const light = cs.getPropertyValue("--scene-ink").trim() === "ink";
    theme = light ? "light" : "dark";
    f.light = light ? 1 : 0;
    f.bg.set(get("--scene-bg", light ? [0.98, 0.957, 0.929] : [0.098, 0.09, 0.141]));
    INKS.forEach((k, i) => f.inks.set(get(`--scene-${k}`, [0.6, 0.55, 0.7]), i * 3));
    glowInk = scene.glows.map((g) => f.inks.slice(g.ink * 3, g.ink * 3 + 3));
  }

  function resize() {
    const r = container.getBoundingClientRect();
    const native = window.devicePixelRatio || 1;
    let nd = level >= 1 ? Math.min(1, native) : Math.min(2, native);
    nd = Math.min(nd, Math.sqrt(MAX_PIXELS / Math.max(1, r.width * r.height)));
    const w = Math.max(1, Math.round(r.width * nd)), h = Math.max(1, Math.round(r.height * nd));
    aspect = r.width / Math.max(1, r.height);
    if (w === W && h === H && nd === dpr) return false;
    W = w; H = h; dpr = nd;
    canvas.width = W;
    canvas.height = H;
    scene.layout(1 - smooth(0.62, 1.25, aspect));
    return true;
  }

  // One frame at intro time it and flow time ft (the shutter is open for 1/30 s: heads streak with the motion in it).
  const SHUTTER = 1 / 30;
  function frame() {
    const it = introT, ft = flowT, p = [ptr.x.x, ptr.y.x], s = scr.x;
    scene.pose(pose, it, ft, p, s);
    scene.pose(poseP, it - SHUTTER, ft - SHUTTER, p, s);
    // Out of focus: the focus distance comes close and the aperture opens.
    const df = 1 - focus.x;
    for (const q of [pose, poseP]) {
      q.focus = mix(q.focus, 1.6, df);
      q.ap = mix(q.ap, 7, df);
      q.blur = mix(q.blur, 15, df);
    }
    viewProj(VP, pose, aspect);
    viewProj(VPp, poseP, aspect);
    const exposure = pose.exp * clamp(intensity.x, 0, 1);
    const n = Math.round(scene.N * (level >= 2 ? 0.5 : 1));
    f.W = W; f.H = H; f.dpr = dpr; f.n = n;
    f.focal = (0.5 * H) / Math.tan((pose.fov * Math.PI) / 360);
    f.gain = scene.gain[theme] * exposure * (level >= 2 ? 1.55 : 1);
    f.vignette = scene.vignette[theme];
    f.time.set([ft, it, ft - SHUTTER, it - SHUTTER]);
    f.lens.set([pose.focus, pose.ap * dpr, pose.blur * dpr, dpr]);
    f.fog.set(scene.fog(it));
    f.trail.set([scene.trail.time, scene.trail.width, scene.trail.alpha[theme]]);
    f.glows.fill(0);
    scene.glows.forEach((g, i) => {
      const q = project(VP, g.p, W, H);
      if (q) f.glows.set([q[0], q[1], g.r * H, g.a[theme] * exposure], i * 4);
      f.glowInks.set(glowInk[i], i * 3);
    });
    return { it, ptr: p };
  }

  function draw() {
    if (!ready || destroyed) return 0;
    const t0 = performance.now();
    const info = frame();
    stats.vertices = renderer.draw(f);
    if (!shown) {
      shown = true;
      if (!canvas.parentNode) container.append(canvas);
      container.classList.add("is-live");
    }
    opts.onFrame?.({ it: info.it, T, ptr: info.ptr });
    const js = performance.now() - t0;
    stats.frames++;
    stats.js.push(js);
    if (stats.js.length > 600) stats.js.shift();
    return js;
  }

  // The settled state: no intro, springs at their targets.
  function settle() {
    introT = Math.max(introT, SETTLED);
    skip = null;
    for (const s of [scr, focus, intensity]) { s.x = s.t; s.v = 0; }
    if (reduced.matches) { ptr.tx = ptr.ty = 0; }
    ptr.x.x = ptr.tx; ptr.y.x = ptr.ty; ptr.x.v = ptr.y.v = 0;
  }
  // A still frame (reduced motion, paused, still quality, or a repaint while not running).
  function still() {
    if (!ready || destroyed) return;
    settle();
    draw();
  }

  const running = () => ready && !destroyed && !seeking && !paused && !reduced.matches && level < 3;
  const canRun = () => running() && onScreen && !document.hidden;

  // Adaptive quality.
  const intervals = [], busy = [];
  let warm = WARMUP, stalls = 0;
  const median = (a) => a.slice().sort((x, y) => x - y)[a.length >> 1];
  function judge(interval, js) {
    if (warm > 0) { warm--; return; }
    stalls = interval > STALL_MS ? stalls + 1 : 0;
    intervals.push(interval);
    busy.push(js);
    if (stalls >= STALLS) return stepDown();
    if (intervals.length < WINDOW) return;
    const mi = median(intervals), mb = median(busy);
    intervals.length = busy.length = 0;
    if (mi > SLOW_MS || (mi > BUSY_INTERVAL_MS && mb > BUSY_MS)) stepDown();
  }
  function stepDown() {
    if (level >= 3) return;
    level = level === 0 && (window.devicePixelRatio || 1) <= 1 ? 2 : level + 1;
    stats.level = level;
    store((s) => s.setItem(QUALITY_KEY, String(level)));
    warm = WARMUP;
    stalls = 0;
    intervals.length = busy.length = 0;
    resize();
    opts.onQuality?.(level);
    if (level >= 3) { stop(); still(); }
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
  }

  function tick(now) {
    raf = 0;
    if (!canRun()) { last = 0; return; }
    // Real elapsed time (capped after a stall), so a slow device still plays the intro in about T seconds.
    const dt = last ? Math.min(0.1, (now - last) / 1000) : 1 / 60;
    const interval = last ? now - last : 0;
    last = now;
    introClock(dt);
    flowT += dt;
    spring(scr, scr.t, 9, dt);
    spring(focus, focus.t, 6, dt);
    spring(intensity, intensity.t, 6, dt);
    spring(ptr.x, ptr.tx, 3.2, dt);
    spring(ptr.y, ptr.ty, 3.2, dt);
    const js = draw();
    if (interval) judge(interval, js);
    if (canRun()) raf = requestAnimationFrame(tick);
  }
  const kick = () => {
    if (!raf && canRun()) raf = requestAnimationFrame(tick);
  };
  const stop = () => {
    if (raf) cancelAnimationFrame(raf);
    raf = 0;
    last = 0;
  };
  // Not running: show the right still (reduced motion, paused, still quality); running: make sure the loop is on.
  const refresh = () => (running() ? kick() : still());

  const skipIntro = () => {
    if (introRunning() && !skip) skip = { from: introT, at: performance.now() };
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
    restyle();
    resize();
    opts.onQuality?.(level);
    if (running()) { draw(); kick(); } else still();
    opts.onReady?.();
  }
  function fail(why) {
    failed = true;
    ready = false;
    shown = false;
    stop();
    container.classList.remove("is-live");
    opts.onFail?.(why);
  }
  restyle();
  boot();

  // Input: skip on any key, press, wheel or touch, from the next frame on.
  const arm = requestAnimationFrame(() => {
    if (destroyed) return;
    for (const ev of ["keydown", "pointerdown", "wheel", "touchstart"]) on(window, ev, skipIntro, { passive: true });
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
  const io = new IntersectionObserver(([e]) => {
    onScreen = e.isIntersecting;
    if (onScreen) kick(); else stop();
  });
  io.observe(container);
  const onReduce = () => (reduced.matches ? (stop(), still()) : kick());
  reduced.addEventListener("change", onReduce);
  let rt = 0;
  const ro = new ResizeObserver(() => {
    clearTimeout(rt);
    rt = setTimeout(() => { if (ready && resize() && !raf) still(); }, 60);
  });
  ro.observe(container);
  on(canvas, "webglcontextlost", (e) => { e.preventDefault(); fail("context lost"); });
  on(canvas, "webglcontextrestored", () => {
    if (destroyed) return;
    renderer = createRenderer(gl, scene);
    failed = false;
    boot();
  });

  return {
    setScroll(progress) {
      scr.t = Math.max(0, +progress || 0);
      if (scr.t > 0.01) skipIntro();
      if (reduced.matches) scr.t = 0; // no scroll-linked motion
      else kick();
    },
    setFocus(v) { focus.t = clamp(+v, 0, 1); refresh(); },
    setIntensity(v) { intensity.t = clamp(+v, 0, 1); refresh(); },
    pause() {
      paused = true;
      stop();
      still();
    },
    resume() {
      paused = false;
      refresh();
    },
    restyle() {
      restyle();
      if (!raf) still();
    },
    destroy() {
      destroyed = true;
      stop();
      cancelAnimationFrame(pollRaf);
      cancelAnimationFrame(arm);
      clearTimeout(rt);
      for (const [t, ev, fn, o] of listeners) t.removeEventListener(ev, fn, o);
      reduced.removeEventListener("change", onReduce);
      io.disconnect();
      ro.disconnect();
      renderer.dispose();
      gl.getExtension("WEBGL_lose_context")?.loseContext();
      canvas.remove();
      container.classList.remove("is-live");
    },
    get failed() { return failed; },
    // Deterministic captures (screenshots, contrast sampling): the frame at intro time t (s), with the pointer
    // ([-1..1, -1..1]) and scroll given, and the loop stopped until live().
    seek(t, o = {}) {
      if (!ready) return false;
      stop();
      seeking = true;
      introT = Math.min(Math.max(0, t), SETTLED);
      flowT = FLOW_START + t;
      skip = null;
      const p = o.ptr || [0, 0];
      ptr.x.x = ptr.tx = p[0]; ptr.y.x = ptr.ty = p[1]; ptr.x.v = ptr.y.v = 0;
      scr.x = scr.t = o.scroll || 0; scr.v = 0;
      resize();
      draw();
      return true;
    },
    live() { seeking = false; kick(); },
    // For measurements: frame count, script ms per frame, quality level, particles and vertices per frame.
    stats: () => ({ ...stats, js: stats.js.slice(), N: Math.round(scene.N * (level >= 2 ? 0.5 : 1)), perParticle: 4 + VERTS_PER_TRAIL }),
  };
}
