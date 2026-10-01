// The home page: mounts the scene behind the page once it has painted, and ties it to the page.
// - The scene is one canvas, fixed behind the page ([data-scene]); it shows in the landing and in the windows
//   between the chapters (windows.js), and nowhere else. Its runtime (stage.js: the renderer, the world, the
//   windows) is a chunk of its own, fetched as soon as this script runs (the URL is the scene element's data-src;
//   its integrity is in the page's import map) and started after the first contentful paint.
// - The intro plays on the first visit per tab session, from the scene's first frame. The session flag is written
//   when it has played or been skipped, never before.
// - The name is painted from the first frame. On a first visit it starts slightly lifted and enlarged, and the rest
//   of the landing's UI slightly offset (CSS, under [data-intro]; transform only, from the final layout, never
//   hidden); the intro clock settles them. If the intro cannot play, they settle in 0.45 s instead of snapping.
// - Motion follows the site-wide preference (../motion.js): off by default under reduced motion, where the control
//   lets the visitor opt in. The control shows whenever the scene can loop, its label always says what it will do,
//   and only the control changes the preference (kept across pages and visits).
// - The title bar: the name docks into it as the landing leaves (../dock.js), whether or not the scene runs.
// - No WebGL2 (or a failure): html.no-gl, which shows the designed stills instead of the canvas.
import { smooth } from "./math.js";
import { initDock } from "../dock.js";
import { motionOn, setMotion, calm } from "../motion.js";

const root = document.documentElement;
const INTRO_KEY = "scene-intro";
const store = (fn) => { try { return fn(sessionStorage); } catch { return null; } };
const reduced = window.matchMedia("(prefers-reduced-motion: reduce)");

const host = document.querySelector("[data-scene]");
const hero = document.querySelector(".hero");
const names = [...(hero?.querySelectorAll(".hero__name .nm > span") || [])];
const button = hero?.querySelector("[data-motion-toggle]");
let scene = null, frames = null, still = false, nameMotion = null;
const runtime = host?.dataset.src ? import(host.dataset.src) : Promise.reject(new Error("scene: no runtime"));
runtime.catch(() => {}); // reported by boot()
// A scene that has not come up 2.5 s after load gets the stills (html.scene-late; CSS fetches them only then).
setTimeout(() => { if (!root.matches(".scene-live, .no-gl")) root.classList.add("scene-late"); }, 2500);

// The landing's UI joins the intro: [selector, delay (s), duration (s), offset (px)], eased out, transform only.
// The offsets are the first-paint states in home.css. The lede, the calls to action and the cue move their contents,
// not themselves: a transformed element paints as a layer of its own, and their soft clouds (pseudo-elements) would
// then cover their neighbours' text instead of staying under all text.
const JOIN = [[".hero-bar", 1.2, 0.8, -10], [".hero__role", 1.45, 0.8, 14], [".hero__lede > *", 1.6, 0.85, 16], [".hero__cta > *", 1.75, 0.85, 16], [".cue > *", 2, 0.8, 10], [".hero__ctrl", 2.05, 0.8, 10]]
  .flatMap(([s, d, t, y]) => [...(hero?.querySelectorAll(s) || [])].map((el) => ({ el, d, t, y, v: "" })));
const easeOut = (x) => 1 - (1 - x) ** 3;
let joining = root.hasAttribute("data-intro");

function clearJoin() {
  for (const el of names) el.style.transform = "";
  for (const j of JOIN) { j.el.style.transform = ""; j.v = ""; }
}
// The intro cannot play (or has ended) while the landing still waits in its start state: settle it.
function release() {
  joining = false;
  clearJoin();
  if (!root.hasAttribute("data-intro")) return;
  root.classList.add("intro-release");
  root.removeAttribute("data-intro");
  setTimeout(() => root.classList.remove("intro-release"), 600);
}
function onFrame({ it, T }) {
  if (!joining) return;
  if (it >= T + 0.2) return release();
  for (const j of JOIN) {
    const k = easeOut(Math.min(1, Math.max(0, (it - j.d) / j.t)));
    const v = k < 0.9995 ? `translate3d(0,${(j.y * (1 - k)).toFixed(2)}px,0)` : "";
    if (v !== j.v) { j.el.style.transform = v; j.v = v; }
  }
  names.forEach((el, i) => {
    const lag = i * 0.07;
    const k = 1 - smooth(T * 0.36 + lag, T + lag, it);
    const m = nameMotion(k);
    el.style.transform = k > 0.0005 ? `translate3d(0,${m.y.toFixed(4)}em,0) scale(${m.s.toFixed(4)})` : "";
  });
  // From the first frame on, the script holds the landing; the first-paint states (and their CSS fallback) go.
  root.removeAttribute("data-intro");
}
function onIntroEnd() {
  store((s) => s.setItem(INTRO_KEY, "1"));
  joining = false;
  clearJoin(); // the join has reached its end state (within a few thousandths)
}

function syncButton() {
  if (!button) return;
  const off = !motionOn();
  button.hidden = !scene || scene.failed || still;
  button.toggleAttribute("data-paused", off);
  button.querySelector("span").textContent = off ? "Play motion" : "Pause motion";
}

function noScene() {
  root.classList.add("no-gl");
  root.classList.remove("scene-live");
  release();
  syncButton();
}

async function boot() {
  if (!host || !hero || scene) return;
  let rt;
  try {
    rt = await runtime;
  } catch (err) {
    console.warn(err);
    return noScene();
  }
  const { mount, createWindows, STILL } = rt;
  nameMotion = rt.nameMotion;
  // The intro needs both: motion on, and no reduced-motion request from the browser (an opt-in brings the scene to
  // life, not the fly-through).
  const intro = root.hasAttribute("data-intro") && !reduced.matches && motionOn();
  frames = createWindows({ hero, frames: [...document.querySelectorAll(".window")], header: document.querySelector(".site-header"), reduced: calm });
  scene = mount(host, {
    intro,
    reduced: calm, // motion off: one composed still frame, exactly as for reduced motion
    views: frames.views,
    visible: frames.visible,
    vignette: frames.vignette,
    onFrame,
    onIntroEnd,
    onReady: () => root.classList.add("scene-live"),
    onFail: noScene,
    onQuality: (level) => { still = level >= STILL; syncButton(); },
  });
  if (!scene) {
    frames.destroy();
    frames = null;
    return noScene();
  }
  if (!intro) release();
  // Under automation only (screenshots and measurements): the scene and its frames, read-only.
  if (navigator.webdriver) window.__scene = Object.assign(scene, { layout: frames.layout });
  syncButton();
}

if (hero) {
  try { initDock(); } catch (err) { console.warn(err); }
  window.addEventListener("scroll", () => scene?.setScroll(window.scrollY / window.innerHeight), { passive: true });
  // The scene follows the preference through `calm`; the control only records the choice.
  button?.addEventListener("click", () => setMotion(!motionOn()));
  document.addEventListener("motionchange", syncButton);
  document.addEventListener("themechange", () => scene?.restyle());

  // The WebGL context is created after the first contentful paint has been presented, in a task of its own.
  let started = false;
  const start = () => {
    if (started) return;
    started = true;
    requestAnimationFrame(() => setTimeout(boot, 0));
  };
  try {
    new PerformanceObserver((list, obs) => {
      if (list.getEntriesByName("first-contentful-paint").length) { obs.disconnect(); start(); }
    }).observe({ type: "paint", buffered: true });
  } catch { /* no paint timing: the timeout below */ }
  setTimeout(start, 800);
}
