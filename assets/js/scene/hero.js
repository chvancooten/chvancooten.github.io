// The home landing: mounts the scene behind the name once the page has painted, and ties it to the page.
// - The name is painted from the first frame. On the first visit of a session it starts slightly lifted and
//   enlarged (CSS, under [data-intro]; transform only, never hidden) and the scene's intro settles it.
// - Motion follows the site-wide preference (../motion.js): off by default under reduced motion, where the control
//   lets the visitor opt in. The control is shown whenever the scene can loop, its label always says what it will
//   do, and only the control changes the preference (kept across pages and visits).
// - Scroll: the scene's camera travels with the native scroll position (read, never changed).
// - The title bar: the name docks into it as the hero leaves (../dock.js), whether or not the scene runs.
// - No WebGL2 (or a failure): html.no-gl, which shows the designed still instead of the canvas.
import { mount } from "./index.js";
import { smooth } from "./math.js";
import { initDock } from "../dock.js";
import { motionOn, setMotion, calm } from "../motion.js";

const root = document.documentElement;
const INTRO_KEY = "scene-intro";
const store = (fn) => { try { return fn(sessionStorage); } catch { return null; } };
const reduced = window.matchMedia("(prefers-reduced-motion: reduce)");

const hero = document.querySelector(".hero");
const stage = hero?.querySelector("[data-scene]");
const names = [...(hero?.querySelectorAll(".hero__name .nm > span") || [])];
const button = hero?.querySelector("[data-motion-toggle]");
let scene = null, level = 0;

// The name: the intro's lift and scale, then a little pointer parallax (the second line moves more).
function nameFrame({ it, T, ptr }) {
  names.forEach((el, i) => {
    const lag = i * 0.07;
    const k = 1 - smooth(T * 0.36 + lag, T + lag, it);
    const px = -ptr[0] * (2.5 + i * 3), py = ptr[1] * (1.2 + i * 1.6);
    el.style.transform = k <= 0 && !px && !py ? "" :
      `translate3d(${px.toFixed(2)}px,calc(${(0.05 * k).toFixed(4)}em + ${py.toFixed(2)}px),0) scale(${(1 + 0.07 * k).toFixed(4)})`;
  });
  // From the first frame on, the script holds the name; the first-paint transform (and its CSS settle) goes.
  if (root.dataset.intro === "") delete root.dataset.intro;
}

function syncButton() {
  if (!button) return;
  const off = !motionOn();
  button.hidden = !scene || scene.failed || level >= 3;
  button.toggleAttribute("data-paused", off);
  button.querySelector("span").textContent = off ? "Play motion" : "Pause motion";
}

function noScene() {
  root.classList.add("no-gl");
  // A first visit without the scene: the name settles at once rather than after the intro's length.
  if (root.dataset.intro === "") root.dataset.intro = "settle";
  syncButton();
}

function boot() {
  if (!stage || scene) return;
  // The intro needs both: motion on, and no reduced-motion request from the browser (an opt-in brings the scene to
  // life, not the fly-through).
  const intro = root.dataset.intro === "" && !reduced.matches && motionOn();
  scene = mount(stage, {
    intro,
    reduced: calm, // motion off: one composed still frame, exactly as for reduced motion
    onFrame: nameFrame,
    onFail: noScene,
    onQuality: (l) => { level = l; syncButton(); },
  });
  if (!scene) return noScene();
  // Under automation only (screenshots, contrast sampling, measurements): the scene, for seek() and stats().
  if (navigator.webdriver) window.__scene = scene;
  if (intro) store((s) => s.setItem(INTRO_KEY, "1"));
  else if (root.dataset.intro === "") delete root.dataset.intro;
  onScroll();
  syncButton();
}

// Scroll, coalesced to one update a frame.
let scrollRaf = 0;
function onScroll() {
  scrollRaf = 0;
  scene?.setScroll(window.scrollY / window.innerHeight);
}

if (hero) {
  try { initDock(); } catch (err) { console.warn(err); }
  window.addEventListener("scroll", () => { if (!scrollRaf) scrollRaf = requestAnimationFrame(onScroll); }, { passive: true });
  onScroll();
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
