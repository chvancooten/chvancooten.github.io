// The home landing: mounts the scene behind the name once the page has painted, and ties it to the page.
// - The name is painted from the first frame. On the first visit of a session it starts slightly lifted and
//   enlarged (CSS, under [data-intro]; transform only, never hidden) and the scene's intro settles it.
// - The pause control: shown while the scene can loop; the choice lasts for the session.
// - Scroll: the scene's camera travels with the native scroll position (read, never changed).
// - The title bar: the name docks into it as the hero leaves (../dock.js), whether or not the scene runs.
// - No WebGL2 (or a failure): html.no-gl, which shows the designed still instead of the canvas.
import { mount } from "./index.js";
import { smooth } from "./math.js";
import { initDock } from "../dock.js";

const root = document.documentElement;
const PAUSE_KEY = "motion-paused";
const INTRO_KEY = "scene-intro";
const store = (fn) => { try { return fn(sessionStorage); } catch { return null; } };
const reduced = window.matchMedia("(prefers-reduced-motion: reduce)");

const hero = document.querySelector(".hero");
const stage = hero?.querySelector("[data-scene]");
const names = [...(hero?.querySelectorAll(".hero__name .nm > span") || [])];
const button = hero?.querySelector("[data-motion-toggle]");
let scene = null, level = 0;

const isPaused = () => store((s) => s.getItem(PAUSE_KEY)) === "1";

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
  const p = isPaused();
  button.hidden = !scene || scene.failed || reduced.matches || level >= 3;
  button.toggleAttribute("data-paused", p);
  button.querySelector("span").textContent = p ? "Play motion" : "Pause motion";
}

function noScene() {
  root.classList.add("no-gl");
  // A first visit without the scene: the name settles at once rather than after the intro's length.
  if (root.dataset.intro === "") root.dataset.intro = "settle";
  syncButton();
}

function boot() {
  if (!stage || scene) return;
  const intro = root.dataset.intro === "" && !reduced.matches && !isPaused();
  scene = mount(stage, {
    intro,
    paused: isPaused(),
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
  button?.addEventListener("click", () => {
    const p = !isPaused();
    store((s) => s.setItem(PAUSE_KEY, p ? "1" : "0"));
    if (p) scene?.pause(); else scene?.resume();
    syncButton();
  });
  reduced.addEventListener("change", syncButton);
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
