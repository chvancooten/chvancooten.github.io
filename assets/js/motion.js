// One motion preference for the whole site, for the hero scene and any other scene on a page: localStorage
// "motion" = "on" | "off", kept across pages and visits, and shared by open tabs. Without a stored choice it follows
// the browser: off under prefers-reduced-motion: reduce, on otherwise, so the pause control is how a visitor who
// asked for less motion opts in. The inline <head> script applies it before first paint as <html data-motion> (and
// skips the intro when it is off). Nothing but setMotion() changes it: scrolling, tab visibility or the end of the
// intro never resume a paused scene.
//   motionOn()        the current state
//   setMotion(on)     the visitor's choice (the pause control)
//   calm              a MediaQueryList-like source for a scene: .matches while motion is off, "change" events
const KEY = "motion";
const root = document.documentElement;
const media = window.matchMedia("(prefers-reduced-motion: reduce)");

function stored() {
  try {
    const v = localStorage.getItem(KEY);
    return v === "on" || v === "off" ? v : null;
  } catch {
    return null;
  }
}
let fallback = null; // the visitor's choice, where storage is unavailable (it then lasts for this page only)
const current = () => fallback ?? stored() ?? (media.matches ? "off" : "on");
export const motionOn = () => current() === "on";

// Every bundle that imports this module shares one state (storage and the attribute on <html>), and the event fires
// once per actual change, whichever copy notices it first.
function sync() {
  const v = current();
  if (root.dataset.motion === v) return;
  root.dataset.motion = v;
  document.dispatchEvent(new CustomEvent("motionchange", { detail: v === "on" }));
}
export function setMotion(on) {
  const v = on ? "on" : "off";
  try {
    localStorage.setItem(KEY, v);
  } catch {
    fallback = v;
  }
  sync();
}
window.addEventListener("storage", (e) => { if (e.key === KEY || e.key === null) sync(); });
media.addEventListener("change", () => { if (!stored()) sync(); });

const listeners = new Map();
export const calm = {
  get matches() { return !motionOn(); },
  addEventListener(type, fn) {
    if (type !== "change" || listeners.has(fn)) return;
    const h = () => fn({ matches: calm.matches });
    listeners.set(fn, h);
    document.addEventListener("motionchange", h);
  },
  removeEventListener(type, fn) {
    const h = listeners.get(fn);
    if (h) document.removeEventListener("motionchange", h);
    listeners.delete(fn);
  },
};
