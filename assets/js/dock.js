// The home page's hero converts into the title bar. There is no bar over the landing: just the landing's own quiet
// bar (.hero-bar: the same nav and tools). As the page scrolls, each line of the big name moves and shrinks into its
// word of the title bar's wordmark (FLIP: the start and end boxes are measured once per layout; every frame in
// between is a transform), arriving where the line would naturally pass the bar, and cross-fades into the real
// wordmark. The bar's surface slides in under the name on the way, so nothing ever scrolls under a bare wordmark.
// Scrolling back reverses it.
// - Where CSS scroll-driven animations exist, it is pure CSS: keyframes generated from the measured geometry, on
//   animation-timeline: scroll(root), with no script per frame. Elsewhere a rAF loop applies the same states
//   (#dock=js in the URL forces that path, for testing).
// - Only transform, opacity and visibility change while scrolling; nothing is read from layout then.
// - Exactly one nav is exposed at a time: the landing's bar until the title bar starts to arrive, then the title bar
//   (the other one is visibility: hidden, so it is out of the tab order and the accessibility tree).
// - Narrow screens, where the title bar's nav has a row of its own under the wordmark ("stacked"): the docking name
//   would cross that row, so the bar fades in place and its nav row appears only once the name has docked.
// - Reduced motion: no morph; the bar and the wordmark fade in once the name has scrolled away.
import { clamp, smooth } from "./scene/math.js";
import { reducedMotion as reduced } from "./util.js";

const ease = (t) => (t < 0.5 ? 4 * t * t * t : 1 - (-2 * t + 2) ** 3 / 2);
const TIMELINE = "animation-timeline:scroll(root block)";

export function initDock() {
  const root = document.documentElement;
  const hero = document.querySelector(".hero");
  const header = document.querySelector(".site-header");
  const lines = [...document.querySelectorAll(".hero__name .nm")];
  const words = [...document.querySelectorAll(".site-header .brand .bw")];
  const brand = header?.querySelector(".brand");
  const role = hero?.querySelector(".hero__role");
  const heroBar = hero?.querySelector(".hero-bar");
  const barNav = header?.querySelector(".site-nav");
  if (!hero || !header || !brand || !lines.length || lines.length !== words.length) return null;
  const forceJs = new URLSearchParams(location.hash.slice(1)).get("dock") === "js";
  const cssMode = !forceJs && typeof CSS !== "undefined" && CSS.supports("animation-timeline: scroll()");
  const style = document.createElement("style");
  style.dataset.dock = "";
  document.head.append(style);
  let G = null, raf = 0;

  function measure() {
    root.classList.add("dock-measure");
    const sy = window.scrollY;
    const hr = hero.getBoundingClientRect();
    // the name's lines in page coordinates; the wordmark's words where the bar sits once it is pinned (top: 0),
    // whatever is above it now (the preview banner, at the top of the page)
    const pin = header.getBoundingClientRect().top - (parseFloat(getComputedStyle(header).top) || 0);
    const box = (el, dy) => {
      const r = el.getBoundingClientRect();
      return { cx: r.left + r.width / 2, cy: r.top + r.height / 2 + dy, fs: parseFloat(getComputedStyle(el).fontSize) };
    };
    G = {
      heroTop: hr.top + sy,
      heroH: Math.max(1, hr.height),
      src: lines.map((el) => box(el, sy)),
      dst: words.map((el) => box(el, -pin)),
      narrow: window.innerWidth < 960,
    };
    const br = brand.getBoundingClientRect(), nr = barNav ? barNav.getBoundingClientRect() : null;
    G.stacked = !!nr && nr.top >= br.bottom - 2;
    root.classList.remove("dock-measure");
    // the first line docks where it would naturally pass the bar; the morph starts a little before
    const arrive = (G.src[0].cy - G.heroTop - G.dst[0].cy) / G.heroH;
    G.r1 = clamp(arrive, 0.08, 0.7);
    G.r0 = G.r1 * (G.narrow ? 0.04 : 0.28);
    G.f0 = G.r1 - 0.028;
    G.f1 = G.r1 + 0.004;
    // the bar slides in under the docking name, once the landing's own bar has scrolled away
    G.b1 = G.r1;
    G.b0 = Math.min(G.b1 - 0.02, Math.max(G.r1 - (G.narrow ? 0.12 : 0.17), (header.offsetHeight * 0.8) / G.heroH));
    build();
    paint();
  }

  // The states at progress p (scroll from the hero's top, as a fraction of its height).
  function at(p) {
    const y = p * G.heroH;
    const e = ease(clamp((p - G.r0) / (G.r1 - G.r0), 0, 1));
    const nm = G.src.map((s, i) => {
      const d = G.dst[i];
      const k = 1 + (d.fs / s.fs - 1) * e;
      const tx = e * (d.cx - s.cx);
      const ty = e * (d.cy - (s.cy - G.heroTop - y));
      return { t: `translate3d(${tx.toFixed(2)}px,${ty.toFixed(2)}px,0) scale(${k.toFixed(5)})`, o: 1 - smooth(G.f0, G.f1, p) };
    });
    // the role line gives way as the name rises into the bar (opacity only)
    const fade = 1 - smooth(G.r0 + 0.12 * (G.r1 - G.r0), G.r0 + 0.55 * (G.r1 - G.r0), p);
    const nav = G.stacked ? smooth(G.f1, G.f1 + 0.035, p) : 1;
    return { nm, bar: smooth(G.b0, G.b1, p), brand: smooth(G.f0, G.f1, p), role: fade, nav };
  }

  function build() {
    if (!cssMode || reduced.matches) { style.textContent = ""; return; }
    const ps = new Set([0, G.r0, G.f0, G.f1, G.r1, 1]);
    for (let i = 0; i <= 36; i++) ps.add(G.r0 + ((G.f1 - G.r0) * i) / 36);
    const offs = [...ps].filter((p) => p >= 0 && p <= 1).sort((a, b) => a - b);
    const pc = (p) => `${(p * 100).toFixed(3)}%`;
    const tl = `${TIMELINE};animation-range:${Math.round(G.heroTop)}px ${Math.round(G.heroTop + G.heroH)}px`;
    let css = "";
    lines.forEach((_, i) => {
      css += `@keyframes dock-nm-${i}{${offs.map((p) => { const s = at(p).nm[i]; return `${pc(p)}{transform:${s.t};opacity:${s.o.toFixed(3)}}`; }).join("")}}`;
      css += `.hero__name .nm:nth-child(${i + 1}){animation:dock-nm-${i} linear both;${tl}}`;
    });
    const from = G.stacked ? "none" : "translateY(-101%)";
    css += `@keyframes dock-bar{0%,${pc(G.b0)}{opacity:0;transform:${from};visibility:hidden}${pc(G.b0 + 0.001)}{visibility:visible}${pc(G.b1)},100%{opacity:1;transform:none;visibility:visible}}`;
    if (G.stacked) {
      css += `@keyframes dock-nav{0%,${pc(G.f1)}{opacity:0;transform:translateY(-0.4rem);visibility:hidden}${pc(G.f1 + 0.001)}{visibility:visible}${pc(G.f1 + 0.035)},100%{opacity:1;transform:none;visibility:visible}}`;
      css += `.js .kind-home .site-header .site-nav{animation:dock-nav linear both;${tl}}`;
    }
    css += `@keyframes dock-brand{0%,${pc(G.f0)}{opacity:0;visibility:hidden}${pc(G.f0 + 0.001)}{visibility:visible}${pc(G.f1)},100%{opacity:1;visibility:visible}}`;
    css += `.js .kind-home .site-header{animation:dock-bar linear both;${tl}}`;
    css += `.js .kind-home .site-header .brand{animation:dock-brand linear both;${tl}}`;
    css += `@keyframes dock-role{${offs.map((p) => `${pc(p)}{opacity:${at(p).role.toFixed(3)}}`).join("")}}`;
    css += `.hero__role{animation:dock-role linear both;${tl}}`;
    css += `@keyframes dock-herobar{0%,${pc(G.b0)}{visibility:visible}${pc(G.b0 + 0.001)},100%{visibility:hidden}}`;
    css += `.hero-bar{animation:dock-herobar linear both;${tl}}`;
    style.textContent = css;
  }

  // The fallback (and reduced motion): the same states from script, on scroll.
  function paint() {
    raf = 0;
    if (!G) return;
    const p = clamp((window.scrollY - G.heroTop) / G.heroH, 0, 1);
    if (reduced.matches) {
      root.classList.toggle("is-docked", p >= G.r1);
      if (heroBar) heroBar.style.visibility = p >= G.r1 ? "hidden" : "";
      for (const el of [header, brand, barNav, role, ...lines].filter(Boolean)) { el.style.transform = ""; el.style.opacity = ""; el.style.visibility = ""; }
      return;
    }
    root.classList.remove("is-docked");
    if (cssMode) return;
    const s = at(p);
    lines.forEach((el, i) => { el.style.transform = s.nm[i].t; el.style.opacity = s.nm[i].o.toFixed(3); });
    header.style.opacity = s.bar.toFixed(3);
    header.style.transform = G.stacked ? "" : `translateY(${((s.bar - 1) * 101).toFixed(2)}%)`;
    header.style.visibility = s.bar > 0.001 ? "visible" : "hidden";
    if (barNav) {
      barNav.style.opacity = G.stacked ? s.nav.toFixed(3) : "";
      barNav.style.transform = G.stacked ? `translateY(${((s.nav - 1) * 0.4).toFixed(3)}rem)` : "";
      barNav.style.visibility = G.stacked ? (s.nav > 0.001 ? "visible" : "hidden") : "";
    }
    brand.style.opacity = s.brand.toFixed(3);
    brand.style.visibility = s.brand > 0.01 ? "visible" : "hidden";
    if (role) role.style.opacity = s.role.toFixed(3);
    if (heroBar) heroBar.style.visibility = s.bar > 0.001 ? "hidden" : "visible";
  }
  const onScroll = () => { if (!raf) raf = requestAnimationFrame(paint); };
  window.addEventListener("scroll", onScroll, { passive: true });
  const ro = new ResizeObserver(() => measure());
  ro.observe(hero);
  window.addEventListener("resize", measure);
  reduced.addEventListener("change", () => { build(); paint(); });
  document.fonts?.ready.then(measure);
  measure();
  root.classList.add(cssMode ? "dock-css" : "dock-js");
  return { mode: cssMode ? "css" : "js", update: measure, geometry: () => G };
}
