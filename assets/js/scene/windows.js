// C3 "Windows": where the home page shows the scene. The content never moves; what changes with scroll is only the
// scene inside its frames. The canvas is fixed behind the page, and each frame is a view of the same world, masked
// in the shader (soft edges, in device pixels), so there is no overlay element anywhere:
// - the landing, with its own camera (the intro, then rest with pointer parallax and a slow drift), and composition
//   veils that keep its copy legible: a column under the copy on wide screens, bands above and below on narrow ones;
// - the full-bleed windows between the chapters (.window), each with its own camera and subject: W1 the two
//   currents side by side, W2 the red current, W3 the blue one, W4 the vortex where they mix into purple.
//   As a band crosses the screen its camera only cranes (moves vertically, across the flow). A camera moving along
//   the flow would make the particles seem to run backwards, as if the scroll rewound time; the simulation time
//   itself only ever moves forward.
// createWindows() returns the views for the scene (index.js, opts.views) and what they depend on: visible() (is any
// frame on screen), vignette(theme) and layout() (for measurements); update() re-measures, destroy() stops.
import { clamp, mix, smooth } from "./math.js";

// A pose as the band enters (a) and as it leaves (b), framed by horizontal field of view (hfov), so a window keeps
// its composition from a phone to a wide screen. portrait: the same for narrow screens, where a band is close to
// 4:3 (otherwise their hfov is 0.74 times the wide one).
const WINDOWS = [
  { a: { pos: [12, 6.6, 18], tgt: [0, 0.4, 14], hfov: 60, focus: 12.5, ap: 0.6, blur: 8, roll: 0 }, b: { pos: [12, 5.2, 18], tgt: [0, -0.3, 14] } },
  { a: { pos: [9, 2.1, 8], tgt: [5.2, 1.1, 19], hfov: 58, focus: 10, ap: 0.6, blur: 8, roll: 0.06 }, b: { pos: [9, 1.0, 8], tgt: [5.2, 0.6, 19], roll: 0.04 } },
  { a: { pos: [-4.4, -1.9, 7.5], tgt: [-6.6, 0.4, 18.5], hfov: 50, focus: 11, ap: 0.6, blur: 8, roll: -0.08 }, b: { pos: [-4.4, -3.0, 7.5], tgt: [-6.6, -0.1, 18.5], roll: -0.06 } },
  {
    form: 1,
    a: { pos: [0, 10, 16], tgt: [0, -0.4, 0], hfov: 62, focus: 18.5, ap: 1.4, blur: 14, roll: 0.05 }, b: { pos: [0, 8.4, 16.6], tgt: [0, -0.8, 0], roll: 0.04 },
    portrait: { a: { pos: [0, 10.5, 15], tgt: [0, -0.3, 0], hfov: 64, focus: 18, ap: 1.4, blur: 14, roll: 0.03 }, b: { pos: [0, 8.8, 15.8], tgt: [0, -0.6, 0], roll: 0.02 } },
    glows: [{ p: [0, 0, 0], r: 0.22, a: { dark: 0.1, light: 0.07 }, ink: 4 }],
    trail: { time: 1.1, width: 0.7, alpha: { dark: 0.6, light: 0.55 } },
  },
];

const vmix = (a, b, k) => a.map((x, i) => mix(x, b[i], k));
function poseMix(a, b, k) {
  const o = { pos: vmix(a.pos, b.pos ?? a.pos, k), tgt: vmix(a.tgt, b.tgt ?? a.tgt, k) };
  for (const f of ["hfov", "roll", "focus", "ap", "blur"]) o[f] = mix(a[f] ?? 0, b[f] ?? a[f] ?? 0, k);
  o.exp = 1;
  return o;
}

export function createWindows({ hero, frames, header, reduced }) {
  const main = hero.closest("main") || document.body;
  const q = (s) => hero.querySelector(s);
  const copy = { role: q(".hero__role"), lede: q(".hero__lede"), cta: q(".hero__cta"), cue: q(".cue") };
  const first = hero.nextElementSibling;
  let L = null;

  // An element's layout box in page coordinates (CSS px), without transforms: the intro moves the copy a little
  // with transforms, and the veils belong to where it comes to rest.
  const page = (el) => {
    let x = 0, y = 0;
    for (let e = el; e; e = e.offsetParent) { x += e.offsetLeft; y += e.offsetTop; }
    return { x0: x, y0: y, x1: x + el.offsetWidth, y1: y + el.offsetHeight };
  };
  function measure() {
    const W = document.documentElement.clientWidth;
    L = {
      W,
      desk: W >= 960,
      header: header ? header.offsetHeight : 64,
      hero: page(hero),
      first: first ? page(first).y0 : page(hero).y1,
      windows: frames.map(page),
      copy: Object.fromEntries(Object.entries(copy).filter(([, el]) => el).map(([k, el]) => [k, page(el)])),
    };
  }

  const sy = () => window.scrollY;
  // 0 in the landing, 1 once the first section is well in view
  const heroK = (H) => smooth(0, Math.max(1, L.first - 0.32 * H), sy());

  // The landing's veils, attached to the page (they scroll with the copy, so they never slide over it).
  function heroVeil(s, W) {
    const c = L.copy;
    if (L.desk) {
      const colX = Math.max(c.lede?.x1 ?? 0, c.cta?.x1 ?? 0, c.role?.x1 ?? 0) + 24;
      return { colX, colS: 0.9, bottomY: (c.cue?.y0 ?? L.hero.y1 - 80) - 20 - s, bottomS: 0.82, topH: L.header + 12, topS: 0.85, f: Math.max(140, 0.12 * W) };
    }
    return { topH: Math.max(L.header + 8, (c.role?.y1 ?? 0) + 16 - s), topS: 0.9, bottomY: (c.lede?.y0 ?? 0.6 * L.hero.y1) - 18 - s, bottomS: 0.93, f: 90 };
  }

  function views(e) {
    if (!L) measure();
    const s = sy(), { W, H } = e;
    const out = [];
    if (L.hero.y1 - s > 0) {
      out.push({ id: "hero", rect: { x0: -400, y0: L.hero.y0 - 400 - s, x1: W + 400, y1: L.hero.y1 - s, f: 0.24 * H }, veil: heroVeil(s, W) });
    }
    L.windows.forEach((r, i) => {
      const y0 = r.y0 - s, y1 = r.y1 - s, h = y1 - y0;
      if (h <= 0 || y1 < 0 || y0 > H) return;
      const P = WINDOWS[i % WINDOWS.length];
      const S = !L.desk && P.portrait ? P.portrait : P;
      // where the band is: 0 entering at the bottom, 1 leaving at the top (the middle under reduced motion)
      const p = clamp(((y0 + y1) / 2 - H / 2) / (H / 2 + h / 2), -1, 1);
      const pose = poseMix(S.a, S.b, reduced.matches ? 0.5 : (1 - p) / 2);
      const hf = pose.hfov * (L.desk || P.portrait ? 1 : 0.74);
      pose.fov = (2 * Math.atan(Math.tan((hf * Math.PI) / 360) / (W / H)) * 180) / Math.PI;
      // the lens shift keeps the subject centred in the band, wherever the band is on the screen
      pose.shift = [0, 1 - (y0 + y1) / H];
      out.push({ id: `w${i + 1}`, rect: { x0: -400, y0, x1: W + 400, y1, f: 0.34 * h }, pose, form: P.form || 0, glows: P.glows, trail: P.trail });
    });
    return out;
  }

  const visible = () => {
    if (!L) measure();
    const s = sy(), H = window.innerHeight;
    return L.hero.y1 - s > 0 || L.windows.some((r) => r.y1 - s > 0 && r.y0 - s < H);
  };
  const vignette = (theme, H) => mix(theme === "light" ? 0.3 : 0.55, 0, heroK(H));

  measure();
  const ro = new ResizeObserver(measure);
  ro.observe(main);
  window.addEventListener("resize", measure);
  return {
    views,
    visible,
    vignette,
    layout: () => L,
    update: measure,
    destroy() {
      ro.disconnect();
      window.removeEventListener("resize", measure);
    },
  };
}
