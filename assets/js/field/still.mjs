// Writes the pre-rendered stills of the hero field (the no-JS and pre-boot fallback) from the same simulation the
// canvas runs, so the swap from still to canvas keeps the composition. Not part of the site bundle.
//
//   node assets/js/field/still.mjs      (from the repository root; rewrites static/field/*.svg)
//
// Colours are not baked in: each group gets a bucket class (b0 love ... b3 iris ... b6 foam) styled with the page's
// --field-* custom properties, which reach the <use> shadow tree by inheritance (fallbacks are the dark inks).
import { writeFileSync, mkdirSync } from "node:fs";
import { createField, warm, BUCKETS, K, WARM } from "./sim.js";

// [name, width, height, particle share, edge fade (same ramps as the canvas mask in field.js)]
const STILLS = [
  ["wide", 720, 836, 0.55, { x: [[0, 0], [0.28, 1], [1, 1]], y: [[0, 0], [0.08, 1], [0.9, 1], [1, 0]] }],
  ["band", 640, 340, 0.8, { x: [[0, 0], [0.12, 1], [0.88, 1], [1, 0]], y: [[0, 0], [0.22, 1], [0.8, 1], [1, 0]] }],
];
// Trails are drawn in two bands (head, tail) from every other history sample.
const BANDS = [[0, 6, 0.5, 1.2], [6, K, 0.18, 1]];
const SCALE = 2; // coordinates are stored as integers in half pixels

function trail(f, i, j) {
  if (j === 0) return [f.RX[i], f.RY[i]];
  const o = i * K + ((f.ring - j + 1 + K) % K);
  return [f.HX[o], f.HY[o]];
}

// Numbers joined with the fewest separators: a minus sign separates on its own.
const join = (nums) => nums.reduce((out, n, k) => out + (k && n >= 0 ? " " : "") + n, "");

function pathFor(f, ids, s0, s1) {
  let d = "";
  for (const i of ids) {
    const pts = [];
    for (let j = s0; j <= s1; j += 2) pts.push(trail(f, i, j).map((v) => Math.round(v * SCALE)));
    const deltas = [];
    for (let k = 1; k < pts.length; k++) deltas.push(pts[k][0] - pts[k - 1][0], pts[k][1] - pts[k - 1][1]);
    d += `M${join(pts[0])}l${join(deltas)}`;
  }
  return d;
}

const INK = { love: "var(--field-love,#eb6f92)", iris: "var(--field-iris,#c4a7e7)", foam: "var(--field-foam,#9ccfd8)" };
const mix = (a, k) => `color-mix(in srgb,${INK[a]} ${k}%,${INK.iris})`;
const STYLE =
  "path{fill:none;vector-effect:non-scaling-stroke}" +
  [INK.love, mix("love", 67), mix("love", 33), INK.iris, mix("foam", 33), mix("foam", 67), INK.foam]
    .map((c, b) => `.b${b}{stroke:${c}}`).join("");

mkdirSync("static/field", { recursive: true });
for (const [name, w, h, share, fade] of STILLS) {
  const f = createField(w, h, { seed: 7 });
  warm(f, WARM);
  const keep = [];
  for (let i = 0; i < f.n; i++) if ((i * 0.618034) % 1 < share) keep.push(i);
  // The edge fade is baked in: each trail takes the fade at its head, in five levels, so the still needs no
  // masks or blend modes (both are costly to paint on the first frame).
  const ramp = (stops, u) => {
    for (let k = 1; k < stops.length; k++) {
      const [o0, a0] = stops[k - 1], [o1, a1] = stops[k];
      if (u <= o1) return a0 + ((a1 - a0) * (u - o0)) / (o1 - o0 || 1);
    }
    return stops.at(-1)[1];
  };
  const level = (i) => Math.round(5 * ramp(fade.x, Math.min(1, Math.max(0, f.RX[i] / w))) * ramp(fade.y, Math.min(1, Math.max(0, f.RY[i] / h)))) / 5;
  const groups = [];
  for (let b = 0; b < BUCKETS; b++) {
    const paths = [];
    for (const lv of [0.2, 0.4, 0.6, 0.8, 1]) {
      const ids = keep.filter((i) => f.B[i] === b && Math.abs(level(i) - lv) < 0.01);
      if (!ids.length) continue;
      for (const [s0, s1, a, lw] of BANDS) paths.push(`<path stroke-opacity="${+(a * lv).toFixed(3)}" stroke-width="${lw}" d="${pathFor(f, ids, s0, s1)}"/>`);
    }
    if (paths.length) groups.push(`<g class="b${b}">${paths.join("")}</g>`);
  }
  const W = w * SCALE, H = h * SCALE;
  const svg =
    `<svg xmlns="http://www.w3.org/2000/svg" id="still" viewBox="0 0 ${W} ${H}" preserveAspectRatio="xMidYMid slice">` +
    `<style>${STYLE}</style><g stroke-linejoin="round">${groups.join("")}</g></svg>\n`;
  writeFileSync(`static/field/still-${name}.svg`, svg);
  console.log(`static/field/still-${name}.svg: ${keep.length} of ${f.n} particles, ${svg.length} bytes`);
}
