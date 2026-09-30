// The hero's flow field as pure math, with no DOM: shared by the canvas runtime (field.js) and the generator of the
// pre-rendered still (still.mjs), so both draw the same composition.
//
// Two currents meet at a seam across the middle of the field. Love (the red team) runs leftwards above it and
// foam (the blue team) rightwards below it; each enters from its own edge. The shear between them rolls up into
// slow eddies along the seam, and particles that linger there mix into iris, the purple of the two combined.
// Every velocity is derived from a stream function, so the flow is divergence-free: particles neither pile up nor
// thin out, and there is no net drift in any direction. Second 60 looks like second 3.

export const K = 12; // trail samples per particle
export const SAMPLE = 1 / 15; // seconds between trail samples, so a trail is about 0.8 s long
export const LEVELS = 4; // colour steps from a current's own ink to iris
export const BUCKETS = LEVELS * 2 - 1; // 0 = love ... LEVELS - 1 = iris ... BUCKETS - 1 = foam
export const WARM = K * SAMPLE; // seconds of flow before the first frame: exactly one full trail

const TAU = Math.PI * 2;

// Small seeded PRNG (mulberry32), so a seed always gives the same field.
export function random(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/**
 * Create a field for a w x h pixel box.
 * opts.seed: PRNG seed. opts.density: particles per 10 000 px². opts.speed: flow speed multiplier.
 */
export function createField(w, h, { seed = 7, density = 13, speed = 1, min = 160, max = 900 } = {}) {
  const f = { w, h, t: 0, clock: 0, ring: 0, rand: random(seed), intro: 1 };
  const S = Math.sqrt(w * h);
  f.U = speed * 0.075 * S; // current speed, px/s
  f.d = 0.13 * S; // half-thickness of the shear layer
  f.cy = h * 0.5;
  f.a1 = 0.035 * h; f.q1 = TAU / (1.3 * w); f.p1 = f.rand() * TAU;
  f.a2 = 0.02 * h; f.q2 = TAU / (0.55 * w); f.p2 = f.rand() * TAU;
  // Eddies along the seam, evenly spaced.
  const spacing = Math.max(0.3 * S, 150);
  f.nv = Math.min(4, Math.max(2, Math.round(w / spacing)));
  const R = 0.5 * (w / f.nv);
  f.iR2 = 1 / (R * R);
  f.G = -1.25 * f.U * R; // negative: turns the same way as the shear (top leftwards, bottom rightwards)
  f.vx = new Float32Array(f.nv); f.vy = new Float32Array(f.nv); f.vp = new Float32Array(f.nv);
  for (let k = 0; k < f.nv; k++) f.vp[k] = f.rand() * TAU;
  // Gentle, uniform curl noise so the streams never look ruled.
  f.na = TAU / (0.9 * S); f.nb = TAU / (0.7 * S); f.nA = 0.35 * f.U / f.nb;

  const n = (f.n = Math.round(Math.min(max, Math.max(min, (w * h * density) / 10000))));
  f.X = new Float32Array(n); f.Y = new Float32Array(n); // positions
  f.RX = new Float32Array(n); f.RY = new Float32Array(n); // drawn positions (differ only during the intro)
  f.M = new Float32Array(n); // mix toward iris, 0..1
  f.T = new Uint8Array(n); // current: 0 love, 1 foam
  f.A = new Float32Array(n); // age, s
  f.L = new Float32Array(n); // lifetime, s; after it the particle freezes while its trail drains, then reappears
  f.D = new Float32Array(n); // time left draining (> 0 while frozen)
  f.B = new Uint8Array(n); // colour bucket
  f.HX = new Float32Array(n * K); f.HY = new Float32Array(n * K); // trail ring buffers
  eddies(f);
  for (let i = 0; i < n; i++) {
    reseed(f, i);
    f.A[i] = f.rand() * f.L[i]; // stagger the recycling
  }
  return f;
}

export function seam(f, x) {
  return f.cy + f.a1 * Math.sin(f.q1 * x + 0.07 * f.t + f.p1) + f.a2 * Math.sin(f.q2 * x - 0.11 * f.t + f.p2);
}

function eddies(f) {
  for (let k = 0; k < f.nv; k++) {
    const x = ((k + 0.5) * f.w) / f.nv + (0.06 * f.w / f.nv) * Math.sin(0.09 * f.t + f.vp[k]);
    f.vx[k] = x;
    f.vy[k] = seam(f, x);
  }
}

// Velocity at (x, y) at time t, written to out.u / out.v; out.e is the signed distance to the seam in
// shear-layer units. Stream functions: shear -U d ln cosh(e) (sign folded in), eddies G exp(-r²/R²), noise.
function velocity(f, x, y, t, out) {
  const s1 = f.q1 * x + 0.07 * t + f.p1, s2 = f.q2 * x - 0.11 * t + f.p2;
  const ys = f.cy + f.a1 * Math.sin(s1) + f.a2 * Math.sin(s2);
  const dys = f.a1 * f.q1 * Math.cos(s1) + f.a2 * f.q2 * Math.cos(s2);
  const e = (y - ys) / f.d;
  const ex = Math.exp(-2 * Math.abs(e));
  const th = (e < 0 ? -1 : 1) * (1 - ex) / (1 + ex); // tanh(e)
  let u = f.U * th, v = f.U * th * dys;
  for (let k = 0; k < f.nv; k++) {
    const dx = x - f.vx[k], dy = y - f.vy[k];
    const g = 2 * f.G * f.iR2 * Math.exp(-(dx * dx + dy * dy) * f.iR2);
    u -= g * dy;
    v += g * dx;
  }
  const ax = f.na * x + 0.05 * t, by = f.nb * y - 0.04 * t, ax2 = 1.9 * f.na * x - 0.07 * t + 1.3, by2 = 1.7 * f.nb * y + 0.06 * t + 0.4;
  u += f.nA * (f.nb * Math.sin(ax) * Math.cos(by) + 0.85 * f.nb * Math.sin(ax2) * Math.cos(by2));
  v -= f.nA * (f.na * Math.cos(ax) * Math.sin(by) + 0.95 * f.na * Math.cos(ax2) * Math.sin(by2));
  out.u = u; out.v = v; out.e = e;
}

// Drawn position. During the intro (f.intro < 1) every particle starts squashed onto a thin band along the seam
// and opens out to its place, the left end of the seam first, so the line unfurls across the field.
export const INTRO_FROM = 0.05;
function place(f, i) {
  const x = f.X[i], y = f.Y[i];
  f.RX[i] = x;
  if (f.intro >= 1) f.RY[i] = y;
  else {
    const u = Math.min(1, Math.max(0, (f.intro - 0.35 * Math.min(1, Math.max(0, x / f.w))) / 0.65));
    const e = u * u * (3 - 2 * u); // smoothstep
    const ys = seam(f, x);
    f.RY[i] = ys + (y - ys) * (INTRO_FROM + (1 - INTRO_FROM) * e);
  }
  const q = Math.round(f.M[i] * (LEVELS - 1));
  f.B[i] = f.T[i] === 0 ? q : BUCKETS - 1 - q;
}

export function resetTrail(f, i) {
  const o = i * K;
  f.HX.fill(f.RX[i], o, o + K);
  f.HY.fill(f.RY[i], o, o + K);
}

// A fresh particle anywhere in the box, on the current of its side of the seam, pre-mixed near the seam.
// Recycling particles this way keeps the density even for good (the pointer wake can push holes into the eddies).
function reseed(f, i) {
  const x = f.rand() * f.w, y = f.rand() * f.h;
  const e = (y - seam(f, x)) / f.d;
  f.X[i] = x; f.Y[i] = y; f.T[i] = e < 0 ? 0 : 1;
  f.M[i] = Math.min(1, Math.exp(-1.2 * e * e) * (0.4 + 0.7 * f.rand()));
  f.A[i] = 0; f.L[i] = 7 + 8 * f.rand(); f.D[i] = 0;
  place(f, i);
  resetTrail(f, i);
}

// A particle that left the box re-enters from its own current's upstream edge, unmixed.
function respawn(f, i) {
  const love = f.T[i] === 0;
  const x = love ? f.w + 2 + f.rand() * 6 : -2 - f.rand() * 6;
  const ys = seam(f, Math.min(f.w, Math.max(0, x)));
  const y = love ? f.h * 0.02 + f.rand() * Math.max(1, ys - 0.25 * f.d - f.h * 0.02) : ys + 0.25 * f.d + f.rand() * Math.max(1, f.h * 0.98 - ys - 0.25 * f.d);
  f.X[i] = x; f.Y[i] = y; f.M[i] = 0; f.A[i] = 0;
  place(f, i);
  resetTrail(f, i);
}

const k1 = { u: 0, v: 0, e: 0 }, k2 = { u: 0, v: 0, e: 0 };

/**
 * Advance the field by dt seconds. p is the pointer wake, or null:
 * { x, y, vx, vy } in field pixels and px/s (already smoothed), plus r (radius).
 */
export function step(f, dt, p = null) {
  const { X, Y, M, n } = f;
  const t = f.t, half = dt * 0.5, mixRate = 0.35 * dt;
  let wake = false, pr2 = 0, pvx = 0, pvy = 0, pspeed = 0;
  if (p) {
    pspeed = Math.hypot(p.vx, p.vy);
    if (pspeed > 4) {
      const cap = Math.min(1, 900 / pspeed); // a flick should not fling the whole field
      pvx = p.vx * cap; pvy = p.vy * cap; pspeed *= cap;
      pr2 = p.r * p.r;
      wake = true;
    }
  }
  const margin = 10, drain = K * SAMPLE;
  const { A, L, D } = f;
  for (let i = 0; i < n; i++) {
    if (D[i] > 0) {
      // Frozen: the trail drains into the head (butt caps draw nothing once it is gone), then a new particle.
      D[i] -= dt;
      if (D[i] <= 0) reseed(f, i);
      continue;
    }
    if ((A[i] += dt) > L[i]) { D[i] = drain + 0.05; continue; }
    let x = X[i], y = Y[i];
    // Midpoint (RK2) step: stable orbits in the eddies, no slow outward spiral.
    velocity(f, x, y, t, k1);
    velocity(f, x + k1.u * half, y + k1.v * half, t + half, k2);
    x += k2.u * dt;
    y += k2.v * dt;
    let m = M[i] + mixRate * Math.exp(-1.5 * k2.e * k2.e);
    if (wake) {
      // The wake: particles near the pointer are dragged along its path and pushed slightly aside.
      // It scales with the pointer's (critically damped) velocity, so it fades out when the pointer rests.
      const dx = x - p.x, dy = y - p.y, d2 = dx * dx + dy * dy;
      if (d2 < pr2) {
        let w = 1 - d2 / pr2;
        w *= w;
        const d = Math.sqrt(d2) + 1e-3;
        x += (0.55 * pvx + 0.06 * pspeed * (dx / d)) * w * dt;
        y += (0.55 * pvy + 0.06 * pspeed * (dy / d)) * w * dt;
        m += w * Math.min(1, pspeed / 600) * 1.5 * dt; // stirring mixes the currents
      }
    }
    X[i] = x; Y[i] = y; M[i] = m > 1 ? 1 : m;
    if (x < -margin || x > f.w + margin || y < -margin || y > f.h + margin) respawn(f, i);
    else place(f, i);
  }
  f.t = t + dt;
  eddies(f);
  f.clock += dt;
  if (f.clock >= SAMPLE) {
    f.clock %= SAMPLE;
    f.ring = (f.ring + 1) % K;
    const { RX, RY, HX, HY, ring } = f;
    for (let i = 0; i < n; i++) {
      HX[i * K + ring] = RX[i];
      HY[i * K + ring] = RY[i];
    }
  }
}

// Point j of particle i's trail, newest first: j = 0 is the drawn position, j >= 1 walks back through history.
export function trailX(f, i, j) {
  return j === 0 ? f.RX[i] : f.HX[i * K + ((f.ring - (j - 1) + K) % K)];
}
export function trailY(f, i, j) {
  return j === 0 ? f.RY[i] : f.HY[i * K + ((f.ring - (j - 1) + K) % K)];
}

// Run the field forward without drawing, one trail sample per step, until every trail is full.
export function warm(f, seconds = WARM, dt = SAMPLE) {
  const steps = Math.round(seconds / dt);
  for (let s = 0; s < steps; s++) step(f, dt);
}

// Set the intro progress (0 = everything on the seam, 1 = done) and redraw positions and trails to match.
export function setIntro(f, progress, resetTrails = false) {
  f.intro = progress;
  for (let i = 0; i < f.n; i++) {
    place(f, i);
    if (resetTrails) resetTrail(f, i);
  }
}
