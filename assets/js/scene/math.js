// Vector, matrix and easing helpers for the scene. Matrices are column-major 4x4 (WebGL order).
export const clamp = (x, a, b) => Math.min(b, Math.max(a, x));
export const mix = (a, b, t) => a + (b - a) * t;
export const smooth = (a, b, x) => {
  const t = clamp((x - a) / (b - a), 0, 1);
  return t * t * (3 - 2 * t);
};
export const easeOutCubic = (t) => 1 - Math.pow(1 - clamp(t, 0, 1), 3);

const sub = (a, b) => [a[0] - b[0], a[1] - b[1], a[2] - b[2]];
const dot = (a, b) => a[0] * b[0] + a[1] * b[1] + a[2] * b[2];
const cross = (a, b) => [a[1] * b[2] - a[2] * b[1], a[2] * b[0] - a[0] * b[2], a[0] * b[1] - a[1] * b[0]];
const norm = (a) => {
  const l = Math.hypot(a[0], a[1], a[2]) || 1;
  return [a[0] / l, a[1] / l, a[2] / l];
};

// Camera basis (right, up, forward) for a pose, with roll in radians around the forward axis.
export function basis(pos, tgt, roll = 0) {
  const f = norm(sub(tgt, pos));
  let r = cross(f, [0, 1, 0]);
  r = Math.hypot(r[0], r[1], r[2]) < 1e-4 ? [1, 0, 0] : norm(r);
  let u = cross(r, f);
  if (roll) {
    const c = Math.cos(roll), s = Math.sin(roll);
    const r2 = [0, 1, 2].map((i) => r[i] * c + u[i] * s);
    u = [0, 1, 2].map((i) => u[i] * c - r[i] * s);
    r = r2;
  }
  return { r, u, f };
}

// View-projection for a pose: a perspective with a vertical fov in degrees, plus a lens shift in NDC units, so the
// subject can be framed off-centre (beside the copy) without turning the camera.
export function viewProj(out, pose, aspect, near = 0.05, far = 400) {
  const { r, u, f } = basis(pose.pos, pose.tgt, pose.roll || 0);
  const e = pose.pos;
  const t = 1 / Math.tan((pose.fov * Math.PI) / 360);
  const [sx, sy] = pose.shift || [0, 0];
  const a = t / aspect, c = -(far + near) / (far - near), d = (-2 * far * near) / (far - near);
  // Rows of projection x view; the lens shift adds shift * w to x and y (w = distance along the view axis).
  const w = [f[0], f[1], f[2], -dot(f, e)];
  const rows = [
    [a * r[0], a * r[1], a * r[2], -a * dot(r, e)],
    [t * u[0], t * u[1], t * u[2], -t * dot(u, e)],
    [-c * f[0], -c * f[1], -c * f[2], c * dot(f, e) + d],
    w,
  ];
  for (let i = 0; i < 4; i++) {
    rows[0][i] += sx * w[i];
    rows[1][i] += sy * w[i];
  }
  for (let col = 0; col < 4; col++) for (let row = 0; row < 4; row++) out[col * 4 + row] = rows[row][col];
  return out;
}

// Screen position (pixels, origin bottom left) and depth of a world point, or null behind the camera.
export function project(m, p, w, h) {
  const x = m[0] * p[0] + m[4] * p[1] + m[8] * p[2] + m[12];
  const y = m[1] * p[0] + m[5] * p[1] + m[9] * p[2] + m[13];
  const q = m[3] * p[0] + m[7] * p[1] + m[11] * p[2] + m[15];
  if (q <= 0.01) return null;
  return [((x / q) * 0.5 + 0.5) * w, ((y / q) * 0.5 + 0.5) * h, q];
}

// Monotone cubic (Fritsch-Carlson) through (xs, ys), flat at both ends: the speed eases in and out.
function monotone(xs, ys) {
  const n = xs.length, d = [], m = new Array(n).fill(0);
  for (let i = 0; i < n - 1; i++) d[i] = (ys[i + 1] - ys[i]) / (xs[i + 1] - xs[i]);
  for (let i = 1; i < n - 1; i++) m[i] = d[i - 1] * d[i] <= 0 ? 0 : (2 * d[i - 1] * d[i]) / (d[i - 1] + d[i]);
  return (x) => {
    if (x <= xs[0]) return ys[0];
    if (x >= xs[n - 1]) return ys[n - 1];
    let i = 0;
    while (x > xs[i + 1]) i++;
    const h = xs[i + 1] - xs[i], t = (x - xs[i]) / h, t2 = t * t, t3 = t2 * t;
    return (2 * t3 - 3 * t2 + 1) * ys[i] + (t3 - 2 * t2 + t) * h * m[i] + (-2 * t3 + 3 * t2) * ys[i + 1] + (t3 - t2) * h * m[i + 1];
  };
}

const catmull = (p0, p1, p2, p3, t) =>
  0.5 * (2 * p1 + (-p0 + p2) * t + (2 * p0 - 5 * p1 + 4 * p2 - p3) * t * t + (-p0 + 3 * p1 - 3 * p2 + p3) * t * t * t);

// A camera path through keys [{ t, pos, tgt, roll, fov, focus, ap, blur, exp, shift }]. Time maps to a key index
// through a monotone cubic (smooth speed, eased at both ends), and the pose between keys is a Catmull-Rom spline
// through them, so the camera curves through the keys rather than turning at them.
const SCALARS = ["roll", "fov", "focus", "ap", "blur", "exp"];
export function makePath(keys) {
  const n = keys.length;
  const index = monotone(keys.map((k) => k.t), keys.map((_, i) => i));
  return (t, out) => {
    const s = index(t);
    const i = Math.min(n - 2, Math.max(0, Math.floor(s))), f = s - i;
    const k0 = keys[Math.max(0, i - 1)], k1 = keys[i], k2 = keys[i + 1], k3 = keys[Math.min(n - 1, i + 2)];
    out.pos = [0, 1, 2].map((c) => catmull(k0.pos[c], k1.pos[c], k2.pos[c], k3.pos[c], f));
    out.tgt = [0, 1, 2].map((c) => catmull(k0.tgt[c], k1.tgt[c], k2.tgt[c], k3.tgt[c], f));
    for (const key of SCALARS) out[key] = catmull(k0[key], k1[key], k2[key], k3[key], f);
    const e = f * f * (3 - 2 * f);
    out.shift = [mix(k1.shift[0], k2.shift[0], e), mix(k1.shift[1], k2.shift[1], e)];
    return out;
  };
}

// Blend two key lists with the same times and fields (landscape and portrait framings) by k in 0..1.
export function blendKeys(a, b, k) {
  return a.map((ka, i) => {
    const kb = b[i], o = { t: ka.t };
    for (const key of Object.keys(ka)) {
      if (key === "t") continue;
      const x = ka[key], y = kb[key];
      o[key] = Array.isArray(x) ? x.map((v, j) => mix(v, y[j], k)) : mix(x, y, k);
    }
    return o;
  });
}

// Move a pose along its own camera axes (right, up, forward); the target follows by tgtK.
export function rig(pose, dx, dy, dz, tgtK = 0.25) {
  const { r, u, f } = basis(pose.pos, pose.tgt, pose.roll || 0);
  for (let i = 0; i < 3; i++) {
    const o = r[i] * dx + u[i] * dy + f[i] * dz;
    pose.pos[i] += o;
    pose.tgt[i] += o * tgtK;
  }
  return pose;
}
