// Shared helpers for the small enhancement modules.
export const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");

let status;
// Polite screen reader announcement through one shared, visually hidden live region.
export function announce(text) {
  if (!status) {
    status = document.createElement("p");
    status.className = "sr-only";
    status.setAttribute("role", "status");
    document.body.append(status);
  }
  status.textContent = text;
}

// Exact step of a critically damped spring: no overshoot and no jitter, whatever the frame rate.
// s = { x, v }; w = angular frequency (higher is snappier).
export function spring(s, target, w, dt) {
  const d = s.x - target;
  const e = Math.exp(-w * dt);
  const c = s.v + w * d;
  s.x = target + (d + c * dt) * e;
  s.v = (s.v - w * c * dt) * e;
  return Math.abs(s.x - target) + Math.abs(s.v) * 0.05;
}
