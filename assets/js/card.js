// Business card: a subtle pointer tilt with a glare that follows the pointer, on critically damped springs.
// Mouse and pen only (touch scrolls the page), and nothing under reduced motion.
import { reducedMotion, spring } from "./util.js";

const MAX = 5; // degrees

export function initCard() {
  const card = document.querySelector("[data-card]");
  const stage = card?.closest(".card-stage");
  if (!stage || !window.matchMedia("(hover: hover)").matches) return;

  const rx = { x: 0, v: 0 }, ry = { x: 0, v: 0 }, gx = { x: 50, v: 0 }, gy = { x: 30, v: 0 }, gl = { x: 0, v: 0 };
  const target = { rx: 0, ry: 0, gx: 50, gy: 30, gl: 0 };
  let raf = 0, last = 0;

  const frame = (now) => {
    const dt = Math.min(0.05, last ? (now - last) / 1000 : 1 / 60);
    last = now;
    const moving =
      spring(rx, target.rx, 12, dt) + spring(ry, target.ry, 12, dt) +
      spring(gx, target.gx, 14, dt) + spring(gy, target.gy, 14, dt) + spring(gl, target.gl, 9, dt);
    card.style.setProperty("--rx", `${rx.x.toFixed(2)}deg`);
    card.style.setProperty("--ry", `${ry.x.toFixed(2)}deg`);
    card.style.setProperty("--gx", `${gx.x.toFixed(1)}%`);
    card.style.setProperty("--gy", `${gy.x.toFixed(1)}%`);
    card.style.setProperty("--glare", gl.x.toFixed(3));
    raf = moving > 0.005 ? requestAnimationFrame(frame) : 0;
    if (!raf) last = 0;
  };
  const kick = () => { if (!raf) raf = requestAnimationFrame(frame); };

  stage.addEventListener("pointermove", (e) => {
    if (e.pointerType === "touch" || reducedMotion.matches) return;
    const r = card.getBoundingClientRect();
    const px = Math.min(1.1, Math.max(-0.1, (e.clientX - r.left) / r.width));
    const py = Math.min(1.1, Math.max(-0.1, (e.clientY - r.top) / r.height));
    target.ry = (px - 0.5) * 2 * MAX;
    target.rx = -(py - 0.5) * 2 * MAX;
    target.gx = px * 100;
    target.gy = py * 100;
    target.gl = 1;
    kick();
  });
  stage.addEventListener("pointerleave", () => {
    Object.assign(target, { rx: 0, ry: 0, gx: 50, gy: 30, gl: 0 });
    kick();
  });
  reducedMotion.addEventListener("change", () => {
    if (!reducedMotion.matches) return;
    Object.assign(target, { rx: 0, ry: 0, gl: 0 });
    Object.assign(rx, { x: 0, v: 0 });
    Object.assign(ry, { x: 0, v: 0 });
    Object.assign(gl, { x: 0, v: 0 });
    kick();
  });
}
