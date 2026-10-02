// The business card as a small physical object (layouts/_partials/card.html): a pointer tilt with a specular glare,
// and a turn to its back, which holds the profiles and "Save contact". Tilt and turn share one critically damped
// spring per axis, so a turn mid-tilt stays smooth.
// - The tilt follows a mouse or pen only (touch scrolls the page). The turn is a real button, below the card in its
//   stage, so mouse, touch and keyboard all use it.
// - The face that is turned away is inert: no focus, nothing for a screen reader.
// - Reduced motion: no tilt, and the turn is a short cross-fade between the faces (CSS).
import { reducedMotion, spring } from "./util.js";

const TILT_Y = 9, TILT_X = 7; // degrees at the card's edges
const REST = { rx: 0, ry: 0, gx: 62, gy: 22, gl: 0.35 };

export function initCard() {
  for (const card of document.querySelectorAll("[data-card3d]")) setup(card);
}

function setup(card) {
  const tilt = card.querySelector(".card3d__tilt");
  const front = card.querySelector(".card3d__front");
  const back = card.querySelector(".card3d__back");
  const btn = (card.closest(".card-stage") || card.parentElement)?.querySelector(".card3d__flip");
  if (!tilt || !front || !back) return;
  const label = btn?.querySelector("span");
  const fine = window.matchMedia("(hover: hover) and (pointer: fine)");
  const S = Object.fromEntries(Object.entries(REST).map(([k, x]) => [k, { x, v: 0 }]));
  const T = { ...REST };
  let flipped = false, raf = 0, last = 0;

  const apply = () => {
    tilt.style.setProperty("--rx", `${S.rx.x.toFixed(2)}deg`);
    tilt.style.setProperty("--ry", `${S.ry.x.toFixed(2)}deg`);
    card.style.setProperty("--gx", `${S.gx.x.toFixed(1)}%`);
    card.style.setProperty("--gy", `${S.gy.x.toFixed(1)}%`);
    card.style.setProperty("--glare", S.gl.x.toFixed(3));
  };
  const frame = (now) => {
    const dt = Math.min(0.05, last ? (now - last) / 1000 : 1 / 60);
    last = now;
    const ry = T.ry + (flipped && !reducedMotion.matches ? 180 : 0);
    const moving = spring(S.rx, T.rx, 9, dt) + spring(S.ry, ry, 9, dt) + spring(S.gx, T.gx, 12, dt) +
      spring(S.gy, T.gy, 12, dt) + spring(S.gl, T.gl, 8, dt);
    apply();
    raf = moving > 0.004 ? requestAnimationFrame(frame) : 0;
    if (!raf) last = 0;
  };
  const kick = () => { if (!raf) raf = requestAnimationFrame(frame); };

  card.addEventListener("pointermove", (e) => {
    if (e.pointerType === "touch" || !fine.matches || reducedMotion.matches) return;
    const r = tilt.getBoundingClientRect();
    const px = Math.min(1.15, Math.max(-0.15, (e.clientX - r.left) / r.width));
    const py = Math.min(1.15, Math.max(-0.15, (e.clientY - r.top) / r.height));
    T.ry = (px - 0.5) * 2 * TILT_Y;
    T.rx = -(py - 0.5) * 2 * TILT_X;
    // the highlight sits where a light above the viewer would catch the surface
    T.gx = (flipped ? 1 - px : px) * 100;
    T.gy = py * 100;
    T.gl = 1;
    kick();
  });
  const rest = () => { Object.assign(T, REST); kick(); };
  card.addEventListener("pointerleave", rest);

  const setFlip = (f) => {
    flipped = f;
    if (label) label.textContent = f ? "Turn to the front" : "Turn over";
    front.inert = f;
    back.inert = !f;
    card.classList.toggle("is-flipped", f);
    kick();
  };
  btn?.addEventListener("click", () => setFlip(!flipped));
  reducedMotion.addEventListener("change", () => {
    Object.assign(S.rx, { x: 0, v: 0 });
    Object.assign(S.ry, { x: flipped && !reducedMotion.matches ? 180 : 0, v: 0 });
    rest();
  });
  setFlip(false);
  apply();
}
