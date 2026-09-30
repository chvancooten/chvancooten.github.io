// Section headings fade up once, over a fixed time, when they first enter the viewport. Not scroll-scrubbed.
// Only headings still below the fold are prepared, so nothing on screen ever disappears; without JS,
// IntersectionObserver or with reduced motion, headings are simply there.
import { reducedMotion } from "./util.js";

export function initReveal() {
  const els = document.querySelectorAll("[data-reveal]");
  if (!els.length || reducedMotion.matches || !("IntersectionObserver" in window)) return;
  const io = new IntersectionObserver(
    (entries) => {
      for (const e of entries) {
        if (!e.isIntersecting) continue;
        e.target.classList.add("is-revealed");
        io.unobserve(e.target);
      }
    },
    { rootMargin: "0px 0px -10% 0px" },
  );
  for (const el of els) {
    if (el.getBoundingClientRect().top < window.innerHeight) continue;
    el.classList.add("will-reveal");
    io.observe(el);
  }
}
