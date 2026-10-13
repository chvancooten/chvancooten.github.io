// The Speaking timeline on the home page: each year and each talk is revealed once, as it scrolls into view (the
// styles are in home.css, under .is-reveal). Only with motion on; without JS, or with motion off, every talk shows
// as is.
// - A talk starts to reveal as its first pixel enters the viewport, and the reveal is short (about 0.6 s), so it
//   has ended before the talk reaches reading height.
// - Anything the page has already scrolled past (a jump to a later anchor) is shown at once.
// - Turning motion off shows every talk that is still hidden.
import { motionOn } from "./motion.js";

export function initTalks() {
  const list = document.querySelector("[data-talks]");
  if (!list || !motionOn() || !("IntersectionObserver" in window)) return;
  const io = new IntersectionObserver((entries) => {
    for (const e of entries) {
      if (e.isIntersecting || e.boundingClientRect.bottom < 0) {
        e.target.classList.add("is-in");
        io.unobserve(e.target);
      }
    }
  }, { rootMargin: "0px 0px 5% 0px" });
  for (const el of list.querySelectorAll(".year, .talk")) io.observe(el);
  list.classList.add("is-reveal");
  document.addEventListener("motionchange", (e) => {
    if (e.detail) return;
    io.disconnect();
    list.classList.remove("is-reveal");
  });
}
