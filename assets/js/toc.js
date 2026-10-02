// Table of contents: open as a sidebar on wide screens, scroll-spy highlighting of the current section.
const WIDE = "(min-width: 75em)";

export function initToc() {
  const details = document.querySelector("[data-toc]");
  if (!details) return;
  const nav = details.querySelector("nav");
  const mq = window.matchMedia(WIDE);
  if (mq.matches) details.open = true;
  mq.addEventListener("change", () => {
    details.open = mq.matches;
  });

  const entries = [];
  for (const a of details.querySelectorAll('a[href^="#"]')) {
    let id = a.hash.slice(1);
    try {
      id = decodeURIComponent(id);
    } catch {
      /* keep the raw id */
    }
    const heading = document.getElementById(id);
    if (heading) entries.push({ heading, link: a });
  }
  if (!entries.length) return;

  let active = null;
  const setActive = (link) => {
    if (link === active) return;
    active?.removeAttribute("aria-current");
    active = link;
    if (!link) return;
    link.setAttribute("aria-current", "location");
    // Keep the active entry visible inside the (scrollable) sidebar without moving the page.
    if (details.open && nav && nav.scrollHeight > nav.clientHeight) {
      const r = link.getBoundingClientRect();
      const n = nav.getBoundingClientRect();
      if (r.top < n.top + 8 || r.bottom > n.bottom - 8) {
        nav.scrollTop += r.top - n.top - n.height / 3;
      }
    }
  };

  const update = () => {
    ticking = false;
    const line = Math.min(window.innerHeight * 0.3, 240);
    // Headings are in document order: binary search for the last one above the reading line.
    let lo = 0;
    let hi = entries.length - 1;
    let found = -1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      if (entries[mid].heading.getBoundingClientRect().top <= line) {
        found = mid;
        lo = mid + 1;
      } else {
        hi = mid - 1;
      }
    }
    setActive(found >= 0 ? entries[found].link : null);
  };

  let ticking = false;
  const onScroll = () => {
    if (!ticking) {
      ticking = true;
      requestAnimationFrame(update);
    }
  };
  window.addEventListener("scroll", onScroll, { passive: true });
  window.addEventListener("resize", onScroll, { passive: true });
  update();
}
