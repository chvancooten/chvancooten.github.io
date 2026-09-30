// Command palette over the home JSON index (title, url, date, tags, description). No library.
// Opens with the header button, "/" or Ctrl/Cmd+K; arrows move, Enter opens, Esc closes.
const MAX_RESULTS = 20;

const isTyping = (el) =>
  el instanceof HTMLElement && (el.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(el.tagName));

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

// Text with every search term wrapped in <mark>, built as DOM nodes (never innerHTML).
function highlight(text, terms) {
  const frag = document.createDocumentFragment();
  if (!terms.length) {
    frag.append(text);
    return frag;
  }
  const re = new RegExp(`(${terms.map(escapeRe).join("|")})`, "gi");
  text.split(re).forEach((part, i) => {
    if (!part) return;
    if (i % 2) {
      const m = document.createElement("mark");
      m.textContent = part;
      frag.append(m);
    } else {
      frag.append(part);
    }
  });
  return frag;
}

function score(item, terms) {
  let total = 0;
  for (const t of terms) {
    if (item.t.includes(t)) total += 3;
    else if (item.g.includes(t)) total += 2;
    else if (item.d.includes(t)) total += 1;
    else return 0;
  }
  return total;
}

export function initSearch() {
  const dialog = document.getElementById("search");
  const triggers = document.querySelectorAll("[data-search-open]");
  if (!dialog || typeof dialog.showModal !== "function") {
    for (const t of triggers) t.hidden = true;
    return;
  }
  const input = dialog.querySelector("input");
  const list = dialog.querySelector('[role="listbox"]');
  const status = dialog.querySelector('[role="status"]');

  let index = null;
  let loading = null;
  let options = [];
  let active = -1;
  let opener = null;

  const load = () =>
    (loading ||= fetch(dialog.dataset.index)
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`search index: HTTP ${r.status}`))))
      .then((items) => {
        index = items.map((it) => ({
          ...it,
          t: it.title.toLowerCase(),
          g: (it.tags || []).join(" ").toLowerCase(),
          d: (it.description || "").toLowerCase(),
        }));
      }));

  const setActive = (i) => {
    if (options[active]) options[active].setAttribute("aria-selected", "false");
    active = i;
    const opt = options[i];
    if (opt) {
      opt.setAttribute("aria-selected", "true");
      input.setAttribute("aria-activedescendant", opt.id);
      opt.scrollIntoView({ block: "nearest" });
    } else {
      input.removeAttribute("aria-activedescendant");
    }
  };

  const message = (text) => {
    const p = document.createElement("p");
    p.className = "palette__empty";
    p.textContent = text;
    return p;
  };

  const render = () => {
    if (!index) {
      list.replaceChildren(message("Loading the index..."));
      options = [];
      return;
    }
    const terms = input.value.trim().toLowerCase().split(/\s+/).filter(Boolean);
    const hits = terms.length
      ? index
          .map((it) => [score(it, terms), it])
          .filter(([s]) => s > 0)
          .sort((a, b) => b[0] - a[0] || b[1].date.localeCompare(a[1].date))
          .map(([, it]) => it)
      : index;
    options = hits.slice(0, MAX_RESULTS).map((it, i) => {
      const a = document.createElement("a");
      a.className = "palette__item";
      a.href = it.url;
      a.id = `search-opt-${i}`;
      a.tabIndex = -1;
      a.setAttribute("role", "option");
      a.setAttribute("aria-selected", "false");
      const title = document.createElement("span");
      title.className = "palette__title";
      title.append(highlight(it.title, terms));
      const meta = document.createElement("span");
      meta.className = "palette__meta";
      meta.append(highlight([it.date, ...(it.tags || []).map((t) => `#${t}`)].join("  "), terms));
      a.append(title, meta);
      a.addEventListener("pointermove", () => active !== i && setActive(i));
      return a;
    });
    list.replaceChildren(...(options.length ? options : [message(`No posts match "${input.value.trim()}".`)]));
    active = -1;
    setActive(options.length ? 0 : -1);
    status.textContent = terms.length
      ? `${hits.length} ${hits.length === 1 ? "post" : "posts"} found`
      : `${hits.length} posts`;
  };

  const open = (from) => {
    if (dialog.open) return;
    opener = from || document.activeElement;
    dialog.showModal();
    input.select();
    render();
    load()
      .then(render)
      .catch(() => {
        loading = null;
        list.replaceChildren(message("The search index could not be loaded."));
      });
  };

  dialog.addEventListener("close", () => {
    if (opener && typeof opener.focus === "function") opener.focus();
    opener = null;
  });
  // A click on the backdrop lands on the dialog element itself.
  dialog.addEventListener("click", (e) => {
    if (e.target === dialog) dialog.close();
  });
  input.addEventListener("input", render);
  input.addEventListener("keydown", (e) => {
    const n = options.length;
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      if (n) setActive((active + (e.key === "ArrowDown" ? 1 : n - 1)) % n);
    } else if (e.key === "Escape") {
      e.preventDefault();
      dialog.close();
    } else if (e.key === "Enter") {
      e.preventDefault(); // the form would otherwise close the dialog
      const opt = options[active];
      if (opt) window.location.href = opt.href;
    }
  });

  for (const t of triggers) t.addEventListener("click", () => open(t));
  document.addEventListener("keydown", (e) => {
    if (e.defaultPrevented || dialog.open || e.isComposing) return;
    const combo = e.key.toLowerCase() === "k" && (e.ctrlKey || e.metaKey) && !e.altKey;
    const slash = e.key === "/" && !e.ctrlKey && !e.metaKey && !e.altKey && !isTyping(e.target);
    if (combo || slash) {
      e.preventDefault();
      open(); // focus goes back to whatever had it before

    }
  });
}
