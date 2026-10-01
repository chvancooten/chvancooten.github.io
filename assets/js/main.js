// Progressive enhancements only: every page works without this file.
import { initTheme } from "./theme.js";
import { initSearch } from "./search.js";
import { initCode } from "./code.js";
import { initToc } from "./toc.js";
import { initCopy } from "./copy.js";
import { initCard } from "./card.js";

for (const init of [initTheme, initSearch, initCode, initToc, initCopy, initCard]) {
  try {
    init();
  } catch (err) {
    console.warn(err);
  }
}
