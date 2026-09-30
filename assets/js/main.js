// Progressive enhancements only: every page works without this file.
import { initTheme } from "./theme.js";
import { initSearch } from "./search.js";
import { initCode } from "./code.js";
import { initToc } from "./toc.js";
import { initNotFound } from "./notfound.js";

for (const init of [initTheme, initSearch, initCode, initToc, initNotFound]) {
  try {
    init();
  } catch (err) {
    console.warn(err);
  }
}
