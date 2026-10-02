// The scene's runtime, as one chunk: the landing script (hero.js) imports it after the page has painted, so the
// landing's own script stays small and the WebGL code never delays the first paint.
export { mount, STILL } from "./index.js";
export { createWindows } from "./windows.js";
export { nameMotion } from "./v1.js";
