# casvancooten.com

Source for [casvancooten.com](https://casvancooten.com), the personal site of Cas van Cooten: offensive security
enthusiast and co-founder of [Offensys](https://offensys.com). It is a business card first (talks, open source, contact), with a blog
on offensive security, red teaming, tooling and certifications.

The site is built with [Hugo](https://gohugo.io/) (v0.167.0 extended) and a small theme that lives in this repository
(`layouts/`, `assets/`). There is no theme submodule, no package.json and no npm dependency: CSS is plain CSS and the
JavaScript is bundled by Hugo itself. The Speaking list is generated from the
[conferences](https://github.com/chvancooten/conferences) repository by a standard-library Python script (see
Speaking). GitHub Actions builds the site, checks it and publishes it to the `gh-pages` branch, which GitHub Pages
serves.

## Local development

Install [Hugo extended v0.167.0](https://github.com/gohugoio/hugo/releases/tag/v0.167.0), then:

```sh
hugo server            # http://localhost:1313/, rebuilds on save
hugo server -D         # include drafts
```

A production-like build goes to `public/`:

```sh
hugo --gc --minify --panicOnWarning --baseURL https://casvancooten.com/
```

The build must finish with zero warnings (`--panicOnWarning` turns any warning into a failure).
`enableGitInfo` is on, so the "Updated" date and the "View source" link of a post come from the last git commit that
touched it. Run Hugo in a full clone, not a shallow one.

## Writing a post

Create the file from the archetype:

```sh
hugo new content posts/my-new-post.md
```

This writes `content/posts/my-new-post.md` with the front matter every post uses (the title comes from the file name):

```toml
+++
title = "My New Post"
date = "2026-09-30"
toc = true                # table of contents (sidebar on wide screens, collapsible on small ones)
draft = true              # set to false to publish
type = ["posts","post"]
# series = ["CheatSheets"]  # optional, lists the post in a series
tags = [
    "Hacking",
]

[ author ]
  name = "Cas van Cooten"
+++
```

Optional: `description = "..."` sets the meta description. Without it, the start of the post is used (about 155
characters). Adding it to an existing post changes that post's git-based "Updated" date.

A front-matter `lastmod` pins the modified date (it wins over the git date), for example to keep a trivial fix from
showing as an update. Remove or update it at the next real edit.

The URL follows `/posts/:year/:month/:title/`, so the title and date decide the slug. Changing either on a published
post breaks existing links.

Writing notes:

- **Headings** get GitHub-style ids (`## Lateral Movement` becomes `#lateral-movement`) and a `#` permalink. Link to a
  heading in the same post with `[text]({{< ref "#lateral-movement" >}})`.
- **Code** uses fenced blocks with a language (```` ```powershell ````). Hugo highlights them at build time; the
  language label and copy button come from the theme. Blocks without a language are shown as `text`.
- **Images** go in `static/images/` and are referenced root-relative: `![Alt text](/images/file.png)`. Always write
  real alt text. The theme adds width/height and lazy loading, and a caption when you give a title:
  `![Alt](/images/file.png "Caption")`.
- **Posts on X** are embedded as static cards, without any third-party script:
  `{{< x user="chvancooten" id="1374993077639733250" >}}`. The content of each card lives in `data/tweets.toml`, keyed by
  the status id (`user`, `name`, `handle`, `date`, `url`, and `html` with the tweet text as HTML). Add an entry there
  when you embed a new post; an unknown id renders as a plain link to the post.
- **GitHub repository cards** from gh-card.dev (`![alt](https://gh-card.dev/repos/<owner>/<repo>.svg)`) are replaced by
  a local SVG card when the repository is listed in `data/projects.toml`.
- **Raw HTML** in Markdown is not rendered (`unsafe = false`).

## Theme overview

| Path | What it holds |
| --- | --- |
| `hugo.toml` | Site config, menus (Work and About are sections of the home page; Writing is `/posts/`), social links, taxonomies (`blog`, `tags`, `series`), `homeTalks` (Speaking rows on the home page) |
| `layouts/baseof.html`, `home.html`, `page.html`, `section.html`, `taxonomy.html`, `term.html`, `404.html` | Page templates |
| `layouts/home.json` | Search index used by the search palette |
| `layouts/alias.html` | Redirect pages (noindex, canonical, meta refresh) |
| `layouts/_partials/` | Header and its navigation (`nav.html`, shared by the title bar and the landing), footer, SEO (`seo.html`, `jsonld.html`), post parts (`post/`), helpers (`func/`), the home sections (`talks.html`, `card.html`) |
| `layouts/_markup/` | Render hooks for headings, code blocks, images and links |
| `layouts/_shortcodes/x.html` | Static X post cards |
| `assets/css/` | `tokens.css` (fonts, colour tokens for both themes), `base.css`, `layout.css`, `components.css`, `home.css`, `syntax.css` |
| `assets/js/` | `main.js` and its modules (theme toggle, search palette, copy buttons, TOC scroll-spy, the 3D business card), `motion.js` (the site-wide motion preference) |
| `assets/js/dock.js` | The home page's hero converting into the title bar |
| `assets/js/scene/` | The home page's scene in WebGL2: `hero.js` (the home page controller), and the runtime it loads after first paint, `stage.js`: `index.js` (`mount()`, the clocks, input, quality), `gl.js` (the renderer), `v1.js` (the particles and the landing's camera path), `windows.js` (the landing's frame and the windows between the chapters), `math.js` |
| `content/_index.md` | Home page lede and description |
| `data/talks.toml` | Speaking list on the home page, generated by `scripts/sync_talks.py` (do not edit by hand) |
| `data/talks_overrides.toml` | Manual fields for the Speaking list (featured talks, title or event fixes) |
| `data/projects.toml` | Open-source list on the home page |
| `scripts/sync_talks.py` | Regenerates `data/talks.toml` from the conferences repository |
| `static/scene/` | Stills of the landing's scene at rest (the fallback without JavaScript or WebGL2) |
| `static/fonts/` | Bricolage Grotesque, Instrument Sans and JetBrains Mono (latin subsets; SIL OFL licences next to the files) |
| `static/cas-van-cooten.vcf` | The vCard behind "Save contact" on the business card |
| `static/images/card-portrait*.webp` | The card's portrait: the photo, and a soft luminance matte of its near-black studio background used as a CSS mask |

Dark is the default theme. The toggle stores `"dark"` or `"light"` in `localStorage["theme"]`, and a tiny inline
script applies it to `<html data-theme>` before the first paint. Everything works with JavaScript disabled; scripts
only add the search palette, theme toggle, copy buttons, TOC highlighting, the card's tilt and turn, the title bar's dock
and the live scene.

## Design

**Colours.** [Flexoki](https://stephango.com/flexoki) by Steph Ango ([kepano/flexoki](https://github.com/kepano/flexoki),
MIT licence), dark and light: black and base tones on dark, paper on light. The tokens in `assets/css/tokens.css` are
the official colours, except a few whose OKLCH lightness moved, by the smallest step, so every pair passes WCAG AA on
the surfaces it is used on (4.5:1 for text, 3:1 for borders, controls and the large star counts); those are marked
"adj." in the file. Red is the accent and purple the second accent. The scene uses Flexoki's own red, blue and purple
(the 400 and 600 shades, `--scene-*` in `tokens.css`) and nothing else: no orange, no other hue.

**Code.** Hugo's Chroma has no Flexoki style, so `assets/css/syntax.css` maps Chroma's token classes onto Flexoki's own
syntax roles (keywords green, strings cyan, functions orange, variables and attributes blue, numbers purple, constants
and types yellow, imports red, language features magenta, punctuation and comments in the base tones; comments in
italics). `tokens.css` sets the role colours per theme: the 400 shades on dark and the 600 shades on light, lightened or
darkened to at least 4.5:1 on the code background and on a highlighted line.

**Type.** All fonts are self-hosted latin subsets under the SIL Open Font License, 135 KB in total, with
metric-matched fallback faces so the swap does not move the layout:

- [Bricolage Grotesque](https://github.com/ateliertriay/bricolage) for the name, headings and numerals, instanced to
  wght 700-800, wdth 75-100 and a fixed opsz of 60 (preloaded);
- [Instrument Sans](https://github.com/Instrument/instrument-sans) for text and UI, with italics, at wdth 100
  (preloaded);
- [JetBrains Mono](https://github.com/JetBrains/JetBrainsMono) for code and tag chips, without its ligature tables.

The files were made from the Google Fonts sources with fonttools (`varLib.instancer`, then `subset` to the Google
Fonts latin range with the kern, liga, calt, locl, mark, mkmk, ccmp, rlig, tnum and case features; JetBrains Mono
keeps kern, locl, mark, mkmk and ccmp only).

**The landing and the scene.** The home page opens on a full-viewport landing: the name over a 3D scene of two
currents of particles, red (the red team) and blue (the blue team). They sweep in from far away as wide streams,
twist into a tight braid and turn purple, the colour of both, where they meet. The scene is raw WebGL2 with no
library: every particle is computed in the vertex shader from its id and the time, so there are no vertex buffers,
and a frame is a few uniforms and a few draw calls. Heads streak with their true screen motion, and depth of field,
depth fog and short trails give the depth.

The scene is one canvas, fixed behind the page, and it shows in exactly five frames: the landing, and four
full-bleed windows between the chapters (`.window`, from `layouts/_partials/window.html`), each a view of the same
world with its own camera. Each frame is masked in the shader, with soft edges, so there is no overlay element; the
chapters themselves sit calmly on the page colour and nothing in them moves.

- W1, after Offensys: the two currents side by side; W2, between Speaking and Open source: the red current; W3,
  before Writing: the blue one.
- W4, before About: the end of the story. The two currents as one calm braid seen from the side: two wide, soft
  strands crossing along the horizontal axis, red and blue between the crossings and a soft purple glow only where
  they cross. The flow along them (about 0.3 units/s) and the twist (0.12 rad/s) are slow: at 390 px wide its
  particles move about 10 px/s, against about 180 px/s for the braid this window showed before.
- As a window crosses the screen the cameras of W1 to W3 only crane (move vertically, across the flow), and W4's
  holds still (craning over a twisted braid would make its twist seem to turn back). The particles' time only ever
  moves forward; scrolling moves cameras, never time, so nothing runs backwards when the page scrolls up.

The particles are accumulated as ink and coverage and composited once (`assets/js/scene/gl.js`): the colour is the
coverage-weighted mean of the inks, so a dense red region stays red and a dense blue one blue, and two inks only mix
where they overlap. On dark the result is added to the page, capped a little above each ink's own brightness, so blue
never washes out to white. On light it is laid over the paper like ink (a mix in OKLab), never subtracted, so nothing
looks inverted. The composite always runs at the canvas's full resolution, also when the particles are drawn at a lower
render scale (it filters their premultiplied sums up), so the browser never upscales a finished frame, which would mix
the inks with the paper in sRGB and turn faint red edges peach on light.

The landing's copy stays legible in two ways: the scene darkens itself under the copy (a column on wide screens,
bands above and below it on narrow ones), and the body text, links and the cue each sit on a soft cloud of the page
colour, opaque enough to keep at least 4.5:1 over the brightest pixel of the scene. The name is display text and sits
over the scene in the open.

On the first visit of a tab session the scene starts with its intro (3 s, from the scene's first frame): the
particles converge into the braid from the knot outward while the camera glides along it, then rises and swings out
to rest beside it. The canvas fades in on its first frame, from the page colour. The name is painted from the first
paint, slightly lifted and enlarged, and the rest of the landing's UI a few pixels off; they settle with the intro,
transform only, from the final layout (the fonts are preloaded and have metric-matched fallbacks, so nothing shifts).
A deliberate input skips the intro to its end: a key, a click or tap, a wheel or a scroll; moving the pointer does
not. The session flag is written when the intro has played or been skipped, so leaving early means it plays again.
At rest the currents flow, the camera drifts slowly and follows the pointer or a touch a little. The scene's time runs
on the real clock, so a slow device still plays the intro in about 3 s.

**The title bar.** There is no bar over the landing: the hero carries its own quiet bar with the same nav and tools
(both come from `layouts/_partials/nav.html` and `tools.html`, so they always match). As the hero scrolls away, each
line of the name moves and shrinks into its word of the title bar's wordmark and cross-fades into it, while the bar's
surface slides in underneath; scrolling back reverses it (`assets/js/dock.js`). Where the browser has CSS
scroll-driven animations, this is pure CSS (keyframes generated from the measured geometry, on a scroll timeline);
elsewhere a `requestAnimationFrame` loop applies the same states. Only one of the two navs is exposed at any time.
On narrow screens, where the title bar's nav has a row of its own, that row appears only once the name has docked.
With reduced motion there is no morph: the bar fades in once the name has gone. Without JavaScript the title bar is
the usual pinned one, as on every other page.

`mount(container, options)` in `assets/js/scene/index.js` takes the frames to render (`views`, from `windows.js`) and
returns `setScroll(progress)`, `setFocus(0..1)`, `setIntensity(0..1)`, `pause()`, `resume()`, `restyle()` and
`destroy()`.

**Loading and fallbacks.** The landing's own script (`hero.js`, with the title bar's dock) is small; the scene's
runtime is a separate chunk (`stage.js`, about 13 KB gzip) that it imports as soon as it runs, with its integrity in
the page's import map. The WebGL context is created after the first contentful paint, and shaders compile without
blocking the main thread.

- Without JavaScript, without WebGL2, or when the shaders fail, the landing shows a designed still of the scene at
  rest (`static/scene/still-{wide,tall}-{dark,light}.webp`, landscape and portrait), and the windows (which only
  exist with JavaScript) each hold a soft composition of their subject's colours. A scene that has not come up
  2.5 s after load gets the same fallbacks.
- Software WebGL renderers (SwiftShader, llvmpipe and similar, as in VMs, remote desktops and headless browsers) get
  the fallbacks too, because there every frame stalls the main thread. For screenshots and measurements, storing a
  quality level before the page loads (`sessionStorage["scene-quality"] = "0"` for full quality) forces the live
  scene.

The stills are browser captures of the scene's composed still frame (motion off) behind the landing, with the copy,
the page's scrims and the bars hidden: 1600x1000 (pixel ratio 1) for `wide` and 390x844 (pixel ratio 2) for `tall`,
in each theme, encoded as WebP at quality 0.8. Recapture them after changing the scene's look. `/preview.png`, the
social card, is a 1200x630 capture of the same landing in the dark theme, with the scene enlarged and brightened
against the page colour so its flow lines survive a thumbnail.

**Motion and reduced motion.**

- The scene renders only while one of its frames is on screen and the tab is visible, and caps the pixel ratio at 2
  (and the canvas at 2560x1600 pixels).
- One motion preference for the whole site (`assets/js/motion.js`): `localStorage["motion"]` is `"on"` or `"off"`,
  kept across pages and visits and shared by open tabs, and it applies to every scene on a page. Without a stored
  choice it follows the browser: off under `prefers-reduced-motion: reduce`, on otherwise. The *Pause motion* /
  *Play motion* control on the landing sets it, so a visitor who asked for less motion can opt in. Only the control
  changes it: scrolling, tab visibility or the end of the intro never resume a paused scene, and the label always
  says what the button will do. Motion off is the composed still frame; the intro plays only with motion on and no
  reduced-motion request from the browser.
- Adaptive quality, judged on frame intervals: when frames are slow (a median over 45 ms) the scene steps down, first
  to a pixel ratio of 1, then halving the particles (drawn a little larger and stronger) and lowering the render
  scale, down to 1/32 of the particles at 0.4 scale; level 8 is a still frame. The first frames are judged in short
  windows, so a slow device drops several steps at once. The level lasts for the session.
- The business card is a small 3D object: dark in both themes, with real thickness, the portrait on the front and the
  profiles (GitHub, X, LinkedIn, email) and *Save contact* on the back. It tilts toward a mouse or pen, with a
  specular glare, and the *Turn over* button below it turns it (mouse, touch and keyboard); the face turned away is
  inert. Without JavaScript both faces lie flat, one above the other. The same card closes the About page. The portrait files come from the
  owner's studio photo: cropped to head and shoulders, a soft luminance matte (the near-black background becomes
  transparent, so keying errors vanish into the card's own near-black surface), then exported as a 500x540 WebP
  without alpha (`card-portrait.webp`) and the matte as a separate WebP for `mask-image`
  (`card-portrait-matte.webp`); an alpha plane in the photo itself would cost about ten times as much.
- Pages cross-fade between each other where browsers support view transitions.

With `prefers-reduced-motion: reduce`, the scene draws one composed still frame (no intro, drift, parallax or
window camera moves) unless the visitor turns motion on; as the page scrolls it is redrawn, still, where the frames
are. The card's tilt and the view transitions are off (the card's turn is a short cross-fade), and smooth
scrolling is disabled.

## Speaking

`data/talks.toml` is generated by `scripts/sync_talks.py` (Python 3.11+, standard library only) from the public
[chvancooten/conferences](https://github.com/chvancooten/conferences) repository. Each top-level folder there is one
appearance, named `YYYY-MM - Title @ Event`; folders starting with `.` (such as `.github`) are ignored. The script
reads the folder names through the GitHub API, takes the first YouTube link in each folder's `README.md` as the
recording (`video`), drops a trailing year from the event and spells x33fcon one way. Only https links to
`youtube.com/watch?v=<id>` (also `www.` and `m.`) or `youtu.be/<id>` with a valid 11-character video id count; the
link is written back in that form, without other parameters. It writes the file newest first with a fixed key order,
and only when the content changes. Run it from anywhere:

```sh
python3 scripts/sync_talks.py            # set GITHUB_TOKEN to lift the API limit of 60 requests an hour
```

It exits 0 when the file is unchanged or updated, and 1 on a fetch or parse error, which leaves the file as it was.
A folder name with control or bidirectional formatting characters, or with an empty title or event, is a parse
error. The token is never sent on to a redirect target, and responses over 1 MB are refused.
Do not edit `data/talks.toml` by hand: the next sync overwrites it.

**Metadata in the conferences repository (`talk.toml`).** A talk folder may hold a `talk.toml`. When it is there,
its values replace the parsed ones, and the script guesses nothing for that folder. Every key is optional:

```toml
# <conferences>/2026-06 - The Best Defense Is A Good Offense @ OrangeCon 2026/talk.toml
title = "The Best Defense Is A Good Offense"
subtitle = "A Pragmatic Path to Continuous Purple Teaming"
event = "OrangeCon"                          # without the year
date = "2026-06"                             # YYYY-MM, ASCII digits
video = "https://youtu.be/<11-character id>" # https YouTube link, or "" for no recording
slides = "slides.pdf"                        # a file in this folder, or "" for none
featured = true                              # always listed on the home page
```

The rules are the same as for the overrides file: an ASCII date, an https YouTube link (written back in canonical
form), no control or bidirectional formatting characters, and at most 160 characters for `title`, 120 for `subtitle`
and 100 for `event`. `subtitle = ""` means no subtitle. `slides` is written to `data/talks.toml` as the file's
`https://github.com/` URL; the home page does not show it yet. A broken value, or a file that is not valid TOML,
fails the sync, so CI warns and keeps the committed data. An unknown key is ignored with a warning. With a
`talk.toml` that gives `date`, `title` and `event`, the folder name does not need to follow the pattern.

**Subtitles without `talk.toml`.** The script looks at the README's first heading, then at the names of the slide
PDFs (in name order). It removes the `.pdf` extension, a leading date and any event or year suffix
(` @ Event`, `(Event 2026)`, ` - Event`, ` 2026`). It only takes a subtitle when what is left reads
`<title><separator><subtitle>`, with the folder's title and a separator of `: `, ` - `, ` | ` or a spaced en or em
dash. A guess over 120 characters, or one that only repeats the event, is dropped. Without a clean match there is no
subtitle; nothing is made up. A file name that runs on after the title without a separator (common for PDFs,
since `:` cannot appear in file names) gives no subtitle; add a `talk.toml` for that talk instead.

**Overrides.** Manual fields go in `data/talks_overrides.toml`, one table per folder name. They win over both the
folder name and `talk.toml`:

```toml
["2022-08 - Nimbly Navigating a Nimiety of Nimplants @ DC30 Adversary Village"]
event = "DEF CON 30 Adversary Village"   # replaces the parsed event
featured = true                          # always listed on the home page
```

The fields are `featured`, `title`, `subtitle` (`""` drops a found one), `event`, `date` (`"YYYY-MM"`), `url` (an
`https://github.com/` URL), `livestream`, `video` (a YouTube link as above, or `""` to drop the README's link),
`slides` (a file in the folder) and `skip = true` (leaves the folder out). A folder whose name does not parse fails
the sync until it gets `skip = true`, or `date`, `title` and `event` (from `talk.toml` or the overrides).

The script's summary line counts the talks, the recordings and the subtitles by source (`talk.toml`, README, PDF,
overrides). On the home page, `homeTalks` in `hugo.toml` sets how many rows show. A row shows its subtitle under the
title (for a talk given at several events in one year, the newest one that has a subtitle), and each appearance with
a recording gets a YouTube link.

## Checks

`scripts/check_site.py` (Python 3.11+, standard library only) compares a build with fixtures taken from the previous
live site (`tests/baseline/`): URLs and redirects, heading ids, feeds, internal links, SEO tags and JSON-LD, post
content integrity, and CSS/JS/font budgets. Run it after a build:

```sh
hugo --gc --minify --panicOnWarning --baseURL https://casvancooten.com/
python3 scripts/check_site.py public --site-url https://casvancooten.com/
```

For a preview build served under a sub-path:

```sh
HUGO_PARAMS_PREVIEWPR=1 hugo --gc --minify --panicOnWarning --environment preview \
  --baseURL https://casvancooten.com/pr-preview/pr-1/ -d public-preview
python3 scripts/check_site.py public-preview --preview --site-url https://casvancooten.com/pr-preview/pr-1/
```

The exit status is 1 when a MUST check fails. See `scripts/README.md` for details. Do not edit the fixtures to make a
check pass.

## Previews and deployment

Every pull request is built and checked. Non-draft pull requests from this repository also get a preview at
`https://casvancooten.com/pr-preview/pr-<N>/`: the preview environment adds `noindex` to every page and shows a
"Preview build" banner. The preview is removed when the pull request is closed. Pushes to `main` deploy the
production site. The details live in `.github/workflows/`.

Every build, previews included, first runs `scripts/sync_talks.py` with the workflow's read-only token, so the site
shows the talks in the conferences repository at build time. If the sync fails, the build warns and uses the committed
`data/talks.toml`; a failed sync never fails a build. The job summary says whether the synced data differs from the
committed file; when it does, run the script locally and commit the result. A weekly scheduled run (Mondays,
05:23 UTC) rebuilds and redeploys production the same way as a push to `main`, so new talks and recordings appear
without a commit here. Like any production run, it does not deploy if `main` has moved past the commit it built.
Production only deploys from `chvancooten/chvancooten.github.io`: a fork with Actions enabled builds and checks, but
never publishes.

GitHub disables scheduled workflows in a public repository after 60 days without repository activity, so the weekly
refresh stops after two quiet months. GitHub's documented way back is to enable the workflow again: *Enable
workflow* on the workflow's page in the Actions tab, or `gh workflow enable "github pages"`. A manual run (*Run
workflow*, which is `workflow_dispatch`, on `main`) then refreshes the talks and redeploys production at once,
without waiting for the next Monday.

## Licence

Content is licensed [CC BY-NC 4.0](https://creativecommons.org/licenses/by-nc/4.0/). The fonts are under the SIL Open
Font License (see `static/fonts/`). The Flexoki palette is MIT licensed.
