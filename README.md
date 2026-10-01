# casvancooten.com

Source for [casvancooten.com](https://casvancooten.com), the personal site of Cas van Cooten: red teamer and
co-founder of [Offensys](https://offensys.com). It is a business card first (talks, open source, contact), with a blog
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
| `assets/js/` | `main.js` and its modules (theme toggle, search palette, copy buttons, TOC scroll-spy, heading reveals, card tilt) |
| `assets/js/dock.js` | The home page's hero converting into the title bar |
| `assets/js/scene/` | The hero scene in WebGL2: `hero.js` (the home page controller), `index.js` (`mount()` and the runtime), `gl.js` (the renderer), `v1.js` (the particles and camera path), `math.js` |
| `content/_index.md` | Home page lede and description |
| `data/talks.toml` | Speaking list on the home page, generated by `scripts/sync_talks.py` (do not edit by hand) |
| `data/talks_overrides.toml` | Manual fields for the Speaking list (featured talks, title or event fixes) |
| `data/projects.toml` | Open-source list on the home page |
| `scripts/sync_talks.py` | Regenerates `data/talks.toml` from the conferences repository |
| `static/scene/` | Stills of the hero scene at rest (the fallback without JavaScript or WebGL2, and the 404 page) |
| `static/fonts/` | Bricolage Grotesque, Instrument Sans and JetBrains Mono (latin subsets; SIL OFL licences next to the files) |
| `static/cas-van-cooten.vcf` | The vCard behind "Save contact" on the business card |

Dark is the default theme. The toggle stores `"dark"` or `"light"` in `localStorage["theme"]`, and a tiny inline
script applies it to `<html data-theme>` before the first paint. Everything works with JavaScript disabled; scripts
only add the search palette, theme toggle, copy buttons, TOC highlighting, the card tilt and the live hero scene.

## Design

**Colours.** [Flexoki](https://stephango.com/flexoki) by Steph Ango ([kepano/flexoki](https://github.com/kepano/flexoki),
MIT licence), dark and light: black and base tones on dark, paper on light. The tokens in `assets/css/tokens.css` are
the official colours, except a few whose OKLCH lightness moved, by the smallest step, so every pair passes WCAG AA on
the surfaces it is used on (4.5:1 for text, 3:1 for borders, controls and the large star counts); those are marked
"adj." in the file. Red is the accent and purple the second accent. The hero scene still uses its own inks for now
(they are being reworked); its background follows the page.

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

**The hero.** The home page opens on a full-viewport landing: the name over a 3D scene of two currents of particles,
love (the red team) and foam (the blue team). They sweep in from far away as wide streams, twist into a tight braid
and turn iris, the purple of both, where they meet. The scene is raw WebGL2 with no library (`assets/js/scene/`,
about 10 KB gzip): every particle is computed in the vertex shader from its id and the time, so there are no vertex
buffers, and a frame is a few uniforms and three draw calls. Heads streak with their true screen motion, and depth
of field, depth fog and short trails give the depth. On the light theme the inks are taken away from the paper, like ink; on
dark they add up like light. The script only loads on the home page.

The body text, links and the cue into the content each sit on a soft cloud of the background colour, so they keep
at least 4.5:1 contrast over the brightest pixel of the scene. The name is display text and sits over the scene in
the open.

On the first visit of a session the camera flies through the scene (3.4 s): up the braid, through the iris knot
(which bursts as the camera passes), out between the two opening arms, and back to rest beside the braid. Any key,
click, wheel, touch or scroll skips to the end. The name is visible from the first paint; during the intro it only
moves (transform only). At rest the currents flow, the camera drifts slowly, follows the pointer or a touch a little,
and travels with the page scroll (it reads the scroll position and never changes it).

**The title bar.** There is no bar over the landing: the hero carries its own quiet bar with the same nav and tools
(both come from `layouts/_partials/nav.html` and `tools.html`, so they always match). As the hero scrolls away, each
line of the name moves and shrinks into its word of the title bar's wordmark and cross-fades into it, while the bar's
surface slides in underneath; scrolling back reverses it (`assets/js/dock.js`). Where the browser has CSS
scroll-driven animations, this is pure CSS (keyframes generated from the measured geometry, on a scroll timeline);
elsewhere a `requestAnimationFrame` loop applies the same states. Only one of the two navs is exposed at any time.
On narrow screens, where the title bar's nav has a row of its own, that row appears only once the name has docked.
With reduced motion there is no morph: the bar fades in once the name has gone. Without JavaScript the title bar is
the usual pinned one, as on every other page.

`mount(container, options)` in `assets/js/scene/index.js` returns `setScroll(progress)`, `setFocus(0..1)`,
`setIntensity(0..1)`, `pause()`, `resume()`, `restyle()` and `destroy()`, so the scene can later sit behind content,
out of focus or dimmed, without changes to the runtime.

**Fallbacks.** The WebGL context is created after the first contentful paint, and shaders compile without blocking
the main thread.

- Without JavaScript, without WebGL2, or when the shaders fail, the landing shows a designed still of the scene at
  rest (`static/scene/still-{wide,tall}-{dark,light}.webp`, landscape and portrait).
- Software WebGL renderers (SwiftShader, llvmpipe and similar, as in VMs, remote desktops and headless browsers) get
  the designed still too, because there every frame stalls the main thread. For screenshots and measurements, setting
  `sessionStorage["scene-quality"] = "0"` before the page loads forces the live scene.
- The 404 page shows the same still, without the script.

The stills are browser captures of the reduced-motion frame (below) with the copy, scrims and header hidden: the
`.stage` element at 1600x1000 (pixel ratio 1) for `wide` and 390x844 (pixel ratio 2) for `tall`, in each theme,
encoded as WebP at quality 0.8. Recapture them after changing the scene's look.

**Motion and reduced motion.**

- The scene stops when it is offscreen or the tab is hidden, and caps the pixel ratio at 2 (and the canvas at
  2560x1600 pixels). A *Pause motion* button stops it for the rest of the browser session.
- Adaptive quality: when frames are slow the scene steps down, first to a pixel ratio of 1, then to half the
  particles (with stronger inks), then to a still frame. The level lasts for the session.
- The business card on the home page tilts slightly toward a mouse or pen, with a glare.
- Section headings fade up once, over a fixed time, when they first come into view. The Offensys claim ("Continuous
  Purple Teaming") reveals line by line as it scrolls in.
- Pages cross-fade between each other where browsers support view transitions.

With `prefers-reduced-motion: reduce`, the scene draws one composed still frame (no intro, drift, parallax or
scroll-linked camera). The pause button, the card tilt, the reveals and the view transitions are off, and smooth
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
