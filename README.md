# casvancooten.com

Source for [casvancooten.com](https://casvancooten.com), the personal site of Cas van Cooten: red teamer and
co-founder of [Offensys](https://offensys.com). It is a business card first (talks, open source, contact), with a blog
on offensive security, red teaming, tooling and certifications.

The site is built with [Hugo](https://gohugo.io/) (v0.167.0 extended) and a small theme that lives in this repository
(`layouts/`, `assets/`). There is no theme submodule, no package.json and no npm dependency: CSS is plain CSS and the
JavaScript is bundled by Hugo itself. One optional Node script regenerates the hero's static images (see Design).
GitHub Actions builds the site, checks it and publishes it to the `gh-pages` branch, which GitHub Pages serves.

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
| `hugo.toml` | Site config, menus, social links, taxonomies (`blog`, `tags`, `series`), `homeTalks` (Speaking rows on the home page) |
| `layouts/baseof.html`, `home.html`, `page.html`, `section.html`, `taxonomy.html`, `term.html`, `404.html` | Page templates |
| `layouts/home.json` | Search index used by the search palette |
| `layouts/alias.html` | Redirect pages (noindex, canonical, meta refresh) |
| `layouts/_partials/` | Header, footer, SEO (`seo.html`, `jsonld.html`), post parts (`post/`), helpers (`func/`), the home sections (`talks.html`, `card.html`, `field.html`) |
| `layouts/_markup/` | Render hooks for headings, code blocks, images and links |
| `layouts/_shortcodes/x.html` | Static X post cards |
| `assets/css/` | `tokens.css` (fonts, colour tokens for both themes), `base.css`, `layout.css`, `components.css`, `home.css`, `syntax.css` |
| `assets/js/` | `main.js` and its modules (theme toggle, search palette, copy buttons, TOC scroll-spy, heading reveals, card tilt) |
| `assets/js/field/` | The hero flow field: `sim.js` (the simulation), `field.js` (canvas runtime), `still.mjs` (writes the static stills) |
| `content/_index.md` | Home page lede and description |
| `data/talks.toml`, `data/projects.toml` | Speaking and open-source lists on the home page |
| `static/field/` | Pre-rendered stills of the field (the no-JS and pre-boot fallback) |
| `static/fonts/` | Bricolage Grotesque, Instrument Sans and JetBrains Mono (latin subsets; SIL OFL licences next to the files) |
| `static/cas-van-cooten.vcf` | The vCard behind "Save contact" on the business card |

Dark is the default theme. The toggle stores `"dark"` or `"light"` in `localStorage["theme"]`, and a tiny inline
script applies it to `<html data-theme>` before the first paint. Everything works with JavaScript disabled; scripts
only add the search palette, theme toggle, copy buttons, TOC highlighting, the card tilt and the live hero.

## Design

**Colours.** [Rosé Pine](https://rosepinetheme.com) (MIT licence): Main for the dark default, Dawn for light. The tokens
in `assets/css/tokens.css` are the official colours, except a few whose lightness moved so every text pair passes WCAG
AA (4.5:1) on the surface it sits on; those are marked "adj." in the file. Love (rose-red) is the accent and iris
(purple) the second accent.

**Code.** `assets/css/syntax.css` maps Chroma's token classes (from `hugo gen chromastyles --style=rose-pine` and
`--style=rose-pine-dawn`, which share one role mapping) to role variables. `tokens.css` sets the role colours per
theme, lightened or darkened to at least 4.6:1 on the code background, comments included.

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

**The hero.** Two currents meet in the hero: love (the red team) runs left above a seam and foam (the blue team)
runs right below it. Where they meet, the shear rolls up into slow eddies and the two mix into iris, the purple of
both. The field is a Canvas 2D particle system (`assets/js/field/`). The flow comes from stream functions, so it
never drifts or bunches up, and it looks the same after a minute as after three seconds. The pointer (mouse or pen)
leaves a wake that follows its velocity, stirs the currents toward iris and fades once the pointer rests. The canvas
sits beside the copy on wide screens and in its own band below it on narrow ones, and fades its edges inside the
canvas, so nothing moves behind text. It only loads on the home page and the 404 page.

Without JavaScript, and until the script has drawn its first frame, the hero shows a pre-rendered still of the same
simulation (`static/field/still-*.svg`, coloured by the page's CSS variables). After changing `sim.js`, regenerate
the stills from the repository root with `node assets/js/field/still.mjs`.

**Motion and reduced motion.**

- The field stops when it is offscreen or the tab is hidden, and caps the pixel ratio at 2. A *Pause motion* button
  stops it for the rest of the browser session.
- On the first visit of a session the field starts as a line along the seam and unfurls into the two currents
  (0.7 s). Any key, click or scroll skips it. The name and the text are static and visible from the first paint.
- The business card on the home page tilts slightly toward a mouse or pen, with a glare.
- Section headings fade up once, over a fixed time, when they first come into view. The Offensys triad reveals
  line by line as it scrolls in.
- Pages cross-fade between each other where browsers support view transitions.

With `prefers-reduced-motion: reduce`, the field draws one still frame, the pause button, the intro, the card tilt,
the reveals and the view transitions are all off, and smooth scrolling is disabled.

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

## Licence

Content is licensed [CC BY-NC 4.0](https://creativecommons.org/licenses/by-nc/4.0/). The fonts are under the SIL Open
Font License (see `static/fonts/`). The Rosé Pine palette is MIT licensed.
