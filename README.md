# casvancooten.com

Source for [casvancooten.com](https://casvancooten.com): "Security Ramblings", the personal site and blog of
Cas van Cooten, with posts on offensive security, red teaming, tooling and certifications.

The site is built with [Hugo](https://gohugo.io/) (v0.167.0 extended) and a small theme that lives in this repository
(`layouts/`, `assets/`). There is no theme submodule, no Node tooling and no npm dependency: CSS is plain CSS and the
JavaScript is bundled by Hugo itself. GitHub Actions builds the site, checks it and publishes it to the `gh-pages`
branch, which GitHub Pages serves.

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
| `hugo.toml` | Site config, menus, social links, taxonomies (`blog`, `tags`, `series`) |
| `layouts/baseof.html`, `home.html`, `page.html`, `section.html`, `taxonomy.html`, `term.html`, `404.html` | Page templates |
| `layouts/home.json` | Search index used by the command palette |
| `layouts/alias.html` | Redirect pages (noindex, canonical, meta refresh) |
| `layouts/_partials/` | Header, footer, SEO (`seo.html`, `jsonld.html`), post parts (`post/`), helpers (`func/`) |
| `layouts/_markup/` | Render hooks for headings, code blocks, images and links |
| `layouts/_shortcodes/x.html` | Static X post cards |
| `assets/css/` | `tokens.css` (fonts, colour tokens for both themes), `base.css`, `layout.css`, `components.css`, `syntax.css` |
| `assets/js/` | `main.js` and its modules: theme toggle, search palette, copy buttons, TOC scroll-spy, 404 path |
| `content/_index.md` | Home page intro text and description |
| `data/projects.toml` | Open-source projects on the home page |
| `static/fonts/` | Inter and JetBrains Mono (latin subsets, SIL OFL; licences next to the files) |

Dark is the default theme. The toggle stores `"dark"` or `"light"` in `localStorage["theme"]`, and a tiny inline
script applies it to `<html data-theme>` before the first paint. Everything works with JavaScript disabled; scripts
only add the search palette, theme toggle, copy buttons and TOC highlighting.

`assets/css/syntax.css` comes from `hugo gen chromastyles` (`github-dark` and `github`), scoped by `data-theme`.

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
Font License (see `static/fonts/`).
