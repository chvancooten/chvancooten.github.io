# Site checks

`check_site.py` automates the review gates G1 (URLs), G2 (SEO), G3 (content integrity) and
the budget and third-party parts of G5. It runs on Python 3.11+ with the standard library only.

It compares a fresh Hugo build against fixtures in `tests/baseline/`. Those fixtures were
generated from the old live site (gh-pages) with `gen_baseline.py`. Never edit a fixture to
make a check pass.

## Running locally

Production build:

```sh
hugo --gc --minify -d public
python3 scripts/check_site.py public --site-url https://casvancooten.com/
```

Preview build (same as a PR preview served under a sub-path):

```sh
hugo --gc --minify -d public-preview -b https://casvancooten.com/pr-preview/pr-7/
python3 scripts/check_site.py public-preview --preview --site-url https://casvancooten.com/pr-preview/pr-7/
```

Run only some gates with `--only G1,G3`. The exit status is 1 if any MUST check fails.
SHOULD findings print as `WARN` and do not change the exit status.

## What is checked

- **G1**: every baseline URL still exists, and redirect pages keep their target, canonical and
  `noindex`. Baseline heading ids still exist in each post. Feeds are well-formed and keep the
  link and guid of each post. Every internal `href`/`src`/`srcset` and CSS `url()` resolves to
  a build file, and `#fragment` links match an id. Nothing escapes the base path (for previews).
- **G2** (every indexable baseline page): title, `lang`, a single `<h1>`, canonical, the
  description, Open Graph and Twitter tags, article meta on posts, JSON-LD (WebSite and Person
  on home, BlogPosting on posts, `worksFor` Offensys on every Person), author and theme-color
  meta, RSS autodiscovery, `alt` on images, robots/`noindex` rules, sitemap and robots.txt.
- **G3**: per post, the word count stays within 3% and the `<pre>` and image counts stay at
  or above the baseline. Baseline images are still used, tweets link to the original, the TOC
  is present, `widgets.js` does not appear, and no About sentence is lost.
- **G5**: gzip size per page is at most 35 KB for CSS and 20 KB for JS, and font files in the
  build total at most 200 KB. No third-party scripts, stylesheets, preloads, icons, iframes or
  CSS URLs are allowed. Third-party images only produce a warning.

## Theme contract

In the new theme, the element that wraps only a post's rendered Markdown has `data-post-body`,
and the TOC element has `data-toc`. Inside the post body, text marked `aria-hidden="true"` or
`hidden` (such as heading anchor glyphs) does not count toward the word count.

## Regenerating fixtures

This is only needed if the baseline itself changes, and that is a reviewed decision:

```sh
python3 scripts/gen_baseline.py <extracted-gh-pages-dir> tests/baseline
```
