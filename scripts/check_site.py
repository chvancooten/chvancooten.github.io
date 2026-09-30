#!/usr/bin/env python3
"""Automated review-gate checks for a built site (G1 URLs, G2 SEO, G3 content, G5 budgets).

Usage:
  python3 scripts/check_site.py <build_dir> --site-url URL [--preview] [--baseline DIR] [--only G1,G3]

  --site-url  the full URL this build is served from, e.g. https://casvancooten.com/ (production)
              or https://casvancooten.com/pr-preview/pr-7/ (preview). Its path is the base path.
              A fixture path such as /about/ maps to <build_dir>/about/index.html and to the
              expected absolute URL <site-url>about/.
  --preview   the build is a PR preview: every page must be noindex, sitemap content and
              production robots rules are not checked, and absolute links to the production
              host outside the base path are treated as external.

Fixtures (tests/baseline/) come from scripts/gen_baseline.py run against the old live site.
They are the contract: never edit them to make a check pass.

Theme contract (the new theme must follow it so G3 can find the content):
  * the element that wraps only the rendered Markdown of a post carries `data-post-body`;
  * the table-of-contents element carries `data-toc` (it may sit inside or outside the body;
    it is excluded from the word count either way);
  * content inside the post body marked `aria-hidden="true"` or `hidden` (e.g. heading anchor
    glyphs, language labels) is not counted as words.

Levels: MUST failures print FAIL and make the exit status 1; SHOULD findings print WARN only.
Sizes: KB = 1024 bytes; gzip sizes use level 9.
"""
import argparse
import gzip
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from urllib.parse import urljoin, urlsplit

sys.dont_write_bytecode = True  # keep scripts/ free of __pycache__
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sitelib  # noqa: E402
from sitelib import norm_text  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_BASELINE = os.path.join(REPO_ROOT, "tests", "baseline")
GATES = ("G1", "G2", "G3", "G5")
GATE_TITLES = {"G1": "URLs and permalinks", "G2": "SEO, never worse",
               "G3": "Content integrity", "G5": "Performance budgets and third parties"}
KB = 1024
CSS_BUDGET, JS_BUDGET, FONT_BUDGET = 35 * KB, 20 * KB, 200 * KB
WORD_TOLERANCE = 0.03
POST_DESC_RANGE = (50, 220)
DESC_SHOULD_MAX = 160
OFFENSYS_URL = "https://offensys.com"
FONT_EXTS = (".woff2", ".woff", ".ttf", ".otf", ".eot")
TEXT_EXTS = (".html", ".xml", ".js", ".mjs", ".css", ".json", ".txt", ".webmanifest", ".svg")
WIDGETS_JS = "platform.twitter.com/widgets.js"
RSS_TYPE = "application/rss+xml"


def body_match(tag, attrs):
    return "data-post-body" in attrs


def toc_match(tag, attrs):
    return "data-toc" in attrs


# --------------------------------------------------------------------------- inputs

class Fixtures:
    def __init__(self, root):
        def load(name):
            with open(os.path.join(root, name), encoding="utf-8") as fh:
                return json.load(fh)
        with open(os.path.join(root, "urls.txt"), encoding="utf-8") as fh:
            self.urls = [l.strip() for l in fh if l.strip()]
        self.redirects = load("redirects.json")
        self.pages = load("pages.json")
        self.posts = load("posts.json")
        self.feeds = load("feeds.json")
        self.sitemap = load("sitemap.json")
        self.about = load("about.json")

    @property
    def indexable(self):
        return {p: i for p, i in self.pages.items() if i["kind"] != "404"}


class Build:
    """The new build: file lookup, cached page parsing, URL mapping."""

    def __init__(self, root, site_url, preview):
        self.root = os.path.abspath(root)
        self.site = sitelib.SiteUrl(site_url)
        self.preview = preview
        self.files = sorted(sitelib.iter_files(self.root))
        self._pages = {}
        self._gzip = {}

    def file_for(self, path):
        rel = path.lstrip("/") + ("index.html" if path.endswith("/") else "")
        return os.path.join(self.root, *rel.split("/"))

    def resolve(self, rel):
        """Base-path-relative URL path -> file in the build, or None."""
        parts = [p for p in rel.split("/") if p not in ("", ".")]
        if ".." in parts:
            return None
        full = os.path.join(self.root, *parts)
        if rel == "" or rel.endswith("/"):
            full = os.path.join(full, "index.html")
        if os.path.isfile(full):
            return full
        index = os.path.join(full, "index.html")  # GitHub Pages serves /x as /x/
        return index if os.path.isfile(index) else None

    def page_file(self, full):
        if full not in self._pages:
            self._pages[full] = sitelib.parse_file(full, body_match, toc_match)
        return self._pages[full]

    def page(self, path):
        full = self.file_for(path)
        return self.page_file(full) if os.path.isfile(full) else None

    def html_pages(self):
        """(served path, Page) for every HTML file in the build."""
        for rel in self.files:
            if rel.endswith(".html"):
                yield sitelib.served_path(rel), self.page_file(os.path.join(self.root, rel))

    def css_files(self):
        for rel in self.files:
            if rel.endswith(".css"):
                with open(os.path.join(self.root, rel), encoding="utf-8", errors="replace") as fh:
                    yield "/" + rel, fh.read()

    def local_file(self, url, base_url):
        kind, rel, _ = self.site.classify(url, base_url)
        return self.resolve(rel) if kind == "internal" else None

    def gzip_size(self, full):
        if full not in self._gzip:
            with open(full, "rb") as fh:
                self._gzip[full] = gz(fh.read())
        return self._gzip[full]

    def is_third_party(self, url):
        url = (url or "").strip()
        if not re.match(r"(?i)(https?:)?//", url):
            return False
        return urlsplit(urljoin("https://x/", url)).netloc.lower() != self.site.host


def gz(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return len(gzip.compress(data, compresslevel=9, mtime=0)) if data else 0


def fmt_kb(n):
    return f"{n / KB:.1f} KB"


def cap(items, n=5):
    items = list(items)
    return ", ".join(items[:n]) + (f", ... (+{len(items) - n})" if len(items) > n else "")


# --------------------------------------------------------------------------- report

class Report:
    def __init__(self, gates):
        self.gates = gates
        self.results = []  # (gate, level, name, issues, note)

    def add(self, gate, name, issues, note="", level="MUST"):
        unique = list(dict.fromkeys(issues))  # drop exact duplicates, keep order
        self.results.append((gate, level, name, unique, note))

    def warn(self, gate, name, issues, note=""):
        self.add(gate, name, issues, note, level="SHOULD")

    @staticmethod
    def _lines(issues, limit=12):
        """Group identical messages so a site-wide problem prints once."""
        groups = {}
        for issue in issues:
            subject, msg = issue if isinstance(issue, tuple) else ("", issue)
            groups.setdefault(msg, []).append(subject)
        lines = []
        for msg, subjects in groups.items():
            subjects = [s for s in subjects if s]
            if len(subjects) > 1:
                lines.append(f"{msg}  ({len(subjects)}x: {cap(subjects, 3)})")
            else:
                lines.append(f"{subjects[0]}: {msg}" if subjects else msg)
        if len(lines) > limit:
            lines = lines[:limit] + [f"... and {len(lines) - limit} more"]
        return lines

    def render(self):
        out, fails, warns = [], 0, 0
        for gate in self.gates:
            out.append(f"\n== {gate}: {GATE_TITLES[gate]} ==")
            for g, level, name, issues, note in self.results:
                if g != gate:
                    continue
                if not issues:
                    status = "PASS"
                elif level == "MUST":
                    status, fails = "FAIL", fails + 1
                else:
                    status, warns = "WARN", warns + 1
                label = name if level == "MUST" else f"{name} (SHOULD)"
                suffix = f" - {len(issues)} issue(s)" if issues else (f" ({note})" if note else "")
                out.append(f"[{status}] {label}{suffix}")
                out.extend(f"         {line}" for line in self._lines(issues))
        out.append(f"\nSummary: {fails} MUST check(s) failed, {warns} SHOULD warning(s).")
        return "\n".join(out), fails


# --------------------------------------------------------------------------- G1

def check_urls_exist(b, fx):
    return [(p, "missing from build") for p in fx.urls if not os.path.isfile(b.file_for(p))]


def check_redirects(b, fx):
    for path, target in fx.redirects.items():
        pg = b.page(path)
        if pg is None:
            yield path, "redirect page missing"
            continue
        ok = {b.site.abs(target), b.site.base + target.lstrip("/")}
        if pg.refresh_url not in ok:
            yield path, f"meta refresh -> {pg.refresh_url!r}, expected {b.site.abs(target)}"
        canon = [l.get("href") for l in pg.links_with_rel("canonical")]
        if not canon or canon[0] not in ok:
            yield path, f"canonical {canon[0] if canon else None!r}, expected {b.site.abs(target)}"
        if not pg.noindex:
            yield path, "redirect page lacks noindex"


def check_heading_ids(b, fx):
    for path, post in fx.posts.items():
        pg = b.page(path)
        if pg is None:
            yield path, "post missing"
            continue
        lost = [i for i in post["heading_ids"] if i not in pg.ids]
        if lost:
            yield path, f"{len(lost)} heading id(s) gone: {cap(lost)}"


def check_feeds(b, fx):
    for path, items in fx.feeds.items():
        full = b.file_for(path)
        if not os.path.isfile(full):
            yield path, "feed missing"
            continue
        try:
            root = ET.parse(full).getroot()
        except ET.ParseError as e:
            yield path, f"not well-formed XML: {e}"
            continue
        have = {(it.findtext("link") or "").strip(): (it.findtext("guid") or "").strip()
                for it in root.iter("item")}
        lost, changed = [], []
        for item in items:
            if not item["link"].startswith("/posts/"):
                continue
            link = b.site.abs(item["link"])
            guid = b.site.abs(item["guid"]) if item["guid"].startswith("/") else item["guid"]
            if link not in have:
                lost.append(item["link"])
            elif have[link] != guid:
                changed.append(f"{item['link']} guid {have[link]!r} != {guid!r}")
        if lost:
            yield path, f"{len(lost)} post item(s) missing: {cap(lost, 3)}"
        if changed:
            yield path, f"guid changed: {cap(changed, 2)}"


def iter_refs(b):
    """(source path, description, url, base url) for every URL in HTML attributes and CSS."""
    for path, pg in b.html_pages():
        base_url = b.site.abs(path)
        for tag, attr, url in pg.refs:
            yield path, f"<{tag} {attr}>", url, base_url
    for path, css in b.css_files():
        for url in sitelib.css_urls(css):
            yield path, "css url()", url, b.site.abs(path)


def check_internal_refs(b):
    broken, frags, escapes = [], [], []
    for src, what, url, base_url in iter_refs(b):
        kind, rel, frag = b.site.classify(url, base_url)
        if kind == "escape":
            escapes.append((src, f"{what} {url} is outside base path {b.site.base}"))
        if kind != "internal":
            continue
        target = b.resolve(rel)
        if target is None:
            broken.append((src, f"{what} {url} -> not in build"))
        elif frag and frag != "top" and target.endswith(".html") and frag not in b.page_file(target).ids:
            frags.append((src, f"{what} {url} -> no id {frag!r} on target page"))
    return broken, frags, escapes


def gate_g1(b, fx, rep):
    rep.add("G1", "baseline URLs exist", check_urls_exist(b, fx), f"{len(fx.urls)} paths")
    rep.add("G1", "redirect pages keep target, canonical and noindex", check_redirects(b, fx),
            f"{len(fx.redirects)} redirects")
    rep.add("G1", "baseline post heading ids exist", check_heading_ids(b, fx),
            f"{sum(len(p['heading_ids']) for p in fx.posts.values())} ids in {len(fx.posts)} posts")
    rep.add("G1", "feeds well-formed; post items keep link and guid", check_feeds(b, fx),
            f"{len(fx.feeds)} feeds")
    broken, frags, escapes = check_internal_refs(b)
    rep.add("G1", "internal href/src/srcset/url() resolve to build files", broken)
    rep.add("G1", "fragment links match an id on the target page", frags)
    rep.add("G1", f"internal URLs stay under base path {b.site.base}", escapes,
            "preview" if b.preview else "production")


# --------------------------------------------------------------------------- G2 helpers

def as_list(x):
    return x if isinstance(x, list) else [] if x is None else [x]


def types_of(node):
    return set(as_list(node.get("@type"))) if isinstance(node, dict) else set()


class Graph:
    """All JSON-LD nodes of a page, with @id references merged."""

    def __init__(self, page):
        self.nodes, self.errors = [], []
        for raw in page.jsonld_blocks:
            try:
                self._walk(json.loads(raw))
            except ValueError as e:
                self.errors.append(f"invalid JSON-LD: {e}")
        self.by_id = defaultdict(list)
        for n in self.nodes:
            if "@id" in n:
                self.by_id[n["@id"]].append(n)

    def _walk(self, data):
        stack = [data]
        while stack:
            x = stack.pop()
            if isinstance(x, dict):
                self.nodes.append(x)
                stack.extend(x.values())
            elif isinstance(x, list):
                stack.extend(x)

    def merged(self, node):
        if not isinstance(node, dict):
            return {}
        out = dict(node)
        for other in self.by_id.get(node.get("@id"), []) if "@id" in node else []:
            for k, v in other.items():
                out.setdefault(k, v)
        return out

    def of_type(self, t):
        return [self.merged(n) for n in self.nodes if t in types_of(n)]

    def has_type(self, t):
        return any(t in types_of(n) for n in self.nodes)


def works_for_offensys(graph, person):
    for org in as_list(person.get("worksFor")):
        org = graph.merged(org)
        urls = [u.rstrip("/") for u in as_list(org.get("url")) if isinstance(u, str)]
        if types_of(org) & {"Organization", "Corporation"} and OFFENSYS_URL in urls:
            return True
    return False


def expected_canonical(b, info):
    return b.site.abs(info["canonical_path"])


def seo_title(b, path, info, pg):
    want, got = norm_text(info["title"]), norm_text(pg.title)
    if want not in got:
        yield f"<title> {got!r} lacks {want!r}"


def seo_lang_h1(b, path, info, pg):
    if not (pg.lang or "").strip():
        yield "<html lang> missing"
    if pg.h1_count != 1:
        yield f"{pg.h1_count} <h1> elements (expected 1)"


def seo_canonical(b, path, info, pg):
    canon = [l.get("href") for l in pg.links_with_rel("canonical")]
    want = expected_canonical(b, info)
    if len(canon) != 1:
        yield f"{len(canon)} canonical links (expected 1)"
    elif canon[0] != want:
        yield f"canonical {canon[0]} != {want}"


def seo_description(b, path, info, pg):
    desc = norm_text(pg.meta("description"))
    lo, hi = POST_DESC_RANGE
    if not desc:
        yield "meta description missing or empty"
    elif info["kind"] == "post" and not lo <= len(desc) <= hi:
        yield f"post description {len(desc)} chars (needs {lo}-{hi})"


def seo_social(b, path, info, pg):
    for key in ("og:title", "og:description", "og:url", "og:type", "og:image", "og:site_name",
                "twitter:card", "twitter:title", "twitter:description", "twitter:image"):
        if not norm_text(pg.meta(key)):
            yield f"missing {key}"
    og_url, want = pg.meta("og:url"), expected_canonical(b, info)
    if og_url and og_url != want:
        yield f"og:url {og_url} != canonical {want}"
    image = (pg.meta("og:image") or "").strip()
    if image and not re.match(r"https?://", image):
        yield f"og:image not absolute: {image}"
    elif image.startswith(b.site.url) and not b.local_file(image, b.site.url):
        yield f"og:image {image} not in build"


def seo_article(b, path, info, pg):
    if info["kind"] != "post":
        return
    for key in ("article:published_time", "article:modified_time"):
        if not norm_text(pg.meta(key)):
            yield f"missing {key}"
    if not any(norm_text(t) for t in pg.meta_all("article:tag")):
        yield "no article:tag"


def seo_jsonld_types(b, path, info, pg):
    g = Graph(pg)
    if info["kind"] == "home":
        for t in ("WebSite", "Person"):
            if not g.has_type(t):
                yield f"home JSON-LD lacks {t}"
    if info["kind"] != "post":
        return
    posts = g.of_type("BlogPosting")
    if not posts:
        yield "no BlogPosting JSON-LD"
        return
    bp = posts[0]
    missing = [k for k in ("headline", "datePublished", "dateModified", "author", "publisher",
                           "image", "mainEntityOfPage") if not bp.get(k)]
    if missing:
        yield f"BlogPosting lacks {', '.join(missing)}"
    authors = [g.merged(a) for a in as_list(bp.get("author"))]
    if not any("Person" in types_of(a) and a.get("url") and a.get("sameAs") for a in authors):
        yield "BlogPosting author is not a Person with url and sameAs"


def seo_author_theme(b, path, info, pg):
    author = norm_text(pg.meta("author"))
    if not author:
        yield "meta author missing"
    elif "map[" in author:
        yield f"meta author is {author!r}"
    if not norm_text(pg.meta("theme-color")):
        yield "meta theme-color missing or empty"


def seo_not_noindex(b, path, info, pg):
    if not b.preview and pg.noindex:
        yield "noindex on an indexable production page"


PAGE_CHECKS = [
    ("<title> contains the baseline title", seo_title),
    ("<html lang> set and exactly one <h1>", seo_lang_h1),
    ("canonical equals the expected URL", seo_canonical),
    ("meta description present (posts 50-220 chars)", seo_description),
    ("Open Graph and Twitter card tags", seo_social),
    ("posts carry article:published_time/modified_time/tag", seo_article),
    ("JSON-LD: home WebSite+Person, posts complete BlogPosting", seo_jsonld_types),
    ("meta author is a proper name; theme-color set", seo_author_theme),
    ("indexable pages are not noindex (production)", seo_not_noindex),
]


def check_build_wide_seo(b, fx):
    """Checks that apply to every HTML page in the build, not only baseline pages."""
    issues = defaultdict(list)
    for path, pg in b.html_pages():
        g = Graph(pg)
        issues["jsonld"] += [(path, e) for e in g.errors]
        for person in g.of_type("Person"):
            if not works_for_offensys(g, person):
                issues["person"].append((path, f"Person {person.get('name', '?')!r} lacks worksFor "
                                               f"Organization {OFFENSYS_URL}"))
        redirect = pg.refresh_url is not None
        if not redirect and not any((l.get("type") or "").lower() == RSS_TYPE
                                    for l in pg.links_with_rel("alternate")):
            issues["rss"].append((path, "no <link rel=alternate type=application/rss+xml>"))
        for img in pg.imgs:
            alt = img.get("alt")
            decorative = (img.get("role") in ("presentation", "none")
                          or (img.get("aria-hidden") or "").lower() == "true")
            if alt is None or (not alt.strip() and not (alt == "" and decorative)):
                issues["alt"].append((path, f"<img src={img.get('src', '')}> lacks alt text"))
        unsized = sum(1 for img in pg.imgs if not (img.get("width") and img.get("height")))
        if unsized:
            issues["size"].append((path, f"{unsized} <img> without width/height"))
        if b.preview and not pg.noindex:
            issues["preview"].append((path, "preview page lacks noindex"))
    return issues


def check_special_robots(b, fx):
    """Production: 404 and redirect pages must be noindex."""
    special = [p for p, i in fx.pages.items() if i["kind"] == "404"] + list(fx.redirects)
    for path in special:
        pg = b.page(path)
        if pg is not None and not pg.noindex:
            yield path, "must be noindex"


def sitemap_locs(b, full, seen=None):
    """Locations listed in a sitemap (following a sitemap index into local files)."""
    root = ET.parse(full).getroot()
    locs = [(el.text or "").strip() for el in root.iter() if el.tag.split("}")[-1] == "loc"]
    if root.tag.split("}")[-1] != "sitemapindex":
        return locs
    seen = seen or set()
    out = []
    for loc in locs:
        child = b.local_file(loc, b.site.url)
        if child and child not in seen:
            seen.add(child)
            out += sitemap_locs(b, child, seen)
    return out


def check_sitemap(b, fx):
    full = b.file_for("/sitemap.xml")
    if not os.path.isfile(full):
        return ["sitemap.xml missing"]
    try:
        locs = set(sitemap_locs(b, full))
    except ET.ParseError as e:
        return [f"sitemap.xml not well-formed: {e}"]
    if b.preview:
        return []
    # Every self-canonical indexable baseline page; paginated pages that canonicalise to
    # page 1 (/tags/page/2/) were never in the sitemap and should not be.
    want = [p for p, i in fx.indexable.items() if i["canonical_path"] == p]
    issues = [(p, "not in sitemap") for p in want if b.site.abs(p) not in locs]
    issues += [(p, "redirect page listed in sitemap") for p in fx.redirects if b.site.abs(p) in locs]
    issues += [(u, "preview URL in sitemap") for u in sorted(locs) if "/pr-preview/" in u]
    return issues


def check_robots_txt(b):
    full = b.file_for("/robots.txt")
    if not os.path.isfile(full):
        return ["robots.txt missing"]
    with open(full, encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    issues = []
    if not re.search(r"(?im)^\s*sitemap:\s*\S+", text):
        issues.append("robots.txt has no Sitemap: line")
    if not b.preview and not re.search(r"(?im)^\s*disallow:\s*/pr-preview/?\s*$", text):
        issues.append("robots.txt lacks Disallow: /pr-preview/")
    return issues


def gate_g2(b, fx, rep):
    per_check = {name: [] for name, _ in PAGE_CHECKS}
    missing, long_desc, no_crumbs = [], [], []
    for path, info in fx.indexable.items():
        pg = b.page(path)
        if pg is None:
            missing.append((path, "page missing"))
            continue
        for name, fn in PAGE_CHECKS:
            per_check[name] += [(path, msg) for msg in fn(b, path, info, pg)]
        desc = norm_text(pg.meta("description"))
        if len(desc) > DESC_SHOULD_MAX:
            long_desc.append((path, f"description {len(desc)} chars (> {DESC_SHOULD_MAX})"))
        if info["kind"] == "post" and not Graph(pg).has_type("BreadcrumbList"):
            no_crumbs.append((path, "no BreadcrumbList JSON-LD"))

    rep.add("G2", "indexable baseline pages exist", missing, f"{len(fx.indexable)} pages")
    for name, _ in PAGE_CHECKS:
        if name.endswith("(production)") and b.preview:
            continue
        rep.add("G2", name, per_check[name])
    wide = check_build_wide_seo(b, fx)
    rep.add("G2", "JSON-LD blocks parse (all pages)", wide["jsonld"])
    rep.add("G2", f"every Person has worksFor Organization {OFFENSYS_URL} (all pages)", wide["person"])
    rep.add("G2", "RSS autodiscovery link on every non-redirect page", wide["rss"])
    rep.add("G2", "every <img> has alt (or is marked decorative)", wide["alt"])
    if b.preview:
        rep.add("G2", "every page is noindex (preview)", wide["preview"])
    else:
        rep.add("G2", "404 and redirect pages are noindex (production)", check_special_robots(b, fx))
    rep.add("G2", "sitemap.xml" + (" well-formed (preview)" if b.preview else
                                   " well-formed, complete, no redirects or previews"),
            check_sitemap(b, fx))
    rep.add("G2", "robots.txt has Sitemap:" + ("" if b.preview else " and Disallow: /pr-preview/"),
            check_robots_txt(b))
    rep.warn("G2", "<img> has width and height", wide["size"])
    rep.warn("G2", "posts have BreadcrumbList JSON-LD", no_crumbs)
    rep.warn("G2", f"description <= {DESC_SHOULD_MAX} chars", long_desc)


# --------------------------------------------------------------------------- G3

def page_ref_paths(b, pg, path):
    """Site-relative paths (base path stripped) of every URL referenced on a page."""
    out = set()
    for _, _, url in pg.refs:
        p = urlsplit(urljoin(b.site.abs(path), url)).path
        out.add("/" + p[len(b.site.base):] if p.startswith(b.site.base) else p)
    return out


def check_post_body(post, pg):
    if pg.body is None:
        yield "no [data-post-body] element"
        return
    body, old = pg.body, post["word_count"]
    delta = (body.word_count - old) / old if old else 0
    if abs(delta) > WORD_TOLERANCE:
        yield f"{body.word_count} words vs baseline {old} ({delta:+.1%}, limit ±{WORD_TOLERANCE:.0%})"
    if body.pre_count < post["pre_count"]:
        yield f"{body.pre_count} <pre> vs baseline {post['pre_count']}"
    want_imgs = len(post["local_images"]) + len(post["external_images"])
    if len(body.img_srcs) < want_imgs:
        yield f"{len(body.img_srcs)} <img> in body vs baseline {want_imgs}"


def check_post_assets(b, path, post, pg):
    refs = page_ref_paths(b, pg, path)
    lost = [i for i in post["local_images"] if i not in refs]
    if lost:
        yield f"local image(s) no longer referenced: {cap(lost)}"
    linked = {m.group(1) for h in pg.anchor_hrefs for m in [sitelib.STATUS_RE.search(h)] if m}
    gone = [t for t in post["tweet_ids"] if t not in linked]
    if gone:
        yield f"tweet(s) without a link to the original: {cap(gone)}"


def check_post_toc(post, pg):
    if not post["has_toc"]:
        return
    if pg.toc is None:
        yield "no [data-toc] element"
        return
    heading_ids = set(pg.body.heading_ids) if pg.body else pg.ids
    frags = [urlsplit(h).fragment for h in pg.toc]
    if not any(f in heading_ids for f in frags):
        yield "TOC has no links to heading ids"
    bad = [f for f in frags if f and f not in heading_ids]
    if bad:
        yield f"TOC links to missing heading ids: {cap(bad)}"


def check_widgets_js(b):
    for rel in b.files:
        if rel.endswith(TEXT_EXTS):
            with open(os.path.join(b.root, rel), encoding="utf-8", errors="replace") as fh:
                if WIDGETS_JS in fh.read():
                    yield "/" + rel, f"references {WIDGETS_JS}"


def check_about(b, fx):
    path = fx.about.get("path")
    if not path:
        return []
    pg = b.page(path)
    if pg is None:
        return [(path, "page missing")]
    text = norm_text(pg.text)
    return [(path, f"sentence lost: {s!r}") for s in fx.about["sentences"] if norm_text(s) not in text]


def gate_g3(b, fx, rep):
    body, assets, toc = [], [], []
    for path, post in fx.posts.items():
        pg = b.page(path)
        if pg is None:
            body.append((path, "post missing"))
            continue
        body += [(path, m) for m in check_post_body(post, pg)]
        assets += [(path, m) for m in check_post_assets(b, path, post, pg)]
        toc += [(path, m) for m in check_post_toc(post, pg)]
    rep.add("G3", "post body: word count ±3%, <pre> and <img> counts >= baseline", body,
            f"{len(fx.posts)} posts")
    rep.add("G3", "baseline local images still used; tweets link to the original", assets)
    rep.add("G3", "TOC present with links to heading ids (toc posts)", toc)
    rep.add("G3", f"no {WIDGETS_JS} anywhere in the build", check_widgets_js(b))
    rep.add("G3", "About keeps every baseline sentence", check_about(b, fx),
            f"{len(fx.about.get('sentences', []))} sentences")


# --------------------------------------------------------------------------- G5

def page_weights(b, path, pg):
    """(css_gzip_bytes, js_gzip_bytes) for one page: linked local files + inline code."""
    base_url = b.site.abs(path)
    css_files, js_files = set(), set()
    for link in pg.links:
        rels = (link.get("rel") or "").lower().split()
        target = b.local_file(link.get("href"), base_url)
        if target and "stylesheet" in rels:
            css_files.add(target)
        elif target and "modulepreload" in rels:
            js_files.add(target)
    inline_js = []
    for attrs, text in pg.scripts:
        if attrs.get("src"):
            target = b.local_file(attrs["src"], base_url)
            if target:
                js_files.add(target)
        elif "json" not in (attrs.get("type") or "").lower():
            inline_js.append(text)
    css = sum(b.gzip_size(f) for f in css_files) + gz("".join(pg.styles))
    js = sum(b.gzip_size(f) for f in js_files) + gz("".join(inline_js))
    return css, js


def check_budgets(b):
    over, worst = [], {"CSS": (0, ""), "JS": (0, "")}
    for path, pg in b.html_pages():
        css, js = page_weights(b, path, pg)
        for kind, size, budget in (("CSS", css, CSS_BUDGET), ("JS", js, JS_BUDGET)):
            worst[kind] = max(worst[kind], (size, path))
            if size > budget:
                over.append((path, f"{kind} {fmt_kb(size)} gzip > {fmt_kb(budget)}"))
    note = ", ".join(f"max {k} {fmt_kb(s)} on {p or '-'}" for k, (s, p) in worst.items())
    return over, note


def check_fonts(b):
    fonts = [(rel, os.path.getsize(os.path.join(b.root, rel))) for rel in b.files
             if rel.lower().endswith(FONT_EXTS)]
    total = sum(size for _, size in fonts)
    note = f"{len(fonts)} font file(s), {fmt_kb(total)}"
    issues = [f"font files total {fmt_kb(total)} > {fmt_kb(FONT_BUDGET)} "
              f"({cap(r for r, _ in fonts)})"] if total > FONT_BUDGET else []
    return issues, note


def check_third_party(b):
    fails, imgs = [], []
    for path, pg in b.html_pages():
        for attrs, _ in pg.scripts:
            if b.is_third_party(attrs.get("src")):
                fails.append((path, f"<script src={attrs['src']}>"))
        for link in pg.links:
            rels = (link.get("rel") or "").lower().split()
            loads = {"stylesheet", "preload", "modulepreload"} & set(rels) or any("icon" in r for r in rels)
            if loads and b.is_third_party(link.get("href")):
                fails.append((path, f"<link rel={' '.join(rels)} href={link.get('href')}>"))
        for frame in pg.iframes:
            if b.is_third_party(frame.get("src")):
                fails.append((path, f"<iframe src={frame.get('src')}>"))
        for tag, attr, url in pg.refs:
            if attr in ("url()", "style") and b.is_third_party(url):
                fails.append((path, f"inline CSS url({url})"))
        for img in pg.imgs:
            if b.is_third_party(img.get("src")):
                imgs.append((path, f"third-party <img src={img.get('src')}>"))
    for path, css in b.css_files():
        fails += [(path, f"CSS url()/@import {u}") for u in sitelib.css_urls(css) if b.is_third_party(u)]
    return fails, imgs


def gate_g5(b, fx, rep):
    over, note = check_budgets(b)
    rep.add("G5", f"per-page CSS <= {fmt_kb(CSS_BUDGET)} and JS <= {fmt_kb(JS_BUDGET)} gzip", over, note)
    fonts, note = check_fonts(b)
    rep.add("G5", f"font files <= {fmt_kb(FONT_BUDGET)} total", fonts, note)
    fails, imgs = check_third_party(b)
    rep.add("G5", "no third-party scripts, stylesheets, preloads, icons, iframes or CSS urls", fails)
    rep.warn("G5", "no third-party images", imgs)


# --------------------------------------------------------------------------- main

def parse_args(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("build_dir")
    ap.add_argument("--site-url", required=True, help="full URL this build is served from")
    ap.add_argument("--preview", action="store_true", help="the build is a PR preview")
    ap.add_argument("--baseline", default=DEFAULT_BASELINE, help="fixture directory")
    ap.add_argument("--only", default="", help="comma-separated gates to run, e.g. G1,G3")
    args = ap.parse_args(argv)
    args.gates = [g.strip().upper() for g in args.only.split(",") if g.strip()] or list(GATES)
    unknown = [g for g in args.gates if g not in GATES]
    if unknown:
        ap.error(f"unknown gate(s) {unknown}; choose from {', '.join(GATES)}")
    if not os.path.isdir(args.build_dir):
        ap.error(f"build dir {args.build_dir} does not exist")
    return args


def main(argv=None):
    args = parse_args(argv)
    build = Build(args.build_dir, args.site_url, args.preview)
    fixtures = Fixtures(args.baseline)
    print(f"check_site: {build.root} as {build.site.url} "
          f"({'preview' if args.preview else 'production'}), baseline {args.baseline}")
    rep = Report([g for g in GATES if g in args.gates])
    runners = {"G1": gate_g1, "G2": gate_g2, "G3": gate_g3, "G5": gate_g5}
    for gate in rep.gates:
        runners[gate](build, fixtures, rep)
    text, fails = rep.render()
    print(text)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
