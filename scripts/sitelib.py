"""Shared helpers for gen_baseline.py and check_site.py (Python 3 stdlib only).

One HTML parser pass per page produces a `Page` with every fact the checks need.
The caller decides which element is the post body and which is the TOC by passing
two predicates, so the same parser works for the old theme (baseline) and the new one.
"""
import os
import re
from html.parser import HTMLParser
from urllib.parse import unquote, urljoin, urlsplit

VOID_TAGS = frozenset(
    "area base br col embed hr img input link meta param source track wbr".split())
# Elements that visually separate text; we insert a space at their boundaries.
BLOCK_TAGS = frozenset((
    "address article aside blockquote br dd details div dl dt figcaption figure footer "
    "form h1 h2 h3 h4 h5 h6 header hr li main nav ol p pre section summary table tbody "
    "td tfoot th thead tr ul").split())
TEXTLESS_TAGS = frozenset(("template", "noscript", "svg"))
HEADINGS = frozenset(("h1", "h2", "h3", "h4", "h5", "h6"))
SKIP_SCHEMES = frozenset(("mailto", "tel", "sms", "javascript", "data", "blob", "about"))
STATUS_RE = re.compile(r"/status(?:es)?/(\d+)")
WORD_RE = re.compile(r"\w")
REFRESH_RE = re.compile(r"^\s*\d*\s*[;,]?\s*url\s*=\s*['\"]?([^'\"]+)['\"]?\s*$", re.I)
QUOTES = str.maketrans({
    "‘": "'", "’": "'", "‚": "'", "‛": "'", "′": "'",
    "“": '"', "”": '"', "„": '"', "‟": '"', "″": '"',
    " ": " ",
})


def norm_text(s):
    """Collapse whitespace and fold curly quotes to straight ones."""
    return " ".join((s or "").translate(QUOTES).split())


def count_words(text):
    """Whitespace-separated tokens that contain at least one letter or digit."""
    return sum(1 for tok in text.split() if WORD_RE.search(tok))


def split_sentences(text):
    return [s for s in re.split(r"(?<=[.!?])\s+", norm_text(text)) if s]


def srcset_urls(value):
    urls = []
    for cand in (value or "").split(","):
        parts = cand.split()
        if parts and not parts[0].startswith("data:"):
            urls.append(parts[0])
    return urls


CSS_COMMENT_RE = re.compile(r"/\*.*?\*/", re.S)
CSS_URL_RE = re.compile(r"""url\(\s*(?:"([^"]*)"|'([^']*)'|([^)\s]*))\s*\)""", re.I)
CSS_IMPORT_RE = re.compile(r"""@import\s+(?:"([^"]*)"|'([^']*)')""", re.I)


def css_urls(css):
    """All url(...) and @import "..." references in a CSS string."""
    css = CSS_COMMENT_RE.sub("", css)
    out = []
    for rx in (CSS_URL_RE, CSS_IMPORT_RE):
        for m in rx.finditer(css):
            u = next((g for g in m.groups() if g is not None), "").strip()
            if u and not u.startswith("data:"):
                out.append(u)
    return out


def has_class(attrs, name):
    return name in (attrs.get("class") or "").split()


class Body:
    """Facts about the post-body element (rendered Markdown only)."""

    def __init__(self):
        self.text_parts = []
        self.heading_ids = []
        self.pre_count = 0
        self.img_srcs = []
        self.paragraphs = []
        self.tweet_ids = []

    @property
    def text(self):
        return norm_text("".join(self.text_parts))

    @property
    def word_count(self):
        return count_words(self.text)


class Page:
    """Everything the checks need from one HTML document."""

    def __init__(self):
        self.lang = None
        self.title = None
        self.metas = []       # attribute dicts of every <meta>
        self.links = []       # attribute dicts of every <link>
        self.ids = set()      # id attributes (plus <a name>)
        self.h1_count = 0
        self.refs = []        # (tag, attr, url) from href/src/srcset/poster and inline CSS
        self.imgs = []        # attribute dicts of every <img>
        self.scripts = []     # (attrs, inline text)
        self.styles = []      # inline <style> contents
        self.iframes = []     # attribute dicts
        self.anchor_hrefs = []
        self.body = None      # Body, if the body predicate matched
        self.toc = None       # list of hrefs inside the TOC element, if it matched
        self.text_parts = []  # visible text outside <head>

    @property
    def text(self):
        return norm_text("".join(self.text_parts))

    def meta(self, key):
        """Content of the first <meta name=key> or <meta property=key>, or None."""
        vals = self.meta_all(key)
        return vals[0] if vals else None

    def meta_all(self, key):
        key = key.lower()
        return [m.get("content") or "" for m in self.metas
                if (m.get("name") or "").lower() == key or (m.get("property") or "").lower() == key]

    def links_with_rel(self, rel):
        return [l for l in self.links if rel in (l.get("rel") or "").lower().split()]

    @property
    def refresh_url(self):
        for m in self.metas:
            if (m.get("http-equiv") or "").lower() == "refresh":
                mt = REFRESH_RE.match(m.get("content") or "")
                return mt.group(1).strip() if mt else (m.get("content") or "")
        return None

    @property
    def noindex(self):
        return any("noindex" in v.lower() for v in self.meta_all("robots") + self.meta_all("googlebot"))

    @property
    def jsonld_blocks(self):
        return [text for attrs, text in self.scripts
                if (attrs.get("type") or "").strip().lower() == "application/ld+json"]


class _Parser(HTMLParser):
    def __init__(self, body_match, toc_match):
        super().__init__(convert_charrefs=True)
        self.page = Page()
        self.body_match = body_match
        self.toc_match = toc_match
        self.stack = []
        self.regions = {}   # region name -> stack depth at which it was opened
        self.bufs = {}      # region name -> captured text
        self.script_attrs = None

    # -- element stack -------------------------------------------------------
    def handle_starttag(self, tag, attrs):
        self._start(tag, attrs, tag in VOID_TAGS)

    def handle_startendtag(self, tag, attrs):
        self._start(tag, attrs, True)

    def handle_endtag(self, tag):
        if tag not in self.stack:
            return
        if tag in BLOCK_TAGS:
            self._text(" ")
        while self.stack:
            top = self.stack.pop()
            self._close_regions()
            if top == tag:
                break

    def _start(self, tag, attrs, void):
        a = {k: (v if v is not None else "") for k, v in attrs}
        if tag == "body" and "head" in self.stack:  # tolerate an omitted </head>
            self.handle_endtag("head")
        if tag in BLOCK_TAGS:
            self._text(" ")
        opened = self._element(tag, a)
        if void:
            return
        depth = len(self.stack)
        self.stack.append(tag)
        for name in opened:
            if name not in self.regions:
                self.regions[name] = depth
                self.bufs[name] = []

    def _close_regions(self):
        n = len(self.stack)
        for name, depth in list(self.regions.items()):
            if depth >= n:
                del self.regions[name]
                self._region_closed(name, "".join(self.bufs.pop(name, [])))

    def _region_closed(self, name, text):
        p = self.page
        if name == "title":
            p.title = norm_text(text)
        elif name == "script":
            p.scripts.append((self.script_attrs or {}, text))
        elif name == "style":
            p.styles.append(text)
            p.refs.extend(("style", "url()", u) for u in css_urls(text))
        elif name == "p" and p.body is not None and norm_text(text):
            p.body.paragraphs.append(norm_text(text))

    # -- per-element facts ---------------------------------------------------
    def _element(self, tag, a):
        p, r = self.page, self.regions
        opened = []
        in_body = "body" in r and "toc" not in r
        if tag == "html" and p.lang is None:
            p.lang = a.get("lang", "")
        elif tag == "head":
            opened.append("head")
        elif tag == "title" and p.title is None and "textless" not in r:
            opened.append("title")
        elif tag == "meta":
            p.metas.append(a)
        elif tag == "link":
            p.links.append(a)
        elif tag == "script":
            self.script_attrs = a
            opened.append("script")
        elif tag == "style":
            opened.append("style")
        elif tag == "iframe":
            p.iframes.append(a)
        elif tag == "img":
            p.imgs.append(a)
            if in_body:
                p.body.img_srcs.append(a.get("src", ""))
        elif tag == "h1":
            p.h1_count += 1
        elif tag == "pre" and in_body:
            p.body.pre_count += 1
        if tag in TEXTLESS_TAGS:
            opened.append("textless")

        if a.get("id"):
            p.ids.add(a["id"])
            if in_body and tag in HEADINGS:
                p.body.heading_ids.append(a["id"])
        if tag == "a" and a.get("name"):
            p.ids.add(a["name"])

        for attr in ("href", "src", "poster"):
            if attr in a:
                p.refs.append((tag, attr, a[attr]))
        for attr in ("srcset", "imagesrcset"):
            p.refs.extend((tag, attr, u) for u in srcset_urls(a.get(attr)))
        if a.get("style"):
            p.refs.extend((tag, "style", u) for u in css_urls(a["style"]))

        if tag == "a" and "href" in a:
            p.anchor_hrefs.append(a["href"])
            if "toc" in r:
                p.toc.append(a["href"])
            if "tweet" in r and p.body is not None:
                m = STATUS_RE.search(a["href"])
                if m and m.group(1) not in p.body.tweet_ids:
                    p.body.tweet_ids.append(m.group(1))

        if "toc" not in r and self.toc_match(tag, a):
            p.toc = []
            opened.append("toc")
        if "body" not in r and self.body_match(tag, a):
            p.body = Body()
            opened.append("body")
        if "body" in r or "body" in opened:
            if (a.get("aria-hidden") or "").lower() == "true" or "hidden" in a:
                opened.append("hidden")
            if tag == "p":
                opened.append("p")
            if tag == "blockquote" and has_class(a, "twitter-tweet"):
                opened.append("tweet")
        return opened

    # -- text ----------------------------------------------------------------
    def handle_data(self, data):
        r = self.regions
        for name in ("title", "script", "style"):
            if name in r:
                self.bufs[name].append(data)
        if "script" in r or "style" in r:
            return
        self._text(data)

    def _text(self, s):
        r, p = self.regions, self.page
        if "textless" in r or "script" in r or "style" in r:
            return
        if "head" not in r:
            p.text_parts.append(s)
        if "body" in r and "toc" not in r and "hidden" not in r:
            p.body.text_parts.append(s)
        if "p" in r:
            self.bufs["p"].append(s)


def parse_html(text, body_match, toc_match):
    parser = _Parser(body_match, toc_match)
    parser.feed(text)
    parser.close()
    while parser.stack:  # close anything left open so region buffers are flushed
        parser.handle_endtag(parser.stack[-1])
    return parser.page


def parse_file(path, body_match, toc_match):
    with open(path, encoding="utf-8", errors="replace") as fh:
        return parse_html(fh.read(), body_match, toc_match)


def iter_files(root, skip_top=("pr-preview", ".git")):
    """Yield site-relative file paths ('a/b.html') below root, skipping top-level dirs."""
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root)
        if rel_dir == ".":
            dirnames[:] = [d for d in dirnames if d not in skip_top]
            rel_dir = ""
        for f in filenames:
            yield (os.path.join(rel_dir, f) if rel_dir else f).replace(os.sep, "/")


def served_path(rel):
    """'about/index.html' -> '/about/', 'index.html' -> '/', '404.html' -> '/404.html'."""
    if rel == "index.html":
        return "/"
    if rel.endswith("/index.html"):
        return "/" + rel[: -len("index.html")]
    return "/" + rel


class SiteUrl:
    """Maps between absolute URLs, base-path-relative paths and build files."""

    def __init__(self, site_url):
        if not site_url.endswith("/"):
            site_url += "/"
        self.url = site_url
        parts = urlsplit(site_url)
        self.host = parts.netloc.lower()
        self.base = parts.path or "/"

    def abs(self, path):
        """Fixture path ('/about/') -> absolute URL under this site."""
        return self.url + path.lstrip("/")

    def to_path(self, url):
        """Absolute URL under this site -> fixture path ('/about/'); otherwise returned unchanged."""
        return "/" + url[len(self.url):] if url.startswith(self.url) else url

    def classify(self, url, base_url):
        """Return (kind, rel, fragment) for a reference found on the page at base_url.

        kind: 'skip' (mailto:, data:, empty, same-page '#'), 'external', 'escape'
        (internal-looking URL outside the base path), or 'internal' with rel being the
        unquoted path below the base path ('' for the site root).
        """
        url = (url or "").strip()
        if not url or url == "#":
            return "skip", None, None
        scheme = urlsplit(url).scheme.lower()
        if scheme in SKIP_SCHEMES or (scheme and scheme not in ("http", "https")):
            return "skip", None, None
        has_host = bool(scheme) or url.startswith("//")
        if scheme:  # browsers read "https:///host/x" as "https://host/x"
            url = re.sub(r"^([a-zA-Z]+:)[/\\]*", r"\1//", url)
        parts = urlsplit(urljoin(base_url, url))
        if has_host and parts.netloc.lower() != self.host:
            return "external", None, None
        if not parts.path.startswith(self.base):
            # Absolute links to the production host outside a preview base path are
            # ordinary external links; root-relative and relative ones escape the prefix.
            return ("external" if has_host else "escape"), None, None
        return "internal", unquote(parts.path[len(self.base):]), unquote(parts.fragment)
