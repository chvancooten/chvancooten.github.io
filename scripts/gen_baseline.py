#!/usr/bin/env python3
"""Generate the committed baseline fixtures from the old (hello-friend-ng) site output.

Usage: python3 scripts/gen_baseline.py <baseline_dir> [out_dir=tests/baseline] [--site-url URL]

The fixtures are the contract check_site.py holds every new build to. They are generated
once from the live gh-pages output and must not be edited to make a check pass.

Old-theme selectors: the post body is <div class=post-content> (inside <main class=post>);
the TOC is <aside id=toc> / <nav id=TableOfContents>, which sits outside the post body.
"""
import argparse
import json
import os
import re
import sys
import xml.etree.ElementTree as ET

sys.dont_write_bytecode = True  # keep scripts/ free of __pycache__
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sitelib  # noqa: E402

# Theme assets of the old theme that the new build does not need to keep.
ASSET_ALLOWLIST = [re.compile(p) for p in (
    r"bundle\.min\.[0-9a-f]+\.js", r"main\.min\.[0-9a-f]+\.css", r"main\.css\.map",
    r"css/flag-icons\.min\.css", r"flags/.*", r"fonts/Inter-[^/]*")]
DEPLOY_FILES = {"CNAME", ".nojekyll"}  # added by the deploy step, not by Hugo
TAXONOMIES = ("tags", "series")
TITLE_SUFFIX = " :: Cas van Cooten"


def body_match(tag, a):
    return tag == "div" and sitelib.has_class(a, "post-content")


def toc_match(tag, a):
    return a.get("id") in ("toc", "TableOfContents")


def is_excluded(rel):
    return rel in DEPLOY_FILES or any(rx.fullmatch(rel) for rx in ASSET_ALLOWLIST)


def page_kind(path, page):
    if path == "/":
        return "home"
    if path == "/404.html":
        return "404"
    if re.fullmatch(r"/posts/\d{4}/\d{2}/[^/]+/", path):
        return "post"
    parts = re.sub(r"page/\d+/$", "", path).strip("/").split("/")
    if parts[0] in TAXONOMIES:
        return "taxonomy" if len(parts) == 1 else "term"
    if len(parts) == 1 and page.meta("og:type") == "website":
        return "section"
    return "page"


def clean_title(title):
    title = sitelib.norm_text(title)
    return title[: -len(TITLE_SUFFIX)] if title.endswith(TITLE_SUFFIX) else title


def post_facts(page, site):
    body = page.body
    srcs = [site.to_path(s) for s in body.img_srcs]
    return {
        "heading_ids": body.heading_ids,
        "word_count": body.word_count,
        "pre_count": body.pre_count,
        "local_images": sorted({s for s in srcs if s.startswith("/images/")}),
        "external_images": sorted({s for s in srcs if re.match(r"https?://", s)}),
        "tweet_ids": body.tweet_ids,
        "has_toc": bool(page.toc),
    }


def feed_items(path):
    root = ET.parse(path).getroot()
    return [{"link": (it.findtext("link") or "").strip(), "guid": (it.findtext("guid") or "").strip()}
            for it in root.iter("item")]


def sitemap_locs(path):
    root = ET.parse(path).getroot()
    return [(el.text or "").strip() for el in root.iter() if el.tag.endswith("}loc") or el.tag == "loc"]


def build_fixtures(src, site):
    files = sorted(f for f in sitelib.iter_files(src) if not is_excluded(f))
    urls = sorted({sitelib.served_path(f) for f in files})
    pages, redirects, posts, feeds, about = {}, {}, {}, {}, {}
    for rel in files:
        full = os.path.join(src, rel)
        path = sitelib.served_path(rel)
        if rel.endswith(".html"):
            page = sitelib.parse_file(full, body_match, toc_match)
            if page.refresh_url is not None:
                redirects[path] = site.to_path(page.refresh_url)
                continue
            canonical = next((l.get("href") for l in page.links_with_rel("canonical")), "")
            kind = page_kind(path, page)
            pages[path] = {"kind": kind, "title": clean_title(page.title or ""),
                           "canonical_path": site.to_path(canonical)}
            if kind == "post":
                posts[path] = post_facts(page, site)
            if path == "/about/":
                about = {"path": path, "sentences": [
                    s for para in page.body.paragraphs for s in sitelib.split_sentences(para)]}
        elif rel.endswith(".xml") and rel != "sitemap.xml":
            feeds[path] = [{k: site.to_path(v) for k, v in item.items()} for item in feed_items(full)]
    sitemap = [site.to_path(u) for u in sitemap_locs(os.path.join(src, "sitemap.xml"))]
    return {
        "urls.txt": "\n".join(urls) + "\n",
        "redirects.json": redirects,
        "pages.json": pages,
        "posts.json": posts,
        "feeds.json": feeds,
        "sitemap.json": sitemap,
        "about.json": about,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("baseline_dir")
    ap.add_argument("out_dir", nargs="?", default="tests/baseline")
    ap.add_argument("--site-url", default="https://casvancooten.com/",
                    help="production URL the baseline was built for")
    args = ap.parse_args()
    site = sitelib.SiteUrl(args.site_url)
    fixtures = build_fixtures(args.baseline_dir, site)
    os.makedirs(args.out_dir, exist_ok=True)
    for name, data in fixtures.items():
        with open(os.path.join(args.out_dir, name), "w", encoding="utf-8") as fh:
            if isinstance(data, str):
                fh.write(data)
            else:
                json.dump(data, fh, indent=1, ensure_ascii=False, sort_keys=True)
                fh.write("\n")
    print(f"{args.out_dir}: {fixtures['urls.txt'].count(chr(10))} urls, "
          f"{len(fixtures['pages.json'])} pages, {len(fixtures['redirects.json'])} redirects, "
          f"{len(fixtures['posts.json'])} posts, {len(fixtures['feeds.json'])} feeds, "
          f"{len(fixtures['sitemap.json'])} sitemap entries, "
          f"{len(fixtures['about.json'].get('sentences', []))} About sentences")


if __name__ == "__main__":
    main()
