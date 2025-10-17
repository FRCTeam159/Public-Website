#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import sys
import time
import queue
import hashlib
import urllib.parse as urlparse
from dataclasses import dataclass, field
from typing import Set, Iterable, Optional

import requests
from bs4 import BeautifulSoup

# CONFIG
START_URLS = [
    # Put your site URLs here (home page, top categories, etc.)
    "https://alpinerobotics.org/",
]
OUTPUT_DIR = "downloaded_images"
ALLOWED_DOMAIN = None  # e.g., "example.com" to restrict crawl; if None, auto from first start URL
MAX_PAGES = 500
CONNECTIONS_TIMEOUT = (10, 20)  # (connect, read)
SLEEP_BETWEEN_REQUESTS = 0.25  # polite crawling
MIN_IMAGE_BYTES = 30_000  # ignore tiny assets by default (~30 KB)
USER_AGENT = "ImageScraper/1.0 (+https://yourdomain.com)"

# WordPress-specific patterns
UPLOADS_PATH_FRAGMENT = "/wp-content/uploads/"
SIZE_SUFFIX_RE = re.compile(r"(-\d{2,4}x\d{2,4})(?=\.[a-zA-Z]{2,5}$)")  # -123x456 before extension
IMAGE_EXT_RE = re.compile(r"\.(png|jpe?g|webp|gif|tiff?|bmp|svg)$", re.IGNORECASE)

# Skip obvious non-content images
SKIP_PATTERNS = [
    r"/emoji/",
    r"/icons?/",
    r"/avatar",
    r"/placeholder",
    r"/sprite",
    r"/logo",
    r"/wp-includes/",
]
SKIP_RE = re.compile("|".join(SKIP_PATTERNS), re.IGNORECASE)


@dataclass(eq=True, frozen=True)
class Url:
    url: str


@dataclass
class State:
    to_visit: "queue.Queue[Url]" = field(default_factory=queue.Queue)
    visited_pages: Set[str] = field(default_factory=set)
    found_images: Set[str] = field(default_factory=set)
    downloaded_hashes: Set[str] = field(default_factory=set)


def same_domain(url: str, domain: str) -> bool:
    try:
        netloc = urlparse.urlparse(url).netloc
        return netloc == domain or netloc.endswith("." + domain)
    except Exception:
        return False


def absolutize(base: str, link: str) -> Optional[str]:
    if not link:
        return None
    link = link.strip()
    if link.startswith("mailto:") or link.startswith("tel:") or link.startswith("javascript:"):
        return None
    try:
        abs_url = urlparse.urljoin(base, link)
        parsed = urlparse.urlparse(abs_url)
        if not parsed.scheme.startswith("http"):
            return None
        return abs_url
    except Exception:
        return None


def request_url(session: requests.Session, url: str) -> Optional[requests.Response]:
    try:
        resp = session.get(url, timeout=CONNECTIONS_TIMEOUT)
        if resp.status_code == 200:
            return resp
        return None
    except requests.RequestException:
        return None


def is_probably_wp_media(url: str) -> bool:
    if SKIP_RE.search(url):
        return False
    if UPLOADS_PATH_FRAGMENT in url and IMAGE_EXT_RE.search(url):
        return True
    # Some themes serve images outside uploads; allow any image URL but prioritize uploads
    return bool(IMAGE_EXT_RE.search(url))


def prefer_fullsize_url(img_url: str, session: requests.Session) -> str:
    """
    If URL ends with -WIDTHxHEIGHT.ext, try original by removing the size suffix.
    Only rewrite if the original exists (HTTP 200 and larger or equal size).
    """
    m = SIZE_SUFFIX_RE.search(img_url)
    if not m:
        return img_url

    original_url = img_url[: m.start()] + img_url[m.end() :]
    try:
        head = session.head(original_url, timeout=CONNECTIONS_TIMEOUT, allow_redirects=True)
        if head.status_code == 200:
            return original_url
    except requests.RequestException:
        pass
    return img_url


def sanitize_filename_from_url(url: str) -> str:
    parsed = urlparse.urlparse(url)
    path = parsed.path
    name = os.path.basename(path) or "image"
    # Include a short hash to avoid collisions
    h = hashlib.sha1(url.encode("utf-8")).hexdigest()[:8]
    root, ext = os.path.splitext(name)
    safe_root = re.sub(r"[^a-zA-Z0-9._-]+", "_", root)[:80]
    ext = ext if ext else ".bin"
    return f"{safe_root}.{h}{ext.lower()}"


def save_image(session: requests.Session, url: str, out_dir: str, min_bytes: int) -> Optional[str]:
    resp = request_url(session, url)
    if not resp:
        return None

    data = resp.content
    if len(data) < min_bytes:
        return None

    fname = sanitize_filename_from_url(resp.url)  # use final URL after redirects
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, fname)

    # Deduplicate by content hash
    content_hash = hashlib.sha1(data).hexdigest()
    if os.path.exists(out_path):
        return out_path
    if content_hash in state.downloaded_hashes:
        return None

    with open(out_path, "wb") as f:
        f.write(data)
    state.downloaded_hashes.add(content_hash)
    return out_path


def parse_links_and_images(base_url: str, html: str) -> tuple[Set[str], Set[str]]:
    soup = BeautifulSoup(html, "html.parser")
    page_links: Set[str] = set()
    images: Set[str] = set()

    # Links for crawling
    for a in soup.find_all("a", href=True):
        abs_url = absolutize(base_url, a["href"])
        if abs_url:
            page_links.add(abs_url)

    # Image sources
    for tag in soup.find_all(["img", "source", "a"]):
        url_candidate = None
        if tag.name == "img":
            url_candidate = tag.get("src") or tag.get("data-src") or tag.get("data-lazy-src")
            srcset = tag.get("srcset")
            if srcset:
                # pick the last (usually largest)
                parts = [p.strip().split(" ")[0] for p in srcset.split(",") if p.strip()]
                if parts:
                    url_candidate = parts[-1]
        elif tag.name == "source":
            srcset = tag.get("srcset")
            if srcset:
                parts = [p.strip().split(" ")[0] for p in srcset.split(",") if p.strip()]
                if parts:
                    url_candidate = parts[-1]
        elif tag.name == "a":
            href = tag.get("href")
            # media file pages link directly to the file in many WP sites
            if href and (UPLOADS_PATH_FRAGMENT in href or IMAGE_EXT_RE.search(href)):
                url_candidate = href

        abs_img = absolutize(base_url, url_candidate) if url_candidate else None
        if abs_img and is_probably_wp_media(abs_img):
            images.add(abs_img)

    return page_links, images


def crawl_and_download(
    start_urls: Iterable[str],
    allowed_domain: Optional[str],
    out_dir: str,
    max_pages: int,
    min_image_bytes: int,
):
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    # Determine domain constraint
    first = next(iter(start_urls))
    parsed = urlparse.urlparse(first)
    domain = allowed_domain or parsed.netloc

    for u in start_urls:
        state.to_visit.put(Url(u))

    pages_processed = 0
    while not state.to_visit.empty() and pages_processed < max_pages:
        item = state.to_visit.get()
        page_url = item.url
        if page_url in state.visited_pages:
            continue
        if not same_domain(page_url, domain):
            continue

        resp = request_url(session, page_url)
        if not resp:
            continue

        html = resp.text
        pages_processed += 1
        state.visited_pages.add(page_url)

        links, images = parse_links_and_images(resp.url, html)

        # Queue new links
        for link in links:
            # limit to same domain, avoid feeds/admin/preview/query-heavy
            if not same_domain(link, domain):
                continue
            if any(s in link for s in ["/wp-admin", "/feed", "preview=true"]):
                continue
            # Strip fragments
            parsed = urlparse.urlparse(link)
            link_norm = parsed._replace(fragment="").geturl()
            if link_norm not in state.visited_pages:
                state.to_visit.put(Url(link_norm))

        # Process images
        for img_url in images:
            # Prefer original full-size if possible
            hi_url = prefer_fullsize_url(img_url, session)
            # Avoid duplicates
            if hi_url in state.found_images:
                continue
            state.found_images.add(hi_url)

            saved = save_image(session, hi_url, out_dir, min_image_bytes)
            if saved:
                print(f"Saved: {saved}")
            time.sleep(SLEEP_BETWEEN_REQUESTS)

        time.sleep(SLEEP_BETWEEN_REQUESTS)


if __name__ == "__main__":
    # Allow overrides via CLI
    # Usage: python scrape_wp_images.py https://example.com/ https://example.com/blog/
    start = sys.argv[1:] if len(sys.argv) > 1 else START_URLS

    # Global state
    state = State()

    crawl_and_download(
        start_urls=start,
        allowed_domain=ALLOWED_DOMAIN,
        out_dir=OUTPUT_DIR,
        max_pages=MAX_PAGES,
        min_image_bytes=MIN_IMAGE_BYTES,
    )

    print(f"Pages visited: {len(state.visited_pages)}")
    print(f"Images discovered: {len(state.found_images)}")