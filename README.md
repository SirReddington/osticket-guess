# osticket-guess

A Python tool for enumerating osTicket attachment paths when the **"Attachments on the Filesystem"** plugin is in use. Concurrent, retry-aware, proxy-friendly. Python port + enhancement of the [bash original by @Und3r-r00t](https://github.com/Und3r-r00t).

For use in CTFs (OSCP Proving Grounds, HackTheBox, TryHackMe) and authorized penetration testing only.

---

## Table of Contents

- [Background: how osTicket stores filesystem attachments](#background-how-osticket-stores-filesystem-attachments)
- [What this tool does](#what-this-tool-does)
- [Installation](#installation)
- [Quick start](#quick-start)
- [All options](#all-options)
- [Examples](#examples)
- [Troubleshooting](#troubleshooting)
- [Ethical use](#ethical-use)
- [Credits](#credits)

---

## Background: how osTicket stores filesystem attachments

When osTicket is configured with the **Filesystem Storage** plugin (instead of the default database storage), uploaded attachments are written to disk under a directory tree keyed by a content-derived signature. Looking at the plugin source:

```php
$signature = preg_replace('/=*$/', '',
    str_replace(['+','/'], ['-','_'],
    base64_encode(sha1($content, true))));

$path = $this->root . '/' . $signature[0] . '/' . $signature;
```

In plain English:

1. The file's raw content is SHA1-hashed.
2. The 20-byte hash is base64-encoded.
3. `+` becomes `-`, `/` becomes `_`, `=` padding is stripped (RFC 4648 base64url).
4. The result is the **storage signature**, e.g. `nwHkb4hiFB2oNZ6SCaoqFcTUPlI`.
5. The file lives at `<attachments-root>/<signature[0]>/<signature>` — first char of the signature is the subdirectory, full signature is the filename. No extension.

osTicket then generates a download URL of the form:

```
/file.php?key=<random-prefix><signature>&expires=<ts>&signature=<hmac>&id=<n>
```

The `key=` parameter combines a small per-file prefix with the storage signature. Crucially, the URL handler often normalizes this value to lowercase, even though the on-disk filename preserves the original mixed case. If you can compute the signature yourself (because you uploaded the file), you know the *correct* case for that half — but you still don't know the case of the random prefix. That's what this tool brute-forces.

Reference: [osTicket: Attachments on the Filesystem docs](https://docs.osticket.com/en/latest/Plugins/Attachments%20on%20the%20Filesystem.html)

## What this tool does

Given the **target** osTicket host, the **URL key** (or signature you derived yourself), and an optional **file key** suffix, the tool:

1. Takes the first N characters of the URL key (default 5).
2. Generates every upper/lower case permutation of those N characters. Non-alphabetic characters (digits, dashes, underscores) pass through unchanged.
3. For each permutation, tries every case variant of the first M characters (default 1) as the on-disk subdirectory.
4. Concurrently HTTP-probes each resulting URL using a configurable number of worker threads.
5. Reports any URL that returns a status code in the match-list (default `200`) along with the response size, so a real hit is easy to spot.

The full URL probed has this shape:

```
{target}/attachments/{permuted-dir-prefix}/{permuted-key-prefix}{rest-of-key-unchanged}{file-key}
```

## Installation

```bash
git clone https://github.com/SirReddington/osticket-guess.git
cd osticket-guess
pip install -r requirements.txt
chmod +x osticket_guess.py
```

Python 3.10+ is recommended. The only third-party dependency is [`requests`](https://pypi.org/project/requests/).

## Quick start

```bash
python3 osticket_guess.py \
  -t http://10.10.10.10 \
  -u f56winwHkb4hiFB2oNZ6SCaoqFcTUPlI \
  -f "" \
  -T 40 --head
```

Or run with no arguments and the tool will prompt you interactively, matching the behaviour of the original bash script.

## All options

### Required inputs

| Flag | Long form | Description |
|---|---|---|
| `-t` | `--target` | Target host or full base URL. Accepts `example.com`, `http://example.com`, `https://example.com:8080/osticket`. The scheme defaults to `http://` if you omit it. |
| `-u` | `--url-key` | The key/signature you want to brute-force. Pull this from the download URL osTicket gave you (the `key=` parameter), or compute it locally from the file you uploaded. |
| `-f` | `--file-key` | Trailing suffix appended after the signature. For the modern FS plugin this is usually empty (`""`). Older versions or custom plugins may append `.tmp`, `.pdf`, or similar. Pass `-f ""` explicitly to skip the interactive prompt. |

### Permutation control

| Flag | Long form | Default | When to change |
|---|---|---|---|
| `-n` | `--prefix-len` | `5` | Number of leading characters to case-permute. Matches the bash original. Increase if you suspect more than the first 5 chars get case-mangled; decrease if you already know some leading chars are fixed. Each extra alphabetic character doubles the number of candidate URLs. |
| `-d` | `--dir-depth` | `1` | How many characters of the signature form the subdirectory. The standard FS plugin uses 1; some installs are configured with 2-character subdirs for finer fanout. If `-d 1` produces no hits, retry with `-d 2`. |

### HTTP behaviour

| Flag | Long form | Default | Notes |
|---|---|---|---|
| `-T` | `--threads` | `20` | Concurrent HTTP workers. Bump to 40–80 on a fast local lab box, drop to 5–10 against rate-limited targets. |
| | `--timeout` | `8.0` | Per-request timeout in seconds. Increase on slow targets, decrease for quick "is it there" sweeps. |
| | `--retries` | `2` | Automatic retries on transient 5xx responses, with exponential backoff. Set to `0` to disable. |
| | `--proxy` | none | Route every request through an HTTP proxy. Typical use: `--proxy http://127.0.0.1:8080` to send everything through Burp Suite for inspection/replay. |
| | `--user-agent` | `osticket-guess/1.0 (+research)` | Custom UA string. Useful when the target filters scanners by UA, or when your engagement rules require a specific identifier. |
| `-k` | `--insecure` | off | Skip TLS certificate verification. Needed for self-signed lab boxes. |
| | `--head` | off (GET) | Use HEAD requests instead of GET. Faster and saves bandwidth, but some servers return different status codes for HEAD vs GET on the same resource — fall back to GET if `--head` returns surprising results. |

### Result triage

| Flag | Long form | Default | Notes |
|---|---|---|---|
| `-mc` | `--match-codes` | `200` | Comma-separated list of status codes to treat as hits. Set to `0` to disable filtering and see every response. Example: `-mc 200,206,302`. |
| `-fc` | `--filter-codes` | none | Comma-separated list of status codes to *suppress* from output. Useful when the target returns an unusual code (e.g. `403`) for every non-existent file and you only want to see breaks from that pattern. |
| | `--min-size` | none | Minimum response size (bytes) for a result to count as a hit. Useful when the target returns 200 with a "not found" body — filter on size larger than that body. |
| `-o` | `--output` | none | Write all hits to a TSV file. Columns: `status<TAB>length<TAB>url`. |
| `-v` | `--verbose` | off | Print every probe (including misses), not just hits. Helpful for sanity-checking what's actually being requested. |

### Utility

| Flag | Long form | Notes |
|---|---|---|
| | `--dry-run` | Print every candidate URL the tool would request, without making any HTTP calls. Use this before a real run to confirm the URL shape matches what you expect. Pipe to `wc -l` to count candidates. |
| `-h` | `--help` | Show the help text. |

## Examples

### 1. The typical osTicket box

You uploaded `reverse.php`, captured the download URL `http://10.10.10.10/file.php?key=f56winwhkb4hifb2onz6scaoqfctupli&...`, and you've computed the correctly-cased signature locally:

```php
php > $sig = str_replace(['+','/','='], ['-','_',''], base64_encode(sha1_file('reverse.php', true)));
php > echo $sig;
nwHkb4hiFB2oNZ6SCaoqFcTUPlI
```

Combine the URL prefix with your correctly-cased signature and let the tool flip the case on the first 5 chars:

```bash
python3 osticket_guess.py \
  -t http://10.10.10.10 \
  -u f56winwHkb4hiFB2oNZ6SCaoqFcTUPlI \
  -f "" \
  -T 40 --head
```

### 2. Two-char subdirectory layout

If example 1 finds nothing, the FS plugin is probably configured for two-char subdirs. Same command, plus `-d 2`:

```bash
python3 osticket_guess.py \
  -t http://10.10.10.10 \
  -u f56winwHkb4hiFB2oNZ6SCaoqFcTUPlI \
  -f "" \
  -T 40 --head -d 2
```

### 3. Routing through Burp Suite

```bash
python3 osticket_guess.py \
  -t https://target.tld \
  -u <key> -f "" \
  --proxy http://127.0.0.1:8080 -k
```

`-k` is required because Burp re-signs TLS connections with a per-installation CA.

### 4. Dry-run to preview what would be hit

```bash
python3 osticket_guess.py -t http://target -u abCdE -f .pdf --dry-run | head
python3 osticket_guess.py -t http://target -u abCdE -f .pdf --dry-run | wc -l
```

### 5. Wide net: see every response code

```bash
python3 osticket_guess.py -t http://target -u <key> -f "" -mc 0 -v
```

### 6. Save hits to a TSV

```bash
python3 osticket_guess.py -t http://target -u <key> -f "" -o hits.tsv
cat hits.tsv
```

### 7. Aggressive sweep with retries disabled

```bash
python3 osticket_guess.py -t http://target -u <key> -f "" \
  -T 80 --timeout 3 --retries 0 --head
```

## Troubleshooting

**"requests is required"** — install dependencies: `pip install -r requirements.txt`.

**Zero hits with `-d 1`** — try `-d 2`. Try increasing `-n` (e.g. `-n 6` or `-n 7`) in case more than the first 5 chars are case-mangled.

**Every response is 200 but the file isn't actually there** — the target probably returns a generic 200 page for everything. Use `-v` to see one full response, find the page size, then filter with `--min-size <bigger-than-that>` or use `-mc 206` if the real file would be a partial content response.

**`--head` returns 404 but `GET` would return 200** — some app servers don't handle HEAD on PHP-routed URLs cleanly. Drop `--head`.

**You found the file but the response is the raw PHP source as text** — the path exists but Apache/nginx isn't routing it to PHP. The file is being served as a static asset. That's information disclosure, not RCE — you'll need a different execution vector.

**The hash you computed locally doesn't match the lowercase part of the URL key** — sanity-check with a CLI one-liner:

```bash
sha1sum yourfile | cut -d' ' -f1 | xxd -r -p | base64 | tr '+/' '-_' | tr -d '='
```

If that doesn't match what the URL has (after lowercasing both), you're probably hashing a different version of the file than the one that actually got uploaded — for example, your editor may have re-saved it with different line endings.

## Ethical use

This tool is for environments where you have **explicit authorization** to test. Examples:

- OSCP Proving Grounds, HackTheBox, TryHackMe, VulnHub boxes you've paid for or that are publicly licensed for offensive testing
- Engagements with a signed rules-of-engagement document covering the target host
- Your own osTicket instance

Using this against systems you don't own or aren't authorized to test is illegal in most jurisdictions and won't be supported by the author.

## Credits

- **Original bash script:** [@Und3r-r00t](https://github.com/Und3r-r00t)
- **osTicket project:** https://osticket.com
- **Storage plugin docs:** https://docs.osticket.com/en/latest/Plugins/Attachments%20on%20the%20Filesystem.html

## License

MIT — see `LICENSE`.
