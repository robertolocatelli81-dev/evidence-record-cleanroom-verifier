#!/usr/bin/env python3
"""fetch_specs.py — Q1 grounding on RAW bytes (not summaries): the public specifications the manifest /
vectors cite. Saves under live/specs/ with sha256 and prints the sentences matching the audit's key terms."""
import hashlib, os, re, urllib.request
HERE = os.path.dirname(os.path.abspath(__file__)); OUT = os.path.join(HERE, "live", "specs"); os.makedirs(OUT, exist_ok=True)
UA = {"User-Agent": "tersign-vector-audit/1.0 (read-only)"}
SRC = {
    "x402_compliance_fields_b8a81c0.md": "https://cdn.jsdelivr.net/gh/x402-foundation/x402@b8a81c0/specs/extensions/compliance_fields.md",
    "rfc8785.txt": "https://www.rfc-editor.org/rfc/rfc8785.txt",
    "rfc7493.txt": "https://www.rfc-editor.org/rfc/rfc7493.txt",
}
TERMS = {
    "x402_compliance_fields_b8a81c0.md": ["later phase", "economic phase", "only by parties", "same party", "trailing punctuation", "letter case",
                                          "does not parse", "non-integer", "MUST reject", "no record was omitted", "inclusion proof", "cosign",
                                          "declared", "commit", "reaches", "unknown", "cannot interpret", "fail", "claim"],
    "rfc8785.txt": ["UTF-16", "code units", "NaN", "Infinity"],
    "rfc7493.txt": ["2**53", "duplicate names", "Surrogates"],
}
for name, url in SRC.items():
    raw = urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=60).read()
    open(os.path.join(OUT, name), "wb").write(raw)
    print(f"\n===== {name}  {len(raw)} B  sha256={hashlib.sha256(raw).hexdigest()}  <- {url}")
    text = raw.decode("utf-8", "replace")
    # split into sentences / lines and print those containing a term (with the nearest preceding heading for the md)
    heading = ""
    for i, line in enumerate(text.splitlines()):
        if name.endswith(".md") and line.startswith("#"):
            heading = line.strip()
        for t in TERMS[name]:
            if t.lower() in line.lower():
                print(f"[{name.split('.')[0]} L{i+1}] {heading[:60]} :: {line.strip()[:400]}")
                break
