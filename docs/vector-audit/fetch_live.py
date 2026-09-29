#!/usr/bin/env python3
"""fetch_live.py — Q3: fetch the PUBLIC endpoints named in the provenance blocks of p1, p5, p27 and the
Bitcoin block headers named there, saving RAW bytes + sha256 under live/. Read-only GETs, no contact.
Run: python3 fetch_live.py   (writes live/<name> and live/FETCH_MANIFEST.json)"""
import datetime, hashlib, json, os, ssl, sys, urllib.request, urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "live")
os.makedirs(OUT, exist_ok=True)
UA = "tersign-vector-audit/1.0 (read-only provenance check; python-urllib)"
G = "0xe5874f1ffe87f0a6dd9eb157730f67b86ee4538b125fe30fcc4e165213dd3fc4"   # p1 genesis digest
P5_SUBJ = "0xb2c5d2bd28ff65e13c1549a718a4c447916d5277ce046b2061ed63749ff287d9"
P27_HEAD = "0x339800528596c7d53d32571ad999695aef6dfc8fc86dcc4fb827bb6080493961"
P27_CD = "0xcbbef04598368ed02ae67fc0c8ffade6753628d0b8faf4e9211c9dd49a2dbe7b"

TARGETS = [
    ("p1_genesis.json", "https://tersign.ai/v1/genesis"),
    ("p1_verify.json", f"https://tersign.ai/v1/receipts/{G}/verify"),
    ("p5_anchors.json", "https://tersign.ai/v1/anchors"),
    ("p5_proof.ots", f"https://tersign.ai/v1/anchors/ledger:{P5_SUBJ}/proof.ots"),
    ("p27_head_verify.json", f"https://tersign.ai/v1/receipts/{P27_HEAD}/verify"),
    ("p27_anchor.json", f"https://tersign.ai/v1/anchors/seller:{P27_CD}"),
    ("p27_proof.ots", f"https://tersign.ai/v1/anchors/seller:{P27_CD}/proof.ots"),
    ("btc_mempool_height_958163.txt", "https://mempool.space/api/block-height/958163"),
    ("btc_mempool_height_964428.txt", "https://mempool.space/api/block-height/964428"),
    ("btc_blockstream_height_958163.txt", "https://blockstream.info/api/block-height/958163"),
    ("btc_blockstream_height_964428.txt", "https://blockstream.info/api/block-height/964428"),
    ("gh_0rkz_repo.json", "https://api.github.com/repos/0rkz/foreseal-x402-conformance"),
]

manifest = {"fetched_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
            "python": sys.version.split()[0], "items": []}


def get(url, timeout=40):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()
    except Exception as e:  # network / TLS / timeout
        return None, {}, repr(e).encode()


def save(name, url):
    status, hdrs, body = get(url)
    path = os.path.join(OUT, name)
    with open(path, "wb") as fh:
        fh.write(body)
    item = {"name": name, "url": url, "status": status, "bytes": len(body),
            "sha256": hashlib.sha256(body).hexdigest(),
            "content_type": hdrs.get("Content-Type"), "date": hdrs.get("Date")}
    manifest["items"].append(item)
    print(f"{str(status):>5} {len(body):>8}B sha256={item['sha256'][:16]}… {name}  <- {url}")
    return status, body


results = {}
for name, url in TARGETS:
    results[name] = save(name, url)

# Bitcoin block headers by hash (two explorers), if the heights resolved.
for h in ("958163", "964428"):
    for src, base in (("mempool", "https://mempool.space/api/block/"), ("blockstream", "https://blockstream.info/api/block/")):
        st, body = results.get(f"btc_{src}_height_{h}.txt", (None, b""))
        if st == 200 and len(body) == 64:
            save(f"btc_{src}_block_{h}.json", base + body.decode())

# p27: walk the chain backwards from the head through /verify, following prevDigest 12 more times.
st, body = results["p27_head_verify.json"]
walk = []
if st == 200:
    cur = P27_HEAD
    for step in range(13):
        if step == 0:
            data = body
        else:
            st2, data = save(f"p27_walk_{step:02d}_{cur[:10]}.json", f"https://tersign.ai/v1/receipts/{cur}/verify")
            if st2 != 200:
                walk.append({"step": step, "digest": cur, "status": st2}); break
        try:
            j = json.loads(data.decode("utf-8"))
        except Exception as e:
            walk.append({"step": step, "digest": cur, "error": repr(e)}); break
        # find the predecessor pointer generically (key containing 'prev', case-insensitive) anywhere in the object
        def find_prev(o, path=""):
            if isinstance(o, dict):
                for k, v in o.items():
                    if "prev" in k.lower() and (v is None or isinstance(v, str)):
                        return k, v, path + "/" + k
                    r = find_prev(v, path + "/" + k)
                    if r:
                        return r
            elif isinstance(o, list):
                for i, v in enumerate(o):
                    r = find_prev(v, f"{path}[{i}]")
                    if r:
                        return r
            return None
        r = find_prev(j)
        walk.append({"step": step, "digest": cur, "top_keys": sorted(j.keys()) if isinstance(j, dict) else None,
                     "prev_key": r[2] if r else None, "prev": r[1] if r else None})
        if not r or r[1] is None:
            break
        cur = r[1]
manifest["p27_walk"] = walk
with open(os.path.join(OUT, "FETCH_MANIFEST.json"), "w") as fh:
    json.dump(manifest, fh, indent=1)
print("walk steps:", len(walk))
for w in walk:
    print("  ", w)
