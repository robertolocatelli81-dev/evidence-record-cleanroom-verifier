#!/usr/bin/env python3
"""fetch_pr2853.py — status and authorship of the source cited as «S:x402ext» (compliance_fields.md @b8a81c0):
is it on x402-foundation/x402 main? which PR, state, author, dates? Raw bytes saved under live/pr2853/.
Also: a THIRD Bitcoin explorer (blockchain.info) for blocks 958163 / 964428. Read-only GETs."""
import datetime, hashlib, json, os, urllib.request
HERE = os.path.dirname(os.path.abspath(__file__)); OUT = os.path.join(HERE, "live", "pr2853"); os.makedirs(OUT, exist_ok=True)
UA = {"User-Agent": "tersign-vector-audit/1.0 (read-only)", "Accept": "application/vnd.github+json"}
print("run_at:", datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"))
def get(name, url):
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=40) as r:
            body, st = r.read(), r.status
    except urllib.error.HTTPError as e:
        body, st = e.read(), e.code
    open(os.path.join(OUT, name), "wb").write(body)
    print(f"{st} {len(body):>7}B sha256={hashlib.sha256(body).hexdigest()[:16]}… {name} <- {url}")
    return st, body
R = "https://api.github.com/repos/x402-foundation/x402"
st, b = get("contents_specs_extensions_main.json", f"{R}/contents/specs/extensions?ref=main")
names = [e["name"] for e in json.loads(b)] if st == 200 else []
print("  specs/extensions on main:", names, "| compliance_fields.md present:", "compliance_fields.md" in names)
st, b = get("commits_on_path_main.json", f"{R}/commits?path=specs/extensions/compliance_fields.md&sha=main")
print("  commits touching the path on main:", len(json.loads(b)) if st == 200 else st)
st, b = get("pull_2853.json", f"{R}/pulls/2853")
if st == 200:
    p = json.loads(b)
    print("  PR #2853:", {"state": p["state"], "merged": p.get("merged"), "mergeable_state": p.get("mergeable_state"), "user": p["user"]["login"],
                          "head_sha": p["head"]["sha"], "base": p["base"]["ref"], "created_at": p["created_at"], "updated_at": p["updated_at"],
                          "commits": p.get("commits"), "title": p["title"][:80]})
st, b = get("commit_b8a81c0_pulls.json", f"{R}/commits/b8a81c0/pulls")
if st == 200:
    print("  PRs containing b8a81c0:", [(x["number"], x["state"], x["user"]["login"]) for x in json.loads(b)])
st, b = get("commit_b8a81c0.json", f"{R}/commits/b8a81c0")
if st == 200:
    c = json.loads(b)
    print("  commit b8a81c0:", c["sha"][:12], c["commit"]["author"]["date"], (c.get("author") or {}).get("login"))
# third explorer
for h, hid in (("958163", "000000000000000000000b448a230fbfe54a053e08048df6ec33116f0ef11632"), ("964428", "00000000000000000000c59a40677dd1b45c2ba881a1bfc15ad6876158dff4d7")):
    st, b = get(f"blockchain_info_rawblock_{h}.json", f"https://blockchain.info/rawblock/{hid}")
    if st == 200:
        j = json.loads(b)
        m = json.load(open(os.path.join(HERE, "live", f"btc_mempool_block_{h}.json")))
        print(f"  block {h} blockchain.info: height={j.get('height')} mrkl_root={j.get('mrkl_root')} == mempool {m['merkle_root']} -> {j.get('mrkl_root') == m['merkle_root']}; hash match {j.get('hash') == m['id']}")
