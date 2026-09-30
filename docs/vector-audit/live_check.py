#!/usr/bin/env python3
"""live_check.py — Q3: are the live-ledger vectors (p1, p5, p27; p4/n1/n3/n5 derived) what they declare?
Compares the RAW bytes fetched by fetch_live.py (live/) with the vectors, recomputes every digest with the
clean-room primitives (read-only import), and RECOVERS the secp256k1 counter-signatures (pure Python
ecrecover written here) to check they come from the declared ledger signer.
Writes live_check.json + prints a headed log."""
import datetime, hashlib, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
CR = os.path.abspath(os.path.join(HERE, "..", ".."))          # repository root
LIVE = os.path.join(HERE, "live")
sys.path.insert(0, CR)
import verify_tersign as V  # noqa: E402

# ─── secp256k1 ecrecover (pure Python, written 2026-09-29 for this audit) ───
P = 2 ** 256 - 2 ** 32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    if a == b:
        lam = (3 * a[0] * a[0]) * pow(2 * a[1], -1, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], -1, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return (x, (lam * (a[0] - x) - a[1]) % P)


def _mul(k, pt):
    r = None
    while k:
        if k & 1:
            r = _add(r, pt)
        pt = _add(pt, pt)
        k >>= 1
    return r


def ecrecover(h32: bytes, sig: bytes):
    # 2026-09-30: CANONICAL form enforced (EIP-2 low-s, v in {27, 28}, 65 bytes, r/s in range). Before this, a
    # high-s malleation of a published signature (s' = n - s, v flipped) recovered the same signer and passed —
    # the point raised on tersignhq/evidence-record-conformance PR #11 (vector cn3), measured here on p1.
    if len(sig) != 65:
        raise ValueError(f"signature is {len(sig)} bytes, not 65")
    r, s, v = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:64], "big"), sig[64]
    if v not in (27, 28):
        raise ValueError(f"v = {v}, not in {{27, 28}}")
    if not (1 <= r < N and 1 <= s <= N // 2):
        raise ValueError("r out of range or s not low-s (EIP-2)")
    rec = v - 27
    x = r + (rec // 2) * N
    y = pow((x ** 3 + 7) % P, (P + 1) // 4, P)
    if y % 2 != rec % 2:
        y = P - y
    R = (x, y)
    e = int.from_bytes(h32, "big")
    Q = _mul(pow(r, -1, N), _add(_mul(s, R), _mul((-e) % N, G)))
    pub = Q[0].to_bytes(32, "big") + Q[1].to_bytes(32, "big")
    return "0x" + V.keccak256_pure(pub)[12:].hex()


def personal_hash(msg: bytes) -> bytes:
    return V.keccak256_pure(b"\x19Ethereum Signed Message:\n" + str(len(msg)).encode() + msg)


def recover_variants(link: bytes, sig_hex: str):
    """Try the plausible personal_sign message encodings of a 32-byte digest; return {variant: address}."""
    sig = bytes.fromhex(sig_hex[2:])
    return {"raw32": ecrecover(personal_hash(link), sig),
            "hex0x": ecrecover(personal_hash(("0x" + link.hex()).encode()), sig),
            "hex": ecrecover(personal_hash(link.hex().encode()), sig)}


# ─── positive control for ecrecover: sign with a known key and recover ───
def _sign_control():
    k = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF
    pub = _mul(k, G)
    addr = "0x" + V.keccak256_pure(pub[0].to_bytes(32, "big") + pub[1].to_bytes(32, "big"))[12:].hex()
    h = personal_hash(b"control")
    e = int.from_bytes(h, "big")
    kk = 0x9E3779B97F4A7C15F39CC0605CEDC8341082276BF3A27251F86C6E9B5D4C3B2A  # fixed nonce (test only)
    Rp = _mul(kk, G)
    r = Rp[0] % N
    s = pow(kk, -1, N) * (e + r * k) % N
    v = 27 + (Rp[1] % 2)
    if s > N // 2:
        s = N - s
        v ^= 1
    sig = r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([v])
    return addr, ecrecover(h, sig)


def rd(name):
    return open(os.path.join(LIVE, name), "rb").read()


def vec(name):
    with open(os.path.join(CR, "spec", "vectors", name), encoding="utf-8") as fh:
        return V.load_json(fh.read())


out = {"run_at": datetime.datetime.now(datetime.timezone.utc).astimezone().isoformat(timespec="seconds"), "checks": []}


def check(label, cond, extra=""):
    out["checks"].append({"label": label, "pass": bool(cond), "extra": extra})
    print(f"[{'PASS' if cond else 'FAIL'}] {label} {extra}")


ctrl_addr, ctrl_rec = _sign_control()
check("ecrecover positive control (own key: sign -> recover)", ctrl_addr == ctrl_rec, f"{ctrl_addr} == {ctrl_rec}")

# ── p1: genesis receipt ──
p1 = vec("p1-live-genesis-receipt.json")
g = json.loads(rd("p1_genesis.json").decode())
check("p1 live /v1/genesis artifact == vector payload (deep equal)", g["artifact"] == p1["input"]["payload"])
check("p1 live canonical bytes == vector canonical bytes", V.jcs(g["artifact"]) == V.jcs(p1["input"]["payload"]))
gd = "0x" + V.keccak256_pure(V.jcs(g["artifact"])).hex()
check("p1 keccak256(canonical(live artifact)) == expected_digest", gd == p1["input"]["expected_digest"], gd)
check("p1 live artifactDigest field == expected_digest", g["artifactDigest"] == p1["input"]["expected_digest"])
check("p1 live countersignature == provenance.countersignature", g["countersignature"] == p1["provenance"]["countersignature"])
check("p1 live ledgerSigner == provenance.ledger_signer", g["ledgerSigner"] == p1["provenance"]["ledger_signer"])
check("p1 live seq==1 and prevDigest null", g["seq"] == 1 and g["prevDigest"] is None)
link1 = V.chain_link(bytes.fromhex(gd[2:]), None, 1)
p4 = vec("p4-chain-link-genesis.json")
check("p4 expected_link == chain_link(genesis, null, 1) recomputed", "0x" + link1.hex() == p4["input"]["expected_link"])
rv = recover_variants(link1, g["countersignature"])
out["p1_recover"] = rv
_sig1 = bytes.fromhex(g["countersignature"][2:])
_r1, _s1, _v1 = int.from_bytes(_sig1[:32], "big"), int.from_bytes(_sig1[32:64], "big"), _sig1[64]
_hs = _r1.to_bytes(32, "big") + (N - _s1).to_bytes(32, "big") + bytes([55 - _v1])
try:
    ecrecover(personal_hash(link1), _hs)
    _hs_refused = False
except ValueError:
    _hs_refused = True
check("p1 high-s twin (s'=n-s, v flipped) REFUSED by the canonical ecrecover (PR #11 cn3)", _hs_refused, "EIP-2 low-s")
hit = [k for k, a in rv.items() if a.lower() == g["ledgerSigner"].lower()]
check("p1 countersignature recovers to ledgerSigner (personal_sign over the chain-link digest)", bool(hit), f"variant={hit} recovered={rv}")
v1 = json.loads(rd("p1_verify.json").decode())
check("p1 /verify: found, chainOk, seq 1, anchor confirmed", v1.get("found") and v1.get("chainOk") and v1.get("seq") == 1 and v1["anchor"]["status"] == "confirmed",
      f"genesis artifact anchor block={v1['anchor'].get('bitcoinBlockHeight')}")

# ── p5: bitcoin anchor ──
p5 = vec("p5-live-bitcoin-anchor.json")
anchors = json.loads(rd("p5_anchors.json").decode())["anchors"]
subj, anch = p5["input"]["subject_digest"], p5["input"]["anchored_digest"]
row = [a for a in anchors if a.get("subjectDigest") == subj]
check("p5 subject_digest listed in live /v1/anchors", len(row) == 1)
if row:
    a = row[0]
    out["p5_anchor_row"] = a
    check("p5 live anchoredDigest == vector anchored_digest", a.get("anchoredDigest") == anch)
    check("p5 live bitcoinBlockHeight == 958163 (provenance)", a.get("bitcoinBlockHeight") == 958163, str(a.get("bitcoinBlockHeight")))
    check("p5 live status confirmed", a.get("status") == "confirmed")
    check("p5 anchored == sha256(subject) recomputed", hashlib.sha256(bytes.fromhex(subj[2:])).hexdigest() == anch[2:])
    hint = a.get("subjectSchema"), a.get("prefixCommitting"), a.get("coversSeqThrough"), a.get("id"), a.get("scope")
    out["p5_anchor_meta"] = hint
    print("      p5 anchor meta:", hint)
n5 = vec("n5-truncated-anchor.json")
check("n5 anchored_digest == p5's anchored digest (derived as declared)", n5["input"]["anchored_digest"] == anch)
check("n5 subject is p6's seq-1 artifact (synthetic subject, as declared 'does not bind')",
      n5["input"]["subject_digest"] == vec("p6-chain-set-complete.json")["input"]["records"][0]["artifact_digest"])

# ── p27: 13-record genesis chain + commitment ──
p27 = vec("p27-live-chain-commitment-genesis-chain.json")
recs = p27["input"]["records"]
head = p27["input"]["head"]["digest"]
walk = [(head, json.loads(rd("p27_head_verify.json").decode()))]
cur = walk[0][1]["prevDigest"]
import glob
for f in sorted(glob.glob(os.path.join(LIVE, "p27_walk_*.json"))):
    j = json.loads(open(f, "rb").read().decode())
    digest = "0x" + os.path.basename(f).split("_0x")[1].split(".json")[0]
    # the file name holds only a 8-hex prefix; recover the full digest from the previous step's prevDigest
    walk.append((cur, j))
    cur = j["prevDigest"]
check("p27 walk length == 13 and ends at null prevDigest", len(walk) == 13 and walk[-1][1]["prevDigest"] is None, str(len(walk)))
live_by_seq = {j["seq"]: (d, j["prevDigest"], j["countersignature"], j["ledgerSigner"]) for d, j in walk}
mism = []
for r in recs:
    d, pd, _, _ = live_by_seq.get(r["seq"], (None, None, None, None))
    if d != r["artifact_digest"] or pd != r["prev_digest"]:
        mism.append(r["seq"])
check("p27 all 13 (seq, artifact_digest, prev_digest) == live walk", not mism, f"mismatches={mism}")
# fold the accumulator from the LIVE walk, compare with live commitment.acc and vector head.acc
acc = V.keccak256_pure(V.ACC_SEED)
prev = None
sig_ok, sig_var = [], {}
for s in range(1, 14):
    d, pd, sig, signer = live_by_seq[s]
    art = bytes.fromhex(d[2:])
    link = V.chain_link(art, prev, s)
    acc = V.keccak256_pure(acc + link)
    rv = recover_variants(link, sig)
    hits = [k for k, a in rv.items() if a.lower() == signer.lower()]
    sig_ok.append(bool(hits))
    sig_var[s] = hits
    prev = art
live_commit = walk[0][1]["commitment"]
check("p27 accumulator folded over the LIVE walk == live commitment.acc", "0x" + acc.hex() == live_commit["acc"])
check("p27 vector head.acc == live commitment.acc", p27["input"]["head"]["acc"] == live_commit["acc"])
check("p27 13/13 countersignatures recover to ledgerSigner 0x9d38…", all(sig_ok), f"variants={sig_var}")
an = json.loads(rd("p27_anchor.json").decode())
out["p27_anchor"] = an
check("p27 live anchor subjectArtifact == vector provenance.commitment", an["subjectArtifact"] == p27["provenance"]["commitment"])
cd = V.keccak256_pure(V.jcs(an["subjectArtifact"]))
check("p27 keccak256(JCS(subjectArtifact)) == live subjectDigest == vector commitment_digest",
      "0x" + cd.hex() == an["subjectDigest"] == p27["provenance"]["commitment_digest"])
check("p27 sha256(subjectDigest) == live anchoredDigest == vector anchored_digest",
      hashlib.sha256(cd).hexdigest() == an["anchoredDigest"][2:] == p27["provenance"]["anchored_digest"][2:])
check("p27 live bitcoinBlockHeight == 964428 (manifest/provenance)", an["bitcoinBlockHeight"] == 964428, str(an["bitcoinBlockHeight"]))
check("p27 live anchor status confirmed, prefixCommitting, coversSeqThrough 13",
      an["status"] == "confirmed" and an.get("prefixCommitting") is True and an.get("coversSeqThrough") == 13)
# merkle path -> batchRoot. probe_merkle.py (2026-09-29) measured: the LEAF is the anchoredDigest
# (sha256(subjectDigest)), nodes are sha256(left||right) in the given order; batchRoot is also an
# intermediate message of the OTS proof ops. Keep the keccak variant as a negative control.
node = hashlib.sha256(cd).digest()
node_k = cd
for step in an["merklePath"]:
    h = bytes.fromhex(step["hash"][2:])
    pair = (h + node) if step["side"] == "L" else (node + h)
    pair_k = (h + node_k) if step["side"] == "L" else (node_k + h)
    node = hashlib.sha256(pair).digest()
    node_k = V.keccak256_pure(pair_k)
mp = {"sha256": "0x" + node.hex(), "keccak256": "0x" + node_k.hex(), "batchRoot": an["batchRoot"]}
out["p27_merkle"] = mp
check("p27 merklePath replays anchoredDigest to batchRoot (sha256 nodes; keccak = negative control)", an["batchRoot"] == mp["sha256"] and an["batchRoot"] != mp["keccak256"], str(mp))
# anchor ledgerSignature = personal_sign("tersign-anchor-v1:" + batchRoot)
sig = bytes.fromhex(an["ledgerSignature"][2:])
rec_addr = ecrecover(personal_hash(("tersign-anchor-v1:" + an["batchRoot"]).encode()), sig)
check("p27 anchor ledgerSignature recovers to ledgerSigner 0x9d38… (verifyHint encoding)", rec_addr.lower() == "0x9d38ba84730271eb27ac9bd4bd2620c08db4fda6", rec_addr)

# n1 / n3 derived from p1 as declared
n1 = vec("n1-value-drift.json")
d1 = dict(n1["input"]["payload"]["payload"]); d0 = dict(p1["input"]["payload"]["payload"])
check("n1 == p1 with issuedAt + 1 only", {k for k in d0 if d0[k] != d1[k]} == {"issuedAt"} and d1["issuedAt"] == d0["issuedAt"] + 1
      and n1["input"]["payload"]["signature"] == p1["input"]["payload"]["signature"] and n1["input"]["expected_digest"] == p1["input"]["expected_digest"])
n3 = vec("n3-chain-link-wrong-prev.json")
check("n3 == p4 with prev_digest := artifact (self-referential) only",
      n3["input"]["artifact_digest"] == p4["input"]["artifact_digest"] == n3["input"]["prev_digest"] and n3["input"]["expected_link"] == p4["input"]["expected_link"] and n3["input"]["seq"] == 1)

# block headers: two explorers agree
for h in ("958163", "964428"):
    a = json.loads(rd(f"btc_mempool_block_{h}.json").decode()); b = json.loads(rd(f"btc_blockstream_block_{h}.json").decode())
    check(f"block {h}: mempool.space and blockstream.info agree on id, merkle_root, timestamp", a["id"] == b["id"] and a["merkle_root"] == b["merkle_root"] and a["timestamp"] == b["timestamp"],
          f"merkle_root={a['merkle_root']} time={datetime.datetime.fromtimestamp(a['timestamp'], datetime.timezone.utc).isoformat()}")
    out[f"block_{h}"] = a

out["all_pass"] = all(c["pass"] for c in out["checks"])
with open(os.path.join(HERE, "live_check.json"), "w", encoding="utf-8") as fh:
    json.dump(out, fh, indent=1)
print("ALL PASS" if out["all_pass"] else "SOME FAIL")
