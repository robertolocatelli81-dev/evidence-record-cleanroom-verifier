#!/usr/bin/env python3
"""probe_merkle.py — the p27 anchor row's `merklePath` (subjectDigest -> batchRoot) is NOT a manifest claim;
probe which construction reproduces batchRoot, and whether batchRoot appears among the intermediate
messages of the OTS proof (i.e. the batch tree is embedded in the proof ops)."""
import hashlib, itertools, json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__)); LIVE = os.path.join(HERE, "live")
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "..")))   # repository root
import verify_tersign as V
import ots_check as O  # reuse the parser (importing runs its checks once; harmless, read-only)

an = json.load(open(os.path.join(LIVE, "p27_anchor.json")))
subj = bytes.fromhex(an["subjectDigest"][2:]); anch = bytes.fromhex(an["anchoredDigest"][2:]); root = an["batchRoot"][2:]
H = {"sha256": lambda b: hashlib.sha256(b).digest(), "dsha256": lambda b: hashlib.sha256(hashlib.sha256(b).digest()).digest(),
     "keccak": V.keccak256_pure, "sha3": lambda b: hashlib.sha3_256(b).digest()}
leaves = {"subject": subj, "anchored": anch, "sha256(anchored)": hashlib.sha256(anch).digest(), "keccak(subject)": V.keccak256_pure(subj)}
found = []
for (ln, leaf), (hn, h), order, tagged in itertools.product(leaves.items(), H.items(), ("given", "sorted", "swapped"), (False, True)):
    node = leaf
    for st in an["merklePath"]:
        sib = bytes.fromhex(st["hash"][2:])
        if order == "given":
            pair = sib + node if st["side"] == "L" else node + sib
        elif order == "swapped":
            pair = node + sib if st["side"] == "L" else sib + node
        else:
            pair = b"".join(sorted([sib, node]))
        node = h((b"\x01" + pair) if tagged else pair)
    if node.hex() == root:
        found.append((ln, hn, order, tagged))
print("merklePath constructions reproducing batchRoot:", found or "NONE")

# intermediate messages of the OTS proof (p27): does batchRoot appear?
b = open(os.path.join(LIVE, "p27_proof.ots"), "rb").read()
r = O.R(b); r.take(len(O.MAGIC)); r.varint(); op = r.byte(); msg = r.take(32)
seen = []
def walk(r, msg, depth):
    while True:
        tag = r.byte()
        if tag == 0xFF:
            walk(r, msg, depth + 1); continue
        if tag == 0x00:
            r.take(8); r.varbytes(); return
        if tag == 0xF0: msg = msg + r.varbytes(); nm = "append"
        elif tag == 0xF1: msg = r.varbytes() + msg; nm = "prepend"
        elif tag == 0xF2: msg = msg[::-1]; nm = "reverse"
        elif tag == 0xF3: msg = msg.hex().encode(); nm = "hexlify"
        else: nm, fn = O.HASH_OPS[tag]; msg = fn(msg)
        seen.append((depth, nm, msg.hex()[:64]))
walk(r, msg, 0)
hits = [s for s in seen if s[2] == root]
print("batchRoot among OTS intermediate messages:", hits or "NO")
print("first 12 ops:", seen[:12])
