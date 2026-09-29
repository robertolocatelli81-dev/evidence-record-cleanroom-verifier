#!/usr/bin/env python3
"""ots_check.py — minimal OpenTimestamps (.ots) parser written here (pip is blocked in this sandbox), to
verify p5's and p27's proofs offline against the Bitcoin block headers fetched from two public explorers.
Format (github.com/opentimestamps/python-opentimestamps, serialization): magic, varint version, file-hash op
+ digest, then a Timestamp = ops applied to the message, 0xff = fork, 0x00 = attestation (8-byte tag,
varbytes payload). Bitcoin attestation tag 0588960d73d71901, payload = varint block height; the message at
that point is the block's merkle root (internal byte order). A PASS means: the proof's file digest is the
anchored digest, the ops replay to the merkle root of the named block, and the block is the one declared.
Writes ots_check.json."""
import datetime, hashlib, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
LIVE = os.path.join(HERE, "live")
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "..")))   # repository root
import verify_tersign as V  # noqa: E402  (keccak256_pure only)

MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
TAG_BTC = bytes.fromhex("0588960d73d71901")
TAG_PENDING = bytes.fromhex("83dfe30d2ef90c8e")
TAG_LTC = bytes.fromhex("06869a0d73d71b45")
HASH_OPS = {0x02: ("sha1", lambda m: hashlib.sha1(m).digest()), 0x03: ("ripemd160", lambda m: hashlib.new("ripemd160", m).digest()),
            0x08: ("sha256", lambda m: hashlib.sha256(m).digest()), 0x67: ("keccak256", lambda m: V.keccak256_pure(m))}
HASH_LEN = {0x02: 20, 0x03: 20, 0x08: 32, 0x67: 32}


class R:
    def __init__(self, b):
        self.b, self.i = b, 0

    def byte(self):
        v = self.b[self.i]; self.i += 1; return v

    def take(self, n):
        v = self.b[self.i:self.i + n]; self.i += n; return v

    def varint(self):
        v, shift = 0, 0
        while True:
            c = self.byte()
            v |= (c & 0x7F) << shift
            if not c & 0x80:
                return v
            shift += 7

    def varbytes(self):
        return self.take(self.varint())


def parse_timestamp(r, msg, path, atts, depth=0):
    """Walk one timestamp branch; append (attestation_dict) to atts."""
    while True:
        tag = r.byte()
        if tag == 0xFF:  # fork: a full sub-timestamp follows for the SAME msg, then continue this branch
            parse_timestamp(r, msg, path + ["fork"], atts, depth + 1)
            continue
        if tag == 0x00:  # attestation
            t = r.take(8)
            payload = R(r.varbytes())
            if t == TAG_BTC:
                atts.append({"type": "bitcoin", "height": payload.varint(), "msg": msg.hex(), "path": path})
            elif t == TAG_LTC:
                atts.append({"type": "litecoin", "height": payload.varint(), "msg": msg.hex(), "path": path})
            elif t == TAG_PENDING:
                atts.append({"type": "pending", "uri": payload.varbytes().decode("utf-8", "replace"), "msg": msg.hex(), "path": path})
            else:
                atts.append({"type": "unknown:" + t.hex(), "msg": msg.hex(), "path": path})
            return
        if tag == 0xF0:
            msg = msg + r.varbytes(); path = path + ["append"]
        elif tag == 0xF1:
            msg = r.varbytes() + msg; path = path + ["prepend"]
        elif tag == 0xF2:
            msg = msg[::-1]; path = path + ["reverse"]
        elif tag == 0xF3:
            msg = msg.hex().encode(); path = path + ["hexlify"]
        elif tag in HASH_OPS:
            name, fn = HASH_OPS[tag]
            msg = fn(msg); path = path + [name]
        else:
            raise ValueError(f"unknown op tag 0x{tag:02x} at offset {r.i - 1}")


def parse_ots(b):
    r = R(b)
    if r.take(len(MAGIC)) != MAGIC:
        raise ValueError("bad magic")
    version = r.varint()
    op = r.byte()
    if op not in HASH_OPS:
        raise ValueError(f"unknown file hash op 0x{op:02x}")
    digest = r.take(HASH_LEN[op])
    atts = []
    parse_timestamp(r, digest, [], atts)
    return {"version": version, "file_hash_op": HASH_OPS[op][0], "file_digest": digest.hex(), "attestations": atts, "trailing_bytes": len(b) - r.i}


def rd(n):
    return open(os.path.join(LIVE, n), "rb").read()


out = {"run_at": datetime.datetime.now(datetime.timezone.utc).astimezone().isoformat(timespec="seconds"), "proofs": {}, "checks": []}


def check(label, cond, extra=""):
    out["checks"].append({"label": label, "pass": bool(cond), "extra": extra})
    print(f"[{'PASS' if cond else 'FAIL'}] {label} {extra}")


# positive control of the parser: a hand-built minimal proof (sha256 file op, one append, one bitcoin attestation)
def _control():
    d = hashlib.sha256(b"control").digest()
    body = MAGIC + b"\x01" + b"\x08" + d + b"\xf0" + b"\x02" + b"ab" + b"\x08" + b"\x00" + TAG_BTC + b"\x03" + bytes([0x80 | (958163 & 0x7F), 0x80 | ((958163 >> 7) & 0x7F), (958163 >> 14) & 0x7F])
    p = parse_ots(body)
    exp = hashlib.sha256(d + b"ab").hexdigest()
    return p["attestations"][0]["height"] == 958163 and p["attestations"][0]["msg"] == exp and p["file_digest"] == d.hex()


check("OTS parser positive control (hand-built proof replays to the expected message and height)", _control())

for name, anchored, height, label in (("p5_proof.ots", "cf48bed1712f5b7df2a309fb52cb2b3d51ab1a04730e3b115cd3db79c96c9b1a", 958163, "p5"),
                                      ("p27_proof.ots", "7c00ab806c6a9cc3fd654c0cbb107224ccff80642ea289f3c8f226b592647675", 964428, "p27")):
    b = rd(name)
    try:
        p = parse_ots(b)
    except Exception as e:
        out["proofs"][label] = {"error": repr(e), "sha256": hashlib.sha256(b).hexdigest()}
        check(f"{label} proof parses", False, repr(e)); continue
    p["sha256"] = hashlib.sha256(b).hexdigest(); p["bytes"] = len(b)
    out["proofs"][label] = p
    check(f"{label} proof parses ({len(b)} B, {len(p['attestations'])} attestation(s), trailing {p['trailing_bytes']} B)", p["trailing_bytes"] == 0)
    check(f"{label} proof file digest == anchoredDigest ({p['file_hash_op']})", p["file_digest"] == anchored, p["file_digest"])
    btc = [a for a in p["attestations"] if a["type"] == "bitcoin"]
    heights = sorted({a["height"] for a in btc})
    check(f"{label} proof carries a Bitcoin attestation at the declared height {height}", height in heights, f"heights={heights} pending={[a.get('uri') for a in p['attestations'] if a['type']=='pending']}")
    blk = json.loads(rd(f"btc_mempool_block_{height}.json").decode())
    blk2 = json.loads(rd(f"btc_blockstream_block_{height}.json").decode())
    for a in btc:
        if a["height"] == height:
            root_internal = a["msg"]
            root_display = bytes.fromhex(root_internal)[::-1].hex()
            check(f"{label} replayed message == merkle_root of block {height} (mempool.space)", root_display == blk["merkle_root"], f"replayed={root_display} explorer={blk['merkle_root']}")
            check(f"{label} same merkle_root at blockstream.info", root_display == blk2["merkle_root"])
            check(f"{label} block {height} hash agrees across explorers", blk["id"] == blk2["id"], blk["id"])
            out["proofs"][label]["block"] = {"height": height, "id": blk["id"], "merkle_root": blk["merkle_root"], "timestamp": blk["timestamp"],
                                             "time_utc": datetime.datetime.fromtimestamp(blk["timestamp"], datetime.timezone.utc).isoformat()}

out["all_pass"] = all(c["pass"] for c in out["checks"])
with open(os.path.join(HERE, "ots_check.json"), "w") as fh:
    json.dump(out, fh, indent=1)
print("ALL PASS" if out["all_pass"] else "SOME FAIL")
