#!/usr/bin/env python3
"""remeasure_p18_n25.py — review points 2 and 3, remeasured with a headed log:
 (2) p18/n29 prefixDigest derivable as keccak256(JCS(prefix)) (= M:content_address applied to the prefix array) and sha3_256(JCS(prefix));
 (3) n25 under a verifier that requires `position` but does NOT require attestedPrefixLength when no coverage is claimed;
 and RFC 7493 line numbers for the 2**53 sentence."""
import hashlib, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
CR = os.path.abspath(os.path.join(HERE, "..", ".."))          # repository root
sys.path.insert(0, CR)
import verify_tersign as V
def vec(n):
    return V.load_json(open(os.path.join(CR, "spec", "vectors", n), encoding="utf-8").read())
p18, n29, n25 = vec("p18-boundary-binds-prefix-and-position.json"), vec("n29-suite-transition-redigests-prefix.json"), vec("n25-boundary-prefix-only-no-position.json")
cb = V.jcs(p18["input"]["prefix"])
k, s = "0x" + V.keccak256_pure(cb).hex(), "0x" + hashlib.sha3_256(cb).hexdigest()
print("canonical(prefix) =", cb.decode())
print("keccak256(JCS(prefix)) =", k, "== p18.prefixDigest:", k == p18["input"]["boundary_event"]["prefixDigest"])
print("sha3_256(JCS(prefix))  =", s, "== n29.prefixDigest:", s == n29["input"]["boundary_event"]["prefixDigest"])
print("n25 prefix canonical bytes identical to p18:", V.jcs(n25["input"]["prefix"]) == cb, "| n25.prefixDigest == p18.prefixDigest:", n25["input"]["boundary_event"]["prefixDigest"] == p18["input"]["boundary_event"]["prefixDigest"])
# (3) minimal boundary verifier: position REQUIRED; attestedPrefixLength required only when covered_through is claimed
def boundary_apl_optional(inp, require_position=True):
    ev = inp["boundary_event"]; prefix = inp["prefix"]
    if V.keccak256_pure(V.jcs(prefix)) != bytes.fromhex(ev["prefixDigest"][2:]):
        return "reject", "prefixDigest does not bind"
    if require_position:
        if not V.is_int(ev.get("position")):
            return "reject", "binds no position"
        if ev["position"] != len(prefix):
            return "reject", "position not the continuation point"
    if "covered_through" in inp:
        apl = ev.get("attestedPrefixLength")
        if not V.is_int(apl) or apl == 0 or inp["covered_through"] > apl:
            return "reject", "coverage beyond attestation / unattested"
    return "valid", None
for name, v in (("p18", p18), ("n25", n25), ("n29", n29)):
    print(f"{name}: apl-optional, position required -> {boundary_apl_optional(v['input'])} | expect {v['expect']}")
print("n25: apl-optional AND position NOT required ->", boundary_apl_optional(n25["input"], require_position=False))
# RFC 7493 lines
lines = open(os.path.join(HERE, "live", "specs", "rfc7493.txt"), encoding="utf-8", errors="replace").read().splitlines()
for i in range(143, 152):
    print(f"rfc7493 L{i+1}: {lines[i]}")
