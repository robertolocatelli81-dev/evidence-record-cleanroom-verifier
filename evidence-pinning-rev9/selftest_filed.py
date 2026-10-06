"""Checks for the only code path added to es_check_filed.py (FILED M5: held_sha256), written before any rev-9 vector
was run. Plus a positive control: a copy with the comparison inverted must fail these checks.
Added after the run (2026-10-06, review): one check of the filed presence rule (FILED M1), so that the folder itself
kills mutant M17 of mutanti.py (present_when_unpinned suppressed by the hex failure)."""
import hashlib, sys, types, os
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import es_check_filed as C

A, B = b"content A", b"content B"
def base():
    s = [{"url": "https://a.example/x", "snippet_sha256": hashlib.sha256(A).hexdigest(), "retrieved_at": "2026-09-01T12:00:00.000Z",
          "pinned": True, "content_kind": "snippet"},
         {"url": "https://b.example/y", "snippet_sha256": hashlib.sha256(B).hexdigest(), "retrieved_at": "2026-09-01T12:00:01.000Z",
          "pinned": True, "content_kind": "snippet"}]
    return {"evidence_set": {"evidence_set_version": C.VERSION, "sources": s, "evidence_root": C.evidence_root(s)}}

def checks(M):
    out = []
    h = lambda b: hashlib.sha256(b).hexdigest()
    r = M.resolve(base(), held_sha256={0: h(A), 1: h(B)}); out.append((r["outcome"], r["per_item"]) == ("resolved", ["content_matches"] * 2))
    r = M.resolve(base(), held_sha256={0: h(A), 1: h(b"x")}); out.append((r["outcome"], r["per_item"]) == ("unknown", ["content_matches", "content_differs"]))
    r = M.resolve(base(), held_sha256={0: h(A)}); out.append((r["outcome"], r["per_item"]) == ("unknown", ["content_matches", "content_not_held"]))
    r = M.resolve(base(), held={0: A}, held_sha256={1: h(B)}); out.append(r["outcome"] == "resolved")
    p = base(); p["evidence_set"]["sources"][1].update(pinned=False, snippet_sha256=None, content_kind=None, unpinned_reason="no_content_returned")
    p["evidence_set"]["evidence_root"] = C.evidence_root([p["evidence_set"]["sources"][0]])
    r = M.resolve(p, held_sha256={0: h(A), 1: h(B)}); out.append((r["outcome"], r["per_item"]) == ("unknown", ["content_matches", "content_not_held"]))
    return out

def presence_check(M):
    """FILED M1: an unpinned entry whose non-null snippet_sha256 is not hex64 reports BOTH conditions."""
    p = base(); p["evidence_set"]["sources"][1].update(pinned=False, snippet_sha256="not-hex", content_kind=None,
                                                       unpinned_reason="no_content_returned")
    p["evidence_set"]["evidence_root"] = C.evidence_root([p["evidence_set"]["sources"][0]])
    r = M.resolve(p)
    return r["outcome"] == "malformed" and {"snippet_sha256_not_lowercase_hex64", "snippet_sha256_present_when_unpinned"} <= set(r["conditions"])


ok = checks(C)
print("held_sha256 checks:", sum(ok), "/", len(ok))
okp = presence_check(C)
print("presence rule (FILED M1) check:", int(okp), "/ 1")
src = open(os.path.join(HERE, "es_check_filed.py")).read()
bad = src.replace('per.append("content_matches" if held_sha256[i] == e["snippet_sha256"] else "content_differs")',
                  'per.append("content_matches" if held_sha256[i] != e["snippet_sha256"] else "content_differs")')
assert bad != src
m = types.ModuleType("bad"); exec(compile(bad, "bad", "exec"), m.__dict__)
okb = checks(m)
print("positive control (inverted compare) passes", sum(okb), "/", len(okb), "(must be < %d)" % len(okb))
sys.exit(0 if all(ok) and okp and not all(okb) else 1)
