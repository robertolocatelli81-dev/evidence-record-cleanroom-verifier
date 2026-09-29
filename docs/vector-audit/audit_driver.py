#!/usr/bin/env python3
"""audit_driver.py — Q2 (isolation) and Q4 (twin coverage) measurement over the 69 Tersign vectors.

Uses the repository's clean-room verifier (../../verify_tersign.py) READ-ONLY (imported, never modified):
its 14 built-in ablations PLUS extra ablations defined HERE by monkeypatching module attributes at run
time (restored after each run). Every ablation disables or distorts ONE rule; a vector whose verdict
changes under an ablation is PINNED by that rule.

Run from anywhere: python3 docs/vector-audit/audit_driver.py
Outputs (in this directory): measures_q2q4.json, audit_driver.log (headed, repo-relative paths only).
"""
import copy, datetime, hashlib, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
CR = os.path.abspath(os.path.join(HERE, "..", ".."))          # repository root
SPEC = os.path.join(CR, "spec")
sys.path.insert(0, CR)
import verify_tersign as V  # noqa: E402

LOG = []


def log(s=""):
    print(s)
    LOG.append(s)


def sha256_file(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


# ─────────────────────────── monkeypatch helpers ───────────────────────────
class Patch:
    """Temporarily set module attributes on V and/or entries of V.KINDS."""

    def __init__(self, attrs=None, kinds=None):
        self.attrs, self.kinds, self.saved_a, self.saved_k = attrs or {}, kinds or {}, {}, {}

    def __enter__(self):
        for k, v in self.attrs.items():
            self.saved_a[k] = getattr(V, k)
            setattr(V, k, v)
        for k, v in self.kinds.items():
            self.saved_k[k] = V.KINDS[k]
            V.KINDS[k] = v
        return self

    def __exit__(self, *a):
        for k, v in self.saved_a.items():
            setattr(V, k, v)
        for k, v in self.saved_k.items():
            V.KINDS[k] = v


ORIG = {n: getattr(V, n) for n in ("k_digest_recompute", "k_canonical_bytes", "k_chain_link", "k_anchor_relation",
                                    "k_chain_set", "k_chain_commitment", "k_phase_claim", "k_independence_claim",
                                    "k_offer_binding", "k_decision_evidence_binding", "k_boundary_binding",
                                    "derive_commitments", "normalize_identity", "load_json", "_utf16_key", "_jcs")}


# ── variant: chain-set walk with switchable sub-rules (copied logic, flags added) ──
def chain_set_links_variant(*, completeness=True, prev=True, head=True, genesis=True, witness_presence=False):
    def f(inp):
        R_COMP, R_CONT = V.R_COMPLETENESS, V.R_CONTINUITY
        h = V.need_dict(inp.get("head"), R_COMP, "head")
        hseq = h.get("seq")
        if not V.is_int(hseq) or hseq < 1:
            raise V.Reject(R_COMP, f"head.seq {hseq!r} is not a positive integer token")
        hdig = V.hex32(h.get("digest"), R_CONT, "head.digest")
        records = V.need_list(inp.get("records"), R_COMP, "records")
        by_seq, duplicates = {}, []
        for r in records:
            r = V.need_dict(r, R_COMP, "record")
            s = r.get("seq")
            if not V.is_int(s):
                raise V.Reject(R_COMP, f"record seq {s!r} is not an integer token")
            if s in by_seq:
                duplicates.append(s)
            else:
                by_seq[s] = r
        witnessed = set()
        if witness_presence and isinstance(inp.get("witness"), dict):
            for e in inp["witness"].get("inclusion") or []:
                if isinstance(e, dict) and V.is_int(e.get("seq")):
                    witnessed.add(e["seq"])
        missing = [s for s in range(1, hseq + 1) if s not in by_seq and s not in witnessed]
        beyond = sorted(s for s in by_seq if s < 1 or s > hseq)
        if completeness:
            if duplicates:
                raise V.Reject(R_COMP, f"duplicate seq {sorted(set(duplicates))} under committed head")
            if missing:
                raise V.Reject(R_COMP, f"missing seq {missing} under committed head")
            if beyond:
                raise V.Reject(R_COMP, f"seq {beyond} outside 1..head.seq")
        present = sorted(s for s in by_seq if 1 <= s <= hseq)
        if not present:
            raise V.Reject(R_COMP, "no record under the committed head")
        last_art = V.hex32(by_seq[present[-1]].get("artifact_digest"), R_CONT, "artifact_digest")
        if head and present[-1] == hseq and last_art != hdig:
            raise V.Reject(R_CONT, "head.digest does not equal the final record's artifact digest")
        links, prev_art, prev_seq = [], None, None
        for s in present:
            r = by_seq[s]
            art = V.hex32(r.get("artifact_digest"), R_CONT, f"artifact_digest at seq {s}")
            if "prev_digest" not in r:
                raise V.Reject(R_CONT, f"record at seq {s} presents no prev_digest")
            pd = r["prev_digest"]
            contiguous = (s == 1) or (prev_seq == s - 1)
            if s == 1:
                if genesis and pd is not None:
                    raise V.Reject(R_CONT, "genesis record (seq 1) must carry a null prev_digest")
                prev_for_link = None
            elif contiguous:
                if prev and (pd is None or V.hex32(pd, R_CONT, f"prev_digest at seq {s}") != prev_art):
                    raise V.Reject(R_CONT, f"prev_digest at seq {s} is not the previous record's artifact digest")
                prev_for_link = prev_art
            else:  # witnessed gap: nothing to compare against; trust the presented prev for the link
                prev_for_link = None if pd is None else V.hex32(pd, R_CONT, f"prev_digest at seq {s}")
            link = V.chain_link(art, prev_for_link, s)
            if "link" in r:
                claimed = V.hex32(r["link"], R_CONT, f"link at seq {s}")
                if claimed != link:
                    raise V.Reject(R_CONT, f"link at seq {s} does not recompute")
            links.append(link)
            prev_art, prev_seq = art, s
        return hseq, links
    return f


def acc_last_link_only(inp):
    hseq, links = V._chain_set_links(inp)
    head = inp["head"]
    if "acc" not in head:
        raise V.Reject(V.R_CONTINUITY, "head.acc absent")
    claimed = V.hex32(head["acc"], V.R_CONTINUITY, "head.acc")
    acc = V.keccak256(V.keccak256(V.ACC_SEED) + links[-1])
    if acc != claimed:
        raise V.Reject(V.R_CONTINUITY, "accumulator mismatch (last-link-only fold)")
    return "head.acc equals keccak(acc_0 || last link)"


# ── variant: boundary binding with switchable sub-rules ──
def boundary_variant(*, position=True, apl_required=True, redigest=False, vocab=True):
    def f(inp):
        R = V.R_BOUNDARY
        prefix = V.need_list(inp.get("prefix"), R, "prefix")
        ev = V.need_dict(inp.get("boundary_event"), R, "boundary_event")
        event = ev.get("event")
        if vocab:
            if event not in V.BOUNDARY_EVENTS:
                raise V.Reject(R, f"boundary event {event!r} is not interpretable")
            if ev.get("ruleVersion") != V.BOUNDARY_EVENTS[event]:
                raise V.Reject(R, "ruleVersion unknown")
            if event == "digest_suite_transition":
                if ev.get("fromSuite") != V.PRIOR_SUITE:
                    raise V.Reject(R, "fromSuite is not the prior suite")
                if not isinstance(ev.get("toSuite"), str) or not ev["toSuite"]:
                    raise V.Reject(R, "toSuite absent")
        claimed = V.hex32(ev.get("prefixDigest"), R, "prefixDigest")
        cb = V.jcs(prefix)
        if redigest and event == "digest_suite_transition" and ev.get("toSuite") == "sha3-256-jcs":
            got = hashlib.sha3_256(cb).digest()
        else:
            got = V.keccak256(cb)
        if got != claimed:
            raise V.Reject(R, "prefixDigest does not bind the prefix")
        if position:
            pos = ev.get("position")
            if not V.is_int(pos):
                raise V.Reject(R, "boundary event binds no position")
            if pos != len(prefix):
                raise V.Reject(R, "position is not the continuation point")
        apl = ev.get("attestedPrefixLength")
        if apl is None and not apl_required:
            return "prefix binds; attestation length not required (ablated)"
        if not V.is_int(apl) or apl < 0 or apl > len(prefix):
            raise V.Reject(R, "attestedPrefixLength absent or out of range")
        ct = inp.get("covered_through")
        if "covered_through" in inp and (not V.is_int(ct) or ct < 0):
            raise V.Reject(R, "covered_through not a non-negative integer token")
        if apl == 0:
            raise V.Reject(R, "unattested prefix is its own outcome, not a pass")
        if ct is not None and ct > apl:
            raise V.Reject(R, "coverage claimed beyond attestation")
        return "prefix binds; position ok; coverage within attestation"
    return f


# ── variant: phase ──
def phase_variant(*, vocab=True, equality=True, later_only=False):
    def f(inp):
        rec = V.need_dict(inp.get("record"), V.R_PHASE, "record")
        phase, presented = rec.get("economic_phase"), inp.get("presented_as")
        if vocab:
            if not isinstance(phase, str) or phase not in V.PHASES:
                raise V.Reject(V.R_PHASE, "economic_phase outside vocabulary")
            if not isinstance(presented, str) or presented not in V.PHASES:
                raise V.Reject(V.R_PHASE, "presented_as outside vocabulary")
        if later_only:
            order = {p: i for i, p in enumerate(V.PHASES)}
            if isinstance(phase, str) and isinstance(presented, str) and phase in order and presented in order \
                    and order[presented] > order[phase]:
                raise V.Reject(V.R_PHASE, "record presented as evidence of a LATER phase")
            return "phase ok (later-only reading)"
        if equality and phase != presented:
            raise V.Reject(V.R_PHASE, "record phase != presented phase")
        return "phase ok"
    return f


# ── variant: independence wrappers ──
def indep_wrapper(transform=None, pre=None):
    orig = ORIG["k_independence_claim"]

    def f(inp):
        inp2 = copy.deepcopy(inp)
        if transform:
            inp2 = transform(inp2)
        if pre:
            pre(inp2)
        return orig(inp2)
    return f


def _reject_all_party_only(inp):
    parties = inp.get("parties")
    atts = inp.get("attestations")
    if isinstance(parties, list) and isinstance(atts, list):
        pk = {V.normalize_identity(p) for p in parties}
        outside = sum(1 for a in atts if isinstance(a, dict) and V.normalize_identity(a.get("by")) not in pk)
        if outside == 0:
            raise V.Reject(V.R_INDEPENDENCE, "attested only by parties (unconditional rejector, ablation)")


def _atts_default_empty(inp):
    if "attestations" not in inp:
        inp["attestations"] = []
    return inp


def _att_string_as_by(inp):
    if isinstance(inp.get("attestations"), list):
        inp["attestations"] = [{"by": a} if isinstance(a, str) else a for a in inp["attestations"]]
    return inp


def _drop_covers(inp):
    inp.pop("covers", None)
    return inp


def derive_variant(*, empty_tx_ok=False, trust_digest=False, nothing=False):
    def f(inp):
        if not any(k in inp for k in V.DERIVABLE_FIELDS):
            return None
        if nothing:
            return set()
        c = set()
        sr = inp.get("settlement_result")
        if isinstance(sr, dict):
            tx = sr.get("transaction")
            if sr.get("success") is True and isinstance(tx, str) and (tx != "" or empty_tx_ok):
                c.add("settlement")
            net = sr.get("network")
            if isinstance(net, str) and net != "":
                c.add("network")
        if "deliverable_bytes" in inp and "deliverable_digest" in inp:
            b, d = inp["deliverable_bytes"], inp["deliverable_digest"]
            if isinstance(b, str) and isinstance(d, str) and V._RE_HEX32.fullmatch(d.strip()):
                if trust_digest or V.keccak256(b.encode("utf-8")) == bytes.fromhex(d.strip()[2:]):
                    c.add("delivery")
        return c
    return f


def normalize_variant(*, addr_only=False, no_rstrip=False, case_fold=False):
    def f(v):
        if not isinstance(v, str):
            return None
        t = v.strip()
        if V._RE_ADDR.fullmatch(t):
            return "addr:" + t.lower()
        if addr_only:
            return None
        m = V._RE_SCHEME.fullmatch(t)
        if m and ":" not in m.group(2):
            path = m.group(2) if no_rstrip else m.group(2).rstrip("/.#")
            if case_fold:
                path = path.lower()
            return ("uri:" + m.group(1) + ":" + path) if path else None
        return None
    return f


# ── digest / canonical variants ──
def k_digest_no_compare(inp):
    if "payload" not in inp:
        raise V.Reject(V.R_RECOMPUTE, "no payload")
    got = V.content_address(inp["payload"])
    V.hex32(inp.get("expected_digest"), V.R_RECOMPUTE, "expected_digest")
    return f"digest computed 0x{got.hex()} (comparison ablated)"


def k_canonical_reject_text(inp):
    if "payload_text" in inp:
        raise V.Reject(V.R_CANON, "raw-text pathway rejected unconditionally (ablation)")
    return ORIG["k_canonical_bytes"](inp)


def jcs_insertion_order(x, depth):
    """Copy of V._jcs's dict branch without key sorting (insertion order); other branches delegate."""
    if isinstance(x, dict):
        for k in x:
            if not isinstance(k, str):
                raise V.Reject(V.R_CANON, "object name is not a string")
        return "{" + ",".join(V._jcs_string(k) + ":" + jcs_insertion_order(x[k], depth + 1) for k in x) + "}"
    if isinstance(x, list):
        return "[" + ",".join(jcs_insertion_order(i, depth + 1) for i in x) + "]"
    return ORIG["_jcs"](x, depth)


def load_json_collapse(text):
    import json as _j

    def pf(s):
        f = float(s)
        return int(f) if f.is_integer() else V.NumberToken(s)
    return _j.loads(text, parse_float=pf, parse_constant=V._bad_constant, object_pairs_hook=V._pairs_no_dup)


class _Sha3AsSha256:
    sha256 = staticmethod(hashlib.sha3_256)


def k_anchor_no_compare(inp):
    V.hex32(inp.get("subject_digest"), V.R_EXISTENCE, "subject_digest")
    V.hex32(inp.get("anchored_digest"), V.R_EXISTENCE, "anchored_digest")
    return "anchor relation not compared (ablation)"


def k_link_no_compare(inp):
    V.hex32(inp.get("artifact_digest"), V.R_CONTINUITY, "artifact_digest")
    V.hex32(inp.get("expected_link"), V.R_CONTINUITY, "expected_link")
    return "link not compared (ablation)"


def k_offer_no_compare(inp):
    offer = V.need_dict(inp.get("offer"), V.R_BINDING, "offer")
    receipt = V.need_dict(inp.get("receipt"), V.R_BINDING, "receipt")
    if "offerDigest" not in receipt:
        raise V.Reject(V.R_BINDING, "no offerDigest")
    V.hex32(receipt["offerDigest"], V.R_BINDING, "receipt.offerDigest")
    V.content_address(offer)
    return "offer digest not compared (ablation)"


def k_offer_no_presence(inp):
    receipt = V.need_dict(inp.get("receipt"), V.R_BINDING, "receipt")
    if "offerDigest" not in receipt:
        return "no offerDigest: accepted (ablation)"
    return ORIG["k_offer_binding"](inp)


def k_decision_no_presence(inp):
    rec = V.need_dict(inp.get("record"), V.R_BINDING, "record")
    if "decisionEvidenceDigest" not in rec:
        return "no decisionEvidenceDigest: accepted (ablation)"
    return ORIG["k_decision_evidence_binding"](inp)


def k_decision_no_compare(inp):
    rec = V.need_dict(inp.get("record"), V.R_BINDING, "record")
    ev = V.need_dict(inp.get("decision_evidence"), V.R_BINDING, "decision_evidence")
    if "decisionEvidenceDigest" not in rec:
        raise V.Reject(V.R_BINDING, "no decisionEvidenceDigest")
    V.hex32(rec["decisionEvidenceDigest"], V.R_BINDING, "digest")
    V.content_address(ev)
    return "decision evidence digest not compared (ablation)"


EXTRA = {
    # digest_recompute / canonical_bytes
    "no_digest_compare": ("digest_recompute: expected_digest is parsed but never compared",
                          Patch(kinds={"digest_recompute": k_digest_no_compare})),
    "numeric_hoist_keys": ("JCS: integer-like keys sorted numerically first (JS engine hoisting)",
                           Patch(attrs={"_utf16_key": lambda k: (0, int(k)) if k.isdigit() else (1, k.encode("utf-16-be", "surrogatepass"))})),
    "insertion_order_keys": ("JCS: object keys emitted in insertion order (no sort)",
                             Patch(attrs={"_jcs": jcs_insertion_order})),
    "strict_below_2_53": ("number domain: |n| <= 2^53-2 (rejects the boundary value 2^53-1 itself)",
                          Patch(attrs={"I_JSON_MAX": 2 ** 53 - 2})),
    "accept_2_53": ("number domain: |n| <= 2^53 (off-by-one, accepts 2^53)",
                    Patch(attrs={"I_JSON_MAX": 2 ** 53})),
    "reject_payload_text": ("canonical_bytes: the raw-text (payload_text) pathway rejects unconditionally",
                            Patch(kinds={"canonical_bytes": k_canonical_reject_text})),
    "json_parse_collapses_integral_floats": ("loader: integer-valued float tokens (2.0, 3.0) collapse to int (JSON.parse engine)",
                                             Patch(attrs={"load_json": load_json_collapse})),
    # chain_link / anchor
    "no_link_compare": ("chain_link: expected_link parsed but never compared",
                        Patch(kinds={"chain_link": k_link_no_compare})),
    "no_anchor_compare": ("anchor_relation: sha256(subject) never compared with anchored_digest",
                          Patch(kinds={"anchor_relation": k_anchor_no_compare})),
    "anchor_sha3": ("anchor_relation: SHA3-256 instead of SHA-256",
                    Patch(attrs={"hashlib": _Sha3AsSha256})),
    # chain_set / chain_commitment sub-rules
    "no_prev_continuity": ("chain_set: prev_digest not compared with the previous record's artifact digest",
                           Patch(attrs={"_chain_set_links": chain_set_links_variant(prev=False)})),
    "no_head_digest_binding": ("chain_set: head.digest not compared with the final record's artifact digest",
                               Patch(attrs={"_chain_set_links": chain_set_links_variant(head=False)})),
    "no_genesis_null_prev": ("chain_set: genesis record may carry a non-null prev_digest",
                             Patch(attrs={"_chain_set_links": chain_set_links_variant(genesis=False)})),
    "witness_counts_as_presence": ("chain_set: a witnessed inclusion (leaf index) counts as a present record",
                                   Patch(attrs={"_chain_set_links": chain_set_links_variant(witness_presence=True)})),
    "acc_last_link_only": ("chain_commitment: head.acc compared with keccak(acc_0 || last link) only",
                           Patch(kinds={"chain_commitment": acc_last_link_only})),
    # phase
    "phase_vocab_only": ("phase_claim: vocabulary checked, equality record/presented NOT checked",
                         Patch(kinds={"phase_claim": phase_variant(equality=False)})),
    "phase_equality_only": ("phase_claim: equality checked, vocabulary NOT checked",
                            Patch(kinds={"phase_claim": phase_variant(vocab=False)})),
    "phase_later_only": ("phase_claim: reject only when presented as a LATER phase than the record's (spec's literal wording)",
                         Patch(kinds={"phase_claim": phase_variant(later_only=True)})),
    # independence
    "reject_all_party_only": ("independence: unconditional rejector of party-only attested records, whatever is claimed",
                              Patch(kinds={"independence_claim": indep_wrapper(pre=_reject_all_party_only)})),
    "attestations_default_empty": ("independence: a missing `attestations` field is read as an empty list",
                                   Patch(kinds={"independence_claim": indep_wrapper(transform=_atts_default_empty)})),
    "attestation_string_as_by": ("independence: a bare-string attestation is read as {by: string}",
                                 Patch(kinds={"independence_claim": indep_wrapper(transform=_att_string_as_by)})),
    "covers_not_checked": ("independence: the `covers` scope is ignored",
                           Patch(kinds={"independence_claim": indep_wrapper(transform=_drop_covers)})),
    "settlement_any_string": ("derivation: settlement committed when success is true and transaction is ANY string (empty ok)",
                              Patch(attrs={"derive_commitments": derive_variant(empty_tx_ok=True)})),
    "trust_declared_delivery_digest": ("derivation: delivery committed when digest present, bytes NOT recomputed",
                                       Patch(attrs={"derive_commitments": derive_variant(trust_digest=True)})),
    "derive_nothing": ("derivation: commitments always empty when the fields are present",
                       Patch(attrs={"derive_commitments": derive_variant(nothing=True)})),
    "addr_only_identity": ("identity: only 0x-addresses parse (scheme-qualified identifiers fail closed)",
                           Patch(attrs={"normalize_identity": normalize_variant(addr_only=True)})),
    "no_trailing_punct_fold": ("identity: scheme identifiers compared without trailing / . # fold",
                               Patch(attrs={"normalize_identity": normalize_variant(no_rstrip=True)})),
    "case_fold_scheme_ids": ("identity: scheme identifier paths compared case-insensitively",
                             Patch(attrs={"normalize_identity": normalize_variant(case_fold=True)})),
    # offer / decision evidence
    "no_offer_compare": ("offer_binding: digest present but not compared",
                         Patch(kinds={"offer_binding": k_offer_no_compare})),
    "no_offer_presence": ("offer_binding: a receipt without offerDigest is accepted",
                          Patch(kinds={"offer_binding": k_offer_no_presence})),
    "no_decision_presence": ("decision_evidence_binding: a record without decisionEvidenceDigest is accepted",
                             Patch(kinds={"decision_evidence_binding": k_decision_no_presence})),
    "no_decision_compare": ("decision_evidence_binding: digest present but not compared",
                            Patch(kinds={"decision_evidence_binding": k_decision_no_compare})),
    # boundary
    "redigest_under_toSuite": ("boundary: prefixDigest recomputed under the SUCCESSOR suite at a transition",
                               Patch(kinds={"boundary_binding": boundary_variant(redigest=True)})),
    "no_boundary_vocab": ("boundary: any event / ruleVersion / fromSuite accepted",
                          Patch(kinds={"boundary_binding": boundary_variant(vocab=False)})),
    "no_position_apl_optional": ("boundary: position not required AND attestedPrefixLength optional",
                                 Patch(kinds={"boundary_binding": boundary_variant(position=False, apl_required=False)})),
    "apl_optional_only": ("boundary: attestedPrefixLength optional (position still required)",
                          Patch(kinds={"boundary_binding": boundary_variant(apl_required=False)})),
}


# ─────────────────────────── runs ───────────────────────────
def run_builtin(name):
    V._ABLATE.clear()
    if name:
        V._ABLATE.add(name)
    try:
        return V.run_suite(SPEC)
    finally:
        V._ABLATE.clear()


def run_extra(name):
    V._ABLATE.clear()
    with EXTRA[name][1]:
        return V.run_suite(SPEC)


def main():
    started = datetime.datetime.now(datetime.timezone.utc).astimezone()
    log("=== audit_driver header ===")
    log(f"started  : {started.isoformat(timespec='seconds')}")
    log("cwd      : . (repository root; paths repo-relative)")
    log(f"python   : {sys.version.split()[0]}")
    log(f"verifier : verify_tersign.py sha256={sha256_file(os.path.join(CR, 'verify_tersign.py'))} version={V.__version__}")
    log(f"manifest : sha256={sha256_file(os.path.join(SPEC, 'MANIFEST.json'))}")
    base = run_builtin(None)
    log(f"baseline : fully concordant {base['concordant']}/{base['n']}")
    assert base["concordant"] == base["n"] == 69
    per = {r["file"]: {"file": r["file"], "kind": r["kind"], "expect": r["expect"], "expect_reason": r["expect_reason"],
                       "baseline_verdict": r["verdict"], "baseline_reason": r["reason"], "baseline_detail": r["detail"],
                       "flips": [], "reason_only": []} for r in base["rows"]}
    abl_summary = {}
    for kind_, names in (("builtin", list(V.ABLATIONS)), ("extra", list(EXTRA))):
        for name in names:
            res = run_builtin(name) if kind_ == "builtin" else run_extra(name)
            desc = V.ABLATIONS[name] if kind_ == "builtin" else EXTRA[name][0]
            flips, ronly = [], []
            for r in res["rows"]:
                if r["verdict"] != r["expect"]:
                    flips.append(r["file"]); per[r["file"]]["flips"].append(name)
                elif r["expect_reason"] and r["reason"] != r["expect_reason"]:
                    ronly.append(r["file"]); per[r["file"]]["reason_only"].append(name)
            abl_summary[name] = {"source": kind_, "description": desc, "verdict_flips": flips, "reason_only": ronly}
            log(f"ablate[{kind_}] {name:<38} flips={len(flips):<2} reason-only={len(ronly):<2} {flips}")
    # post-condition: baseline restored
    base2 = run_builtin(None)
    assert base2["concordant"] == 69, "patches not restored"
    # mutations (positive control on the valid vectors)
    V._ABLATE.clear()
    mut = V.run_mutations(SPEC)
    log(f"mutations: flipped valid->reject {mut['flipped']}/{mut['n']}")
    for r in mut["rows"]:
        per[r["file"]].setdefault("mutations", []).append({"mutation": r["mutation"], "flipped": r["flipped"], "reason": r["reason"]})
    # Q4: twin diffs (leaf paths of `input`)
    vecs = {}
    for f in per:
        with open(os.path.join(SPEC, "vectors", f), encoding="utf-8") as fh:
            vecs[f] = V.load_json(fh.read())

    def flatten(o, path="", out=None):
        out = {} if out is None else out
        if isinstance(o, dict):
            for k, v in o.items():
                flatten(v, f"{path}/{k}", out)
            if not o:
                out[path] = "{}"
        elif isinstance(o, list):
            for i, v in enumerate(o):
                flatten(v, f"{path}[{i}]", out)
            if not o:
                out[path] = "[]"
        else:
            out[path] = repr(o)
        return out

    flat = {f: flatten(vecs[f]["input"]) for f in per}
    for f, p in per.items():
        same_kind = [g for g in per if g != f and per[g]["kind"] == p["kind"] and per[g]["expect"] != p["expect"]]
        best = None
        for g in same_kind:
            a, b = flat[f], flat[g]
            changed = sorted(k for k in a if k in b and a[k] != b[k])
            added = sorted(k for k in a if k not in b)
            removed = sorted(k for k in b if k not in a)
            n = len(changed) + len(added) + len(removed)
            top = sorted({k.split("/")[1].split("[")[0] for k in changed + added + removed})
            cand = {"twin": g, "leaf_diff": n, "changed": changed, "added": added, "removed": removed, "top_level_fields": top}
            if best is None or n < best["leaf_diff"]:
                best = cand
        p["closest_opposite_twin"] = best
        p["n_flips"] = len(p["flips"])
    ended = datetime.datetime.now(datetime.timezone.utc).astimezone()
    log(f"ended    : {ended.isoformat(timespec='seconds')}")
    out = {"header": {"started": started.isoformat(timespec="seconds"), "ended": ended.isoformat(timespec="seconds"),
                      "python": sys.version.split()[0], "verifier_sha256": sha256_file(os.path.join(CR, "verify_tersign.py")),
                      "manifest_sha256": sha256_file(os.path.join(SPEC, "MANIFEST.json")), "baseline_concordant": base["concordant"]},
           "ablations": abl_summary, "mutations_total": {"n": mut["n"], "flipped": mut["flipped"]}, "vectors": per}
    with open(os.path.join(HERE, "measures_q2q4.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1, ensure_ascii=False)
    with open(os.path.join(HERE, "audit_driver.log"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(LOG) + "\n")
    log("\nper-vector pin counts (verdict flips under single ablations):")
    for f, p in per.items():
        log(f"  {f:<56} n_flips={p['n_flips']:<2} {p['flips']}  reason-only={p['reason_only']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
