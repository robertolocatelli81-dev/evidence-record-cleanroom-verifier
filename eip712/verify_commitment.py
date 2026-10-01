#!/usr/bin/env python3
"""verify_commitment.py — recompute the commitment posted on tersignhq/evidence-record-conformance PR #11
(comment 5921105343, 2026-09-30T22:53:10Z):

    commitment_sha256 = sha256(nonce_hex || canonical_json(record_body))
    record_body       = {"files": {relative path: sha256 hex of the file's bytes}} over every file in commitment-3b766320/
    canonical_json    = JSON with sorted keys, separators (",", ":"), ensure_ascii False, encoded as UTF-8

It walks commitment-3b766320/ itself (it does not trust record_body.json), checks that the result equals record_body.json
byte for byte, then hashes with NONCE. Exit 0 only when both match the published value.
Usage: python3 verify_commitment.py [dir containing commitment-3b766320/, record_body.json and NONCE]      Stdlib only.
"""
import hashlib
import json
import os
import sys

PUBLISHED = "3b7663201182e564f8649f835c4f3e8544438be49b838fde9ff887702a7a7f9e"
FOLDER = "commitment-3b766320"


def record_body(root):
    files = {}
    for d, dirs, names in os.walk(root):
        dirs[:] = [x for x in dirs if x != "__pycache__"]
        for n in names:
            p = os.path.join(d, n)
            with open(p, "rb") as fh:
                files[os.path.relpath(p, root).replace(os.sep, "/")] = hashlib.sha256(fh.read()).hexdigest()
    return {"files": dict(sorted(files.items()))}


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def main(argv):
    base = argv[0] if argv else os.path.dirname(os.path.abspath(__file__))
    body = canonical(record_body(os.path.join(base, FOLDER)))
    with open(os.path.join(base, "record_body.json"), "rb") as fh:
        stored = fh.read()
    with open(os.path.join(base, "NONCE"), encoding="ascii") as fh:
        nonce = fh.read().strip()
    got = hashlib.sha256(nonce.encode("ascii") + body).hexdigest()
    print(f"files hashed       {len(json.loads(body)['files'])}")
    print(f"record_body.json   {'matches the files' if body == stored else 'DOES NOT match the files'}")
    print(f"commitment_sha256  {got}")
    print(f"published          {PUBLISHED}  {'MATCH' if got == PUBLISHED else 'NO MATCH'}")
    return 0 if body == stored and got == PUBLISHED else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
