#!/usr/bin/env python3
"""Convert a verify_tersign.py --json result into the run format read by the
upstream suite's tools/compare_run.py.

Target format (from the upstream README, section "Reproduction", tag v0.5.9):
a JSON array, one object per vector; "file" is the vector's file name as the
manifest lists it, "verdict" is "valid" or "reject", a reject carries
"reason", a valid carries none. No other key.

Only the "file", "verdict" and "reason" fields of each row are copied; nothing
is recomputed. Anything outside that shape is refused (exit 2), never dropped:
a row without those fields, a verdict other than valid/reject, a reject
without a reason, a valid with one, two rows for one file, or a row count that
differs from the result's "n".

Deterministic: rows keep the order of the input; one object per line; LF.

Usage: python3 tools/to_compare_run.py <verify_tersign.json> <out.json>
"""
import json
import sys


def convert(result):
    if not isinstance(result, dict) or not isinstance(result.get("rows"), list):
        raise ValueError("input is not a verify_tersign.py --json result (no 'rows' list)")
    rows = result["rows"]
    if result.get("n") != len(rows):
        raise ValueError("'n' is %r but there are %d rows" % (result.get("n"), len(rows)))
    out, seen = [], set()
    for i, row in enumerate(rows):
        if not isinstance(row, dict) or not {"file", "verdict", "reason"} <= row.keys():
            raise ValueError("row %d lacks file/verdict/reason" % i)
        f, v, r = row["file"], row["verdict"], row["reason"]
        if not isinstance(f, str) or not f:
            raise ValueError("row %d: file is not a non-empty string" % i)
        if f in seen:
            raise ValueError("row %d: second row for %s" % (i, f))
        seen.add(f)
        if v == "valid":
            if r is not None:
                raise ValueError("row %d (%s): valid with a reason" % (i, f))
            out.append({"file": f, "verdict": "valid"})
        elif v == "reject":
            if not isinstance(r, str) or not r:
                raise ValueError("row %d (%s): reject without a reason" % (i, f))
            out.append({"file": f, "verdict": "reject", "reason": r})
        else:
            raise ValueError("row %d (%s): verdict %r is neither valid nor reject" % (i, f, v))
    return out


def dumps(entries):
    lines = [json.dumps(e, ensure_ascii=False) for e in entries]
    return "[\n" + ",\n".join("  " + l for l in lines) + "\n]\n"


def main(argv):
    if len(argv) != 3:
        sys.stderr.write("usage: to_compare_run.py <verify_tersign.json> <out.json>\n")
        return 2
    try:
        with open(argv[1], encoding="utf-8") as fh:
            entries = convert(json.load(fh))
    except (OSError, ValueError) as e:
        sys.stderr.write("refused: %s\n" % e)
        return 2
    with open(argv[2], "w", encoding="utf-8", newline="\n") as fh:
        fh.write(dumps(entries))
    print("%d entries written to %s" % (len(entries), argv[2]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
