#!/usr/bin/env python3
"""Step 5 (after the freeze): our frozen raw outputs vs babyblueviper1's transcript at be2a291, vector by vector."""
import ast, json, re, sys
tr = open(sys.argv[1], encoding="utf-8").read().splitlines()
g = {x["id"]: x for x in json.load(open(sys.argv[2], encoding="utf-8"))["results"]}
rows = []
for ln in tr:
    m = re.match(r"^(AGREE|DIFF\w*|DISAGREE)\s+(\S+)\s+(.*)$", ln)
    if not m:
        continue
    status, vid, rest = m.groups()
    o = g[vid]; r = o["result"]
    if o["kind"] == "root":
        hx = re.findall(r"(root(?:_\d)?) ([0-9a-f]{12})", rest)
        ours = {k: (r[k][:12] if r.get(k) else None) for k, _ in hx}
        if "want" in rest:  # "root X want Y": his root is the first
            ours = {"root": r["root"][:12]}; hx = hx[:1]
        same = all(ours[k] == v for k, v in hx)
        rows.append({"id": vid, "his": rest, "ours": ours, "same": same, "aspect": "root prefixes"})
        continue
    tok = rest.split()[0]
    lst = re.search(r"\[(.*?)\]", rest)
    his_list = ast.literal_eval("[" + lst.group(1) + "]") if lst else None
    if tok == "halt":
        same = r["outcome"] == "malformed" and sorted(his_list) == r["conditions"]
        rows.append({"id": vid, "his": rest, "ours": [r["outcome"], r["conditions"]], "same": same, "aspect": "halt + condition set"})
    else:
        same_tok = r["outcome"] == tok
        same_items = True if not his_list else his_list == r["per_item"]
        rows.append({"id": vid, "his": rest, "ours": [r["outcome"], r["per_item"]], "same": same_tok and same_items,
                     "aspect": "token" + (" + per-item" if his_list else ""), "his_status": status})
print(json.dumps({"vectors": len(rows), "same": sum(x["same"] for x in rows),
                  "differ": [x for x in rows if not x["same"]]}, indent=1))
json.dump(rows, open(sys.argv[3], "w"), indent=1, sort_keys=True)
