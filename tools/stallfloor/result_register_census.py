#!/usr/bin/env python3
"""ptxas's practice by RESULT register: the pair census of dep_latency_census.py for the fixed-latency producers that
write more than one register (IMAD.WIDE, MOV.64, CS2R, ...), split by which register of the result the consumer reads —
`low` (the first register) or `high` (any register above it).

Why: the census cell of a pair is the minimum over every reader, and the two halves of a 64-bit product are not ready
at the same time. Over the 166 frozen sm_120 listings ptxas reads the LOW register of an IMAD.WIDE result from 3 issue
cycles (-> LOP3 3 x 36, -> IADD3 second addend 3 x 8) and the HIGH register never below 5 (-> IADD3 5 x 2 100, -> SHFL
5 x 758, -> LOP3 5 x 8 of 12) or 4 into the multiplier (-> IMAD 4 x 403 / 4 x 808, -> the high half of the next
IMAD.WIDE's addend 4 x 354); silicon says the same (stall_floors_sm120_20261110_em_blk3.json: high 5 / 5 / 5 / 5 / 5 /
5 / 4 / 4 / 3 into IADD3 / LEA / LOP3 / SHF / MOV / SEL / ISETP / IMAD / STS data, low 3 / 3 / 3 / 3 / 2 / 2 / 2 / 1 / 1).
A cell mined from the merged pairs prices the high register with the low register's minimum where the low one is the
closer (IMAD.WIDE -> LOP3 / LEA / IADD3 second addend: 4 against 5).

Same walk, classes and roles as dep_latency_census.py (reset at unconditional transfers; variable-latency and MMA
producers are left out: a scoreboard or the MMA rows synchronise them).

usage: result_register_census.py out.json file.dep.jsonl [...]   (the .dep.jsonl files: `cargo run --example depdump`)
"""
import sys, json, collections, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dep_latency_census as C

VARIABLE = {"LDG", "LDS", "LDSM", "LDL", "LDC", "LDCU", "LD", "LDGSTS", "S2R", "S2UR", "MUFU", "SHFL", "ATOM", "ATOMG",
            "ATOMS", "RED", "REDG", "REDUX", "I2F", "F2I", "FLO", "POPC", "B2R", "TEX", "TLD", "TXQ", "LEPC", "GETLMEMBASE",
            "LDTM", "UTCATOMSWS"}
MMA = {"HMMA", "QMMA", "IMMA", "DMMA"}


def mine(path, agg, ex):
    D = {}
    clock = 0
    for line in open(path):
        j = json.loads(line)
        if j["i"] == 0:
            D.clear(); clock = 0
        cc = C.klass(j)
        seen = set()
        for cls, r, role in C.uses(j):
            if cls != "R":
                continue
            d = D.get(r)
            if d is None:
                continue
            pj, pclock = d
            pc = C.klass(pj)
            if pj["wb"] != 7 or len(pj["rd"]) < 2 or pc in VARIABLE or pc in MMA:
                continue
            key = (pc, "low" if r == min(pj["rd"]) else "high", cc, role)
            if (key, pj["i"]) in seen:
                continue
            seen.add((key, pj["i"]))
            dist = clock - pclock
            agg[key][min(dist, 40)] += 1
            e = ex.get(key)
            if e is None or dist < e[0]:
                ex[key] = (dist, path.split("/")[-1], pj["i"], pj["text"], j["i"], j["text"])
        d = (j, clock)
        for r in j["rd"]:
            D[r] = d
        clock += j["s"]
        g = j["guard"]
        if j["op"] in ("BRA", "JMP", "RET", "EXIT", "BRX", "JMX") and not (g and g["pred"] < 7):
            D.clear()


def main():
    out = sys.argv[1]
    agg = collections.defaultdict(collections.Counter)
    ex = {}
    for p in sorted(sys.argv[2:]):
        mine(p, agg, ex)
    rows = []
    for key, hist in agg.items():
        n = sum(hist.values()); mn = min(hist)
        rows.append(dict(prod=key[0], part=key[1], cons=key[2], role=key[3], n=n, min=mn, n_min=hist[mn],
                         hist={str(k): v for k, v in sorted(hist.items())}, example=ex[key]))
    rows.sort(key=lambda r: (r["prod"], r["cons"], r["role"], r["part"]))
    with open(out, "w") as f:
        f.write("[\n" + ",\n".join(" " + json.dumps(r) for r in rows) + "\n]\n")
    print(f"{len(rows)} rows, {sum(r['n'] for r in rows)} pairs")


if __name__ == "__main__":
    main()
