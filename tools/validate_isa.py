#!/usr/bin/env python3
"""ISA table validator for sm120.json.

Reports structural issues without modifying the table.
Use as CI gate: exits non-zero if critical issues found.

Usage:
    python3 tools/validate_isa.py                    # report all
    python3 tools/validate_isa.py --critical-only     # only blocking issues
    python3 tools/validate_isa.py --entry IMAD_R_R_R_UR  # single entry
"""

import json, sys, argparse
from collections import Counter

OP_TYPES = ['ARURI','cAI','dARI','ARI','UP','UR','SR','FI','II','IM','LO','R','P','L','B','?']
MODIFIER_EXTS = ('neg','abs','reuse','inv','','none','guard','guard_neg')

def parse_op_types(key):
    parts = key.split('_')
    ops = []
    in_ops = False
    for p in parts:
        if not in_ops and p in OP_TYPES: in_ops = True
        if in_ops: ops.append(p)
    return ops

def validate_entry(key, mg, md):
    """Validate a single (key, mod_group) entry. Returns list of (severity, message)."""
    issues = []
    fields = md.get('fields', [])
    if not fields:
        return issues
    
    op_types = parse_op_types(key)
    
    # 1. Duplicate token_idx for operand fields
    tok_map = {}
    for f in fields:
        if f['extraction'] in MODIFIER_EXTS: continue
        k = (f.get('token_idx'), f['extraction'])
        tok_map.setdefault(k, []).append(f)
    for (tok, ext), flist in tok_map.items():
        if len(flist) > 1:
            shifts = [f['shift'] for f in flist]
            issues.append(('warn', f"DUP_TOK tok={tok} ext={ext} at shifts {shifts}"))
    
    # 2. Overlapping bit ranges between different tokens
    bits = {}
    for f in fields:
        for b in range(f['shift'], min(f['shift']+f['bits'], 128)):
            if b in bits:
                other_tok = bits[b]
                if other_tok != f.get('token_idx'):
                    issues.append(('warn', f"OVERLAP bit {b}: tok={other_tok} vs tok={f.get('token_idx')}"))
                    break
            bits[b] = f.get('token_idx')
    
    # 3. Missing Rd field
    if op_types and op_types[0] in ('R', 'UR'):
        has_rd = any(f['shift'] == 16 and f['extraction'] in ('reg','ureg') 
                    and f.get('token_idx') == 1 for f in fields)
        if not has_rd:
            issues.append(('info', "NO_RD: missing Rd@16 tok=1"))
    
    # 4. Operand fields at tok=0
    for f in fields:
        if f.get('token_idx') == 0 and f['extraction'] in ('reg','ureg','pred','upred','imm','f32'):
            issues.append(('info', f"TOK0_OP: {f['extraction']}@{f['shift']} at tok=0"))
    
    # 5. Extraction type mismatch with InsKey operand type
    for f in fields:
        tok = f.get('token_idx', 0)
        if tok < 1 or tok > len(op_types): continue
        expected = op_types[tok-1]
        ext = f['extraction']
        if expected == 'R' and ext == 'ureg':
            issues.append(('warn', f"TYPE_MISMATCH: tok={tok} key says R but field is ureg@{f['shift']}"))
        elif expected == 'UR' and ext == 'reg' and f['shift'] in (16,24):
            issues.append(('warn', f"TYPE_MISMATCH: tok={tok} key says UR but field is reg@{f['shift']}"))
    
    return issues

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--table', default='tables/sm120.json')
    ap.add_argument('--critical-only', action='store_true')
    ap.add_argument('--entry', type=str, default=None)
    ap.add_argument('--summary', action='store_true')
    args = ap.parse_args()
    
    t = json.load(open(args.table))
    
    totals = Counter()
    all_issues = []
    
    for k, v in sorted(t['instructions'].items()):
        if args.entry and k != args.entry:
            continue
        for mg, md in v.get('mod_groups', {}).items():
            issues = validate_entry(k, mg, md)
            for sev, msg in issues:
                totals[sev] += 1
                if not args.critical_only or sev == 'error':
                    all_issues.append(f"[{sev:5s}] {k}[{mg}]: {msg}")
    
    if args.summary:
        print(f"ISA Table: {sum(totals.values())} issues ({totals['error']} errors, {totals['warn']} warnings, {totals['info']} info)")
    else:
        for issue in all_issues:
            print(issue)
        print(f"\n{'='*60}")
        print(f"Total: {sum(totals.values())} issues")
        for sev in ('error','warn','info'):
            if totals[sev]:
                print(f"  {sev}: {totals[sev]}")
    
    return 1 if totals.get('error', 0) > 0 else 0

if __name__ == '__main__':
    sys.exit(main())
