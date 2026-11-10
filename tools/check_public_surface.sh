#!/usr/bin/env bash
# Public surface gate: `main` is the only canonical branch of the public remote.
#
# Since 2026-11-10 three namespaces may carry review candidates next to it -- work published for review, never canon,
# reaching `main` only as commits that passed the push gate:
#
#   hidden-b300/*    one-commit candidate pairs of the B300 measurement lane (cubit + blackwell-isa)
#   barracuda/*      head branches of pull requests from the sm_103a scheduler work
#   k31-prefill/*    the K3.1 prefill-gap candidates
#
# Heads in these namespaces are reported, not an error. Any other head fails the gate, and so does a missing `main`.
# Usage: tools/check_public_surface.sh [remote]   (default: origin)
set -euo pipefail
remote="${1:-origin}"
heads=$(git ls-remote --heads "$remote" | awk '{print $2}' | sed 's#^refs/heads/##')
main=0
other=""
declare -A candidates=()
while IFS= read -r head; do
    [ -n "$head" ] || continue
    case "$head" in
        main) main=1 ;;
        hidden-b300/* | barracuda/* | k31-prefill/*) ns="${head%%/*}"; candidates[$ns]=$(( ${candidates[$ns]:-0} + 1 )) ;;
        *) other+="$head"$'\n' ;;
    esac
done <<< "$heads"
if [ "$main" -ne 1 ]; then
    echo "public remote '$remote' has no main branch" >&2
    exit 1
fi
if [ -n "$other" ]; then
    echo "unexpected public branches (neither main nor a review-candidate namespace):" >&2
    printf '%s' "$other" >&2
    exit 1
fi
report=""
for ns in hidden-b300 barracuda k31-prefill; do
    [ -n "${candidates[$ns]:-}" ] && report+=" ${candidates[$ns]} x $ns/*,"
done
if [ -n "$report" ]; then
    echo "public surface OK: main + review candidates (not canon):${report%,}"
else
    echo "public surface OK: main only"
fi
