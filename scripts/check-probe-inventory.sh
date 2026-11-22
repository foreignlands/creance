#!/bin/sh
# check-probe-inventory.sh — probe-id inventory gate.
#
# F-063/065 lesson (three recurrences: 058 rename drift -> 063 dead probe
# listed -> 065 live probe missing): declaration surfaces drift when
# synced by hand. This gate diffs probe ids BOTH ways between the code
# and the ROADMAP inventory blocks:
#
#   guest side: literal `echo "PROBE <id>` emission sites in escape.rs
#               (parameterized `$` sites are excluded, like the host's
#               extractor; tokens ending in '-' are the sock-$s family)
#   host side:  `id: "<id>"` struct literals in escape.rs
#
# - every code-emitted id must be tracked in the ROADMAP blocks
#   (enforced or todo — an honest SKIP counts as tracked);
# - every id claimed as enforced must exist in the code (allowlisted
#   parameterized families excepted);
# - host block is checked in both directions too.
set -eu
cd "$(dirname "$0")/.."

fail=0

# NOTE: every id list below is normalized to a single SPACE-separated
# line — the `case " $list " in *" $id "*` membership idiom only works
# on space-delimited strings (sort -u emits newline-separated lines).
guest_code=$(grep -o 'echo "PROBE [a-z0-9-]*' crates/creance/src/escape.rs \
  | sed 's/^echo "PROBE //' | grep -v -- '-$' | sort -u | tr '\n' ' ' || true)
host_code=$(grep -o 'id: "[a-z0-9-]*"' crates/creance/src/escape.rs \
  | sed 's/^id: "//; s/"$//' | sort -u | tr '\n' ' ' || true)

block() { # block <file> <name> -> ids, split on '/' (blocks hold pure ids;
          # any annotation lives in the prose around the block, never
          # inside — BSD sed is byte-wise on multibyte chars, so stripping
          # （）here corrupts tokens)
  sed -n "/<!-- probe-inventory:$2 -->/,/<!-- \/probe-inventory:$2 -->/p" "$1" \
    | grep -v '<!--' \
    | tr '/' '\n' \
    | sed 's/^ *//; s/ *$//' \
    | grep -v '^$' \
    | sort -u | tr '\n' ' ' || true
}

guest_enforced=$(block ROADMAP.md guest-enforced)
guest_todo=$(block ROADMAP.md guest-todo)
host_enforced=$(block ROADMAP.md host-enforced)

# 1) every code-emitted guest id is tracked somewhere (enforced or todo)
tracked="$guest_enforced $guest_todo"
for id in $guest_code; do
  case " $tracked " in
    *" $id "*) ;;
    *) echo "FAIL: guest probe '$id' emitted by escape.rs but absent from ROADMAP inventory"; fail=1 ;;
  esac
done

# 2) every enforced guest id exists in code (parameterized families allowlisted)
guest_families='sock-docker·lima-guestagent'
for id in $guest_enforced; do
  case " $guest_code $guest_families " in
    *" $id "*) ;;
    *) echo "FAIL: ROADMAP enforces guest probe '$id' but escape.rs never emits it"; fail=1 ;;
  esac
done

# 3) host side, both directions
for id in $host_code; do
  case " $host_enforced " in
    *" $id "*) ;;
    *) echo "FAIL: host probe '$id' emitted by escape.rs but absent from ROADMAP host block"; fail=1 ;;
  esac
done
for id in $host_enforced; do
  case " $host_code " in
    *" $id "*) ;;
    *) echo "FAIL: ROADMAP host block claims '$id' but escape.rs never emits it"; fail=1 ;;
  esac
done

# 4) parameterized-family guard (F-066): the sock-$s family is invisible
#    to directions 1-2 by construction (ids are built at runtime), so
#    direction 2's allowlist is a free pass for it. Its emission site
#    must be textually present — deleting the probe has to fail HERE,
#    not pass silently (R16's NC6 lesson).
if ! grep -q 'echo "PROBE sock-\$s ESCAPE"' crates/creance/src/escape.rs; then
  echo "FAIL: sock-\$s family emission site missing from escape.rs (enforced socket probe silently removed?)"
  fail=1
fi

# 5) README surface (F-067): the third declaration surface, guarded the
#    same way — its enforced block must equal the code's enforced id set
#    (ids emitted by the code but tracked as honest-SKIP gaps, e.g.
#    sock-abstract, are excluded: present ≠ enforced). A ghost claim
#    (the deleted numeric endpoint survived four rounds here) and a
#    silently-missing probe both fail.
readme_enforced=$(block README.md readme-enforced)
enforced_guest=""
for id in $guest_code; do
  case " $guest_todo " in
    *" $id "*) ;; # tracked gap: probe present but honest-SKIP
    *) enforced_guest="$enforced_guest $id" ;;
  esac
done
expected_readme="$enforced_guest $host_code $guest_families"
for id in $readme_enforced; do
  case " $expected_readme " in
    *" $id "*) ;;
    *) echo "FAIL: README enforces probe '$id' but the code never emits it"; fail=1 ;;
  esac
done
for id in $expected_readme; do
  case " $readme_enforced " in
    *" $id "*) ;;
    *) echo "FAIL: README enforcement block is missing '$id' (code emits it)"; fail=1 ;;
  esac
done

if [ "$fail" = 0 ]; then
  echo "probe inventory: bidirectional diff empty (guest $(echo "$guest_code" | wc -w | tr -d ' ') code ids, host $(echo "$host_code" | wc -w | tr -d ' '))"
fi
exit $fail
