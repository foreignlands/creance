#!/bin/sh
# r31-shell-semantics — does each NC-HD* injection really stop the bootstrap before the rules heredoc under dash?
# usage: SH=dash sh check.sh   (prints REACHED / NOT-REACHED per injection)
SH=${SH:-dash}
run() { name=$1; inj=$2
  printf 'set -eu\n%s\ncat > /dev/null <<'"'"'EGRESSRULES'"'"'\n*filter\nEGRESSRULES\necho REACHED\n' "$inj" > /tmp/r31-sem.$$
  out=$($SH /tmp/r31-sem.$$ 2>&1); echo "$name: ${out:-NOT-REACHED} (rc=$?)"; rm -f /tmp/r31-sem.$$; }
run HDindent ": <<'SKIPRULES'
 SKIPRULES"
run HDexec "exec true"
run HDandexit "true && exit 0"
run HDfalse "false"
run control ":"
