export PATH=/usr/bin:/bin
if /usr/bin/timeout 1 /bin/true; then /usr/bin/timeout 5 /bin/bash -c '</dev/tcp/1.1.1.1/443' 2>/dev/null && echo tcp-open || echo tcp-blocked; else echo tcp-unknown; fi
if [ -x /usr/bin/ping ]; then /usr/bin/timeout 3 /usr/bin/ping -c1 -W2 1.1.1.1 >/dev/null 2>&1 && echo icmp-open || echo icmp-blocked; else echo icmp-unknown; fi
STAMP=${CREANCE_STAMP:-/run/egress-armed}; WANT=${CREANCE_RULES:-/etc/iptables/rules.v4}
ok=0
if [ -f "$STAMP" ] && [ -f "$WANT" ] && grep -q '^:OUTPUT DROP' "$STAMP" && grep -q '^:OUTPUT DROP' "$WANT"; then
rem=$(cat "$STAMP" "$WANT" | grep -E '^-A OUTPUT' | grep -Ev -- '^-A OUTPUT -o lo -j ACCEPT$|^-A OUTPUT .*conntrack --ctstate .*ESTABLISHED.*-j ACCEPT$')
bad=$(printf '%s\n' "$rem" | grep -v '^$' | grep -Ev -- '-j ACCEPT$')
[ -n "$bad" ] || bad=$(printf '%s\n' "$rem" | grep -v '^$' | grep -Ev -- '-d ((10\.0\.2\.2|10\.0\.2\.3)/32|255\.255\.255\.255(/32)?) ')
[ -n "$bad" ] || bad=$(printf '%s\n' "$rem" | grep -v '^$' | grep -Ev -- '-p udp.*--dport 67|--dport 67.*-p udp|-p icmp')
[ -z "$bad" ] && ok=1
fi
if [ "$ok" = 1 ]; then echo fw-armed; else echo fw-down; fi
