export PATH=/usr/bin:/bin
echo "id: $(id)"
echo "--- /run/egress-armed: $(stat -c 'mtime=%y owner=%U mode=%a' /run/egress-armed)"; cat /run/egress-armed
echo "--- rules.v4 OUTPUT: $(stat -c 'owner=%U mode=%a' /etc/iptables/rules.v4)"; grep -E '^:OUTPUT|^-A OUTPUT' /etc/iptables/rules.v4
echo "--- egress-lock: active=$(systemctl is-active egress-lock.service) enabled=$(systemctl is-enabled egress-lock.service)"
echo "--- boot: $(cat /proc/sys/kernel/random/boot_id)"
echo "--- write attempts: stamp=[$(sh -c ': > /run/egress-armed' 2>&1 || true)] rules=[$(sh -c ': >> /etc/iptables/rules.v4' 2>&1 || true)]"
echo "--- direct tcp: $(/usr/bin/timeout 5 /bin/bash -c '</dev/tcp/1.1.1.1/443' 2>/dev/null && echo open || echo blocked)"
echo "--- sudo: $(sudo -n true 2>&1 | head -1)"
