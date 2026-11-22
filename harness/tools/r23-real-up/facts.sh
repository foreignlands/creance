export PATH=/usr/bin:/bin
echo "id: $(id)"
echo "--- /run/egress-armed:"; ls -l --time-style=+%FT%T /run/egress-armed; stat -c 'mtime=%y owner=%U mode=%a' /run/egress-armed; cat /run/egress-armed
echo "--- /run perms: $(stat -c '%U %a' /run)"
echo "--- egress-lock: active=$(systemctl is-active egress-lock.service) enabled=$(systemctl is-enabled egress-lock.service)"
systemctl show egress-lock.service -p ExecStartPost -p ExecMainStartTimestamp -p ActiveEnterTimestamp -p Result -p NRestarts --no-pager
echo "--- boot: $(cat /proc/sys/kernel/random/boot_id) uptime=$(cut -d' ' -f1 /proc/uptime)"
echo "--- cloud-init: $(cloud-init status 2>&1 | head -1)"
echo "--- probe fw line:"; if [ -f /run/egress-armed ] && grep -q '^:OUTPUT DROP' /run/egress-armed && ! grep -qxF -- '-A OUTPUT -j ACCEPT' /run/egress-armed; then echo fw-armed; else echo fw-down; fi
echo "--- write attempt: $(sh -c ': > /run/egress-armed' 2>&1 || true)"
echo "--- direct tcp: $(/usr/bin/timeout 5 /bin/bash -c '</dev/tcp/1.1.1.1/443' 2>/dev/null && echo open || echo blocked)"
echo "--- sudo: $(sudo -n true 2>&1 | head -1)"
