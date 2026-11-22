# runs inside the netns as root: per destination, did the packet hit the OUTPUT policy DROP? (policy counter delta)
pd() { iptables -L OUTPUT -n -v -x | sed -n '1s/.*policy DROP \([0-9]*\) packets.*/\1/p'; }
chk() { a=$(pd); "$@" >/dev/null 2>&1; b=$(pd); [ "$a" = "$b" ] && echo PASS || echo DROP; }
printf 'udp/8.8.8.8:53=%s ' "$(chk timeout 1 bash -c 'echo x > /dev/udp/8.8.8.8/53')"
printf 'udp/8.8.8.8:5353=%s ' "$(chk timeout 1 bash -c 'echo x > /dev/udp/8.8.8.8/5353')"
printf 'tcp/1.1.1.1:443=%s ' "$(chk timeout 1 bash -c '</dev/tcp/1.1.1.1/443')"
printf 'tcp/10.0.2.2:22=%s ' "$(chk timeout 1 bash -c '</dev/tcp/10.0.2.2/22')"
printf 'icmp/1.1.1.1=%s\n' "$(chk timeout 1 ping -c1 -W1 1.1.1.1)"
