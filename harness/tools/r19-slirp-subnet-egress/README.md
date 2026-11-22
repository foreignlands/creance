# r19-slirp-subnet-egress

R19：在真实 QEMU slirp guest（Ubuntu 24.04 cloud image）里逐字套用 provision.rs 的
`/etc/iptables/rules.v4`，以非特权用户向 192.168.5.0/24（Lima usernet 网段，非 slirp
网段）发 UDP/67 与带载荷 ICMP，宿主 tcpdump 断言是否离开宿主网卡（F-073）。
用法：`sh run.sh`（需 qemu-system-x86_64、genisoimage、tcpdump、sudo -n、/dev/kvm；
`R19_IMG` 指向已下载的 cloud image，`R19_IFACE` 默认 any）。
