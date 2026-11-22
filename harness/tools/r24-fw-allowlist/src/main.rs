fn main() {
    let hosts = match std::env::args().nth(1).as_deref() {
        Some("lima") => creance_vm::vm::NAT_HOSTS_LIMA,
        Some("qemu") => creance_vm::vm::NAT_HOSTS_QEMU,
        _ => creance_vm::vm::nat_allow_hosts(),
    };
    print!("{}", creance::escape::egress_probe_script(hosts));
}
