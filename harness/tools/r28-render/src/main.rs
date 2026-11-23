// usage: r28-render bootstrap|rules|probe qemu|lima
fn main() {
    let a: Vec<String> = std::env::args().collect();
    let hosts = match a.get(2).map(String::as_str) {
        Some("lima") => creance_vm::vm::NAT_HOSTS_LIMA,
        _ => creance_vm::vm::NAT_HOSTS_QEMU,
    };
    match a.get(1).map(String::as_str) {
        Some("bootstrap") => print!(
            "{}",
            creance_vm::provision::guest_bootstrap("en_US.UTF-8", "UTC", "en-US", "tok", "h", "u", hosts)
        ),
        Some("rules") => print!("{}", creance_vm::provision::rules_v4_text(hosts)),
        _ => print!("{}", creance::escape::egress_probe_script(hosts)),
    }
}
