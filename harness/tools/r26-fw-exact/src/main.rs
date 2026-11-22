// usage: r26-fw-exact probe|rules qemu|lima
fn main() {
    let a: Vec<String> = std::env::args().collect();
    let hosts = match a.get(2).map(String::as_str) {
        Some("lima") => creance_vm::vm::NAT_HOSTS_LIMA,
        _ => creance_vm::vm::NAT_HOSTS_QEMU,
    };
    match a.get(1).map(String::as_str) {
        Some("rules") => {
            let s = creance_vm::provision::guest_bootstrap(
                "en_US.UTF-8", "UTC", "en-US", "tok", "h", "u", hosts,
            );
            let b = s.find("<<'EGRESSRULES'\n").unwrap() + "<<'EGRESSRULES'\n".len();
            let e = s[b..].find("\nEGRESSRULES\n").unwrap();
            println!("{}", &s[b..b + e]);
        }
        _ => print!("{}", creance::escape::egress_probe_script(hosts)),
    }
}
