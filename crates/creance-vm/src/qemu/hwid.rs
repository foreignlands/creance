//! Hardware signature scrubbing (anti-fingerprint): a persona-seeded OEM
//! identity for the guest, so its DMI tables, CPUID and NIC MAC read like
//! a commodity laptop, not a QEMU appliance.
//!
//! Detection vectors this covers:
//! - `dmidecode`/`/sys/class/dmi/id/*`: manufacturer/product/version/serial
//!   default to "QEMU"/"Standard PC" — we hand out a seeded OEM identity.
//! - `/proc/cpuinfo`: `-cpu host` leaks the KVM signature leaf (0x40000000)
//!   and the `hypervisor` flag bit — `kvm=off,-hypervisor` hides both, and
//!   dmesg prints "bare hardware" instead of "paravirtualized on KVM".
//! - NIC MAC: QEMU's default OUI 52:54:00 names the card on sight — we use
//!   a real-vendor OUI plus a seeded tail, and the e1000 model reads as a
//!   plain Intel adapter under lspci.
//!
//! The signature is DERIVED from the instance id: stable across reboots,
//! and `identity-reset` (new instance id) rotates it — one identity, one
//! chassis. Nothing is random-per-boot: a VM whose serial changed between
//! boots would look faker than QEMU.
//!
//! Honest residuals: virtio-blk, virtio-rng and virtio-9p stay — they are
//! functional (root disk, entropy, the workspace share) and replacing them
//! breaks the guest. `/sys/firmware/acpi/tables` keeps SeaBIOS' "BOCHS"
//! OEM ids — QEMU cannot override the builtin DSDT header. These are the
//! documented edges of the emulation layer.

/// One OEM identity in the rotation pool.
struct Oem {
    manufacturer: &'static str,
    product: &'static str,
    family: &'static str,
    board: &'static str,
    chassis: &'static str,
    bios_vendor: &'static str,
    bios_version: &'static str,
    mac_oui: &'static str,
}

const OEMS: &[Oem] = &[
    Oem {
        manufacturer: "Dell Inc.",
        product: "Latitude 5540",
        family: "Latitude",
        board: "0X7J2T",
        chassis: "10",
        bios_vendor: "Dell Inc.",
        bios_version: "1.14.2",
        mac_oui: "00:14:22",
    },
    Oem {
        manufacturer: "LENOVO",
        product: "21HDS1C900",
        family: "ThinkPad T14 Gen 4",
        board: "21HDS1C900",
        chassis: "10",
        bios_vendor: "LENOVO",
        bios_version: "N3CET58W (1.35 )",
        mac_oui: "68:F7:28",
    },
    Oem {
        manufacturer: "HP",
        product: "EliteBook 840 G10 Notebook PC",
        family: "103C_5336AN HP EliteBook",
        board: "8A41",
        chassis: "10",
        bios_vendor: "HP",
        bios_version: "V72 Ver. 01.03.05",
        mac_oui: "3C:D9:2B",
    },
    Oem {
        manufacturer: "ASUSTeK COMPUTER INC.",
        product: "Zenbook UX3405MA",
        family: "Zenbook",
        board: "UX3405MA",
        chassis: "10",
        bios_vendor: "American Megatrends Inc.",
        bios_version: "UX3405MA.308",
        mac_oui: "04:92:26",
    },
    Oem {
        manufacturer: "Acer",
        product: "Swift SF314-512",
        family: "Swift 3",
        board: "Sake_CA",
        chassis: "10",
        bios_vendor: "Insyde Corp.",
        bios_version: "V1.12",
        mac_oui: "00:1F:16",
    },
];

/// FNV-1a over the instance id — stable forever, unlike DefaultHasher.
fn seed(id: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in id.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

const BASE32: &[u8] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";

fn b32(mut v: u64, len: usize) -> String {
    let mut out = String::with_capacity(len);
    for _ in 0..len {
        out.push(BASE32[(v & 31) as usize] as char);
        v >>= 5;
    }
    out
}

/// The guest's OEM identity for one instance. All strings are safe to
/// embed in `-smbios`/`mac=` fields (pool literals plus hex/base32).
pub struct Signature {
    pub smbios_type0: String,
    pub smbios_type1: String,
    pub smbios_type2: String,
    pub smbios_type3: String,
    pub mac: String,
}

pub fn signature(instance_id: &str) -> Signature {
    let h = seed(instance_id);
    let oem = &OEMS[(h % OEMS.len() as u64) as usize];
    let serial = b32(h / 7, 7);
    let board_serial = b32(h / 13, 10);
    let chassis_serial = b32(h / 17, 8);
    // Version-4 UUID from the hash — a fresh identity per instance.
    let mut u = [0u8; 16];
    for (i, b) in u.iter_mut().enumerate() {
        *b = (h.rotate_left(i as u32 * 5).wrapping_add(i as u64) & 0xff) as u8;
    }
    u[6] = (u[6] & 0x0f) | 0x40;
    u[8] = (u[8] & 0x3f) | 0x80;
    let uuid = format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7], u[8], u[9], u[10], u[11], u[12], u[13],
        u[14], u[15]
    );
    // The MAC tail uses different hash bits than the uuid tail — a MAC
    // that literally shares bytes with the product UUID advertises the
    // derivation scheme.
    let mac = format!(
        "{}:{:02X}:{:02X}:{:02X}",
        oem.mac_oui,
        (h >> 24) & 0xff,
        (h >> 32) & 0xff,
        (h >> 40) & 0xff
    );
    Signature {
        smbios_type0: format!(
            "type=0,vendor={},version={},date=06/15/2024,release=2.7",
            oem.bios_vendor, oem.bios_version
        ),
        smbios_type1: format!(
            "type=1,manufacturer={},product={},version={},serial={},uuid={},family={}",
            oem.manufacturer, oem.product, serial, serial, uuid, oem.family
        ),
        smbios_type2: format!(
            "type=2,manufacturer={},product={},version=0,serial={}",
            oem.manufacturer, oem.board, board_serial
        ),
        // NB: type 3's chassis `type` field cannot be spelled on the CLI —
        // a second `type=` collides with the table selector, so the
        // chassis form stays QEMU's default. Everything else is ours.
        smbios_type3: format!(
            "type=3,manufacturer={},version={},serial={},asset={},sku={}",
            oem.manufacturer, serial, chassis_serial, oem.chassis, oem.family
        ),
        mac,
    }
}

/// The CPU line: `kvm=off` drops the KVM CPUID signature leaf (the
/// "KVMKVMKVM" string), `-hypervisor` clears the hypervisor flag bit —
/// `/proc/cpuinfo` then shows the host's real model as bare metal.
pub fn cpu_model() -> &'static str {
    "host,kvm=off,-hypervisor"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_is_deterministic_and_rotates_with_identity() {
        let a = signature("iid-one");
        let a2 = signature("iid-one");
        let b = signature("iid-two");
        assert_eq!(a.mac, a2.mac);
        assert_ne!(a.smbios_type1, b.smbios_type1);
        assert!(!a.smbios_type1.contains("QEMU"));
        assert!(!a.smbios_type0.contains("SeaBIOS"));
        assert!(a.smbios_type1.contains("uuid="));
        // MAC = vendor OUI + 3 seeded bytes, never 52:54:00.
        assert!(!a.mac.starts_with("52:54:00"));
        assert_eq!(a.mac.len(), 17);
    }

    #[test]
    fn cpu_hides_hypervisor_and_kvm_leaves() {
        let cpu = cpu_model();
        assert!(cpu.contains("kvm=off"));
        assert!(cpu.contains("-hypervisor"));
        assert!(cpu.starts_with("host"));
    }

    #[test]
    fn smbios_fields_have_no_arg_injection() {
        for id in ["x", "iid-any", "creance-ws-01"] {
            let sig = signature(id);
            for field in [
                sig.smbios_type0,
                sig.smbios_type1,
                sig.smbios_type2,
                sig.smbios_type3,
                sig.mac,
            ] {
                assert!(!field.contains('\n') && !field.contains('\0'), "{field}");
                // `-smbios` fields are comma-separated k=v — a comma inside
                // a value splits it into a bogus key and qemu exits (seen
                // live with "American Megatrends International, LLC.").
                for kv in field.split(',').skip(1) {
                    assert!(kv.contains('='), "comma-broken field: {kv}");
                }
            }
        }
    }
}
