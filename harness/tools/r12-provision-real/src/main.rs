//! R12 探针（F-055 修复面第三档验证）：真实生成文本 + dash 实机执行。
//! 见 Cargo.toml 头注。Rust 只负责产文本；执行与判定在 run.sh。

use creance_vm::lima::{generate_lima_yaml, SetupOptions};

fn main() {
    let out_dir = std::env::args()
        .nth(1)
        .expect("usage: r12-provision-real <out-dir>");

    let opts = SetupOptions {
        // 绝对路径即可；真实性只关乎 provision 脚本文本，mount 本身不执行。
        workspace: "/tmp/r12-f055-ws".to_owned(),
        ..Default::default()
    };
    let yaml = generate_lima_yaml(&opts).expect("generate_lima_yaml ok");
    let text = String::from_utf8(yaml).expect("yaml utf8");
    let v: serde_yaml::Value = serde_yaml::from_str(&text).expect("yaml parse");
    let script = v["provision"][0]["script"]
        .as_str()
        .expect("provision script is a string")
        .to_owned();

    // 1) 逐字节原文（对照基准）
    std::fs::write(format!("{out_dir}/real-byte-exact.sh"), &script)
        .expect("write real-byte-exact.sh");

    // 2) 可执行变体：仅把 /etc/… 绝对目标重写进 rootfs（宿主 /etc
    //    不可写，且裸跑会在第一个重定向处中止）。六类路径重写，
    //    工具链段（sh -c '…'）字节不动。
    let rootfs = format!("{out_dir}/rootfs");
    let exe = script
        .replace(
            "/etc/profile.d/session-env.sh",
            &format!("{rootfs}/etc/profile.d/session-env.sh"),
        )
        .replace(
            "/etc/sysctl.d/99-creance-noipv6.conf",
            &format!("{rootfs}/etc/sysctl.d/99-creance-noipv6.conf"),
        )
        .replace(
            "/etc/iptables/rules.v4",
            &format!("{rootfs}/etc/iptables/rules.v4"),
        )
        .replace(
            "/etc/systemd/system/egress-lock.service",
            &format!("{rootfs}/etc/systemd/system/egress-lock.service"),
        )
        .replace(
            "/etc/sudoers.d/90-cloud-init-users",
            &format!("{rootfs}/etc/sudoers.d/90-cloud-init-users"),
        );
    std::fs::write(format!("{out_dir}/real-exec.sh"), &exe).expect("write real-exec.sh");

    // 3) 旧洞负控变体：把修复形态回退成 ca22ea2 的跨引号展开
    let oldbug = exe.replace(
        "node-v22.14.0-linux-$ARCH/bin/node",
        "node-v22.14.0-linux-'\"$ARCH\"'/bin/node",
    );
    std::fs::write(format!("{out_dir}/oldbug-exec.sh"), &oldbug).expect("write oldbug-exec.sh");

    // 4) 工具链段提取（与 r11 探针对 diff 用）
    let start = script
        .find("timeout \"$TOOLCHAIN_BUDGET\"")
        .expect("toolchain segment start");
    let end = script.find("' || true").expect("toolchain segment end") + "' || true".len();
    std::fs::write(format!("{out_dir}/segment-real.txt"), format!("{}\n", &script[start..end]))
        .expect("write segment-real.txt");

    println!("{out_dir}");
}
