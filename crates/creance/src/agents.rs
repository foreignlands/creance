//! 声明式 agent 注册表（0.8.5 工作台）：左侧面板的数据源。
//! 设计原则（PRODUCT-DEEP-0.8）：接入点是数据不是逐 agent 工程——
//! cli 类 = 安装命令 + 启动命令；desktop 类 = Xvnc 应用通道；
//! web 类 = 内置浏览器。懒安装：点图标=装，再点=开。
//!
//! 安全纪律：install/launch 命令在 guest 内执行（经 ssh 通道），
//! 永远不在 host 执行；命令模板是编译期常量不是用户输入，无注入面。

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentEntry {
    pub id: &'static str,
    pub name: &'static str,
    /// cli | desktop | web
    pub kind: &'static str,
    /// guest 内检测是否已安装的命令（which/存在性检查）
    pub detect: &'static str,
    /// guest 内安装命令（bash -c 执行）；空=需手工安装，UI 给指引
    pub install: &'static str,
    /// guest 内启动命令；cli 类在终端里跑，desktop 类经 Xvnc 通道
    pub launch: &'static str,
    /// 接入依据（开源/官方 linux 版），UI 存疑时给用户看
    pub note: &'static str,
}

/// 首期内置注册表。核实口径（2026-11-27 联网核实）：
/// 全部开源或有官方 Linux 渠道；star 数为那时值。
pub const REGISTRY: &[AgentEntry] = &[
    AgentEntry {
        id: "claude-code",
        name: "Claude Code",
        kind: "cli",
        detect: "which claude",
        install: "curl -fsSL https://claude.ai/install.sh | bash",
        launch: "claude",
        note: "官方 CLI；OAuth 授权走内置浏览器通道",
    },
    AgentEntry {
        id: "codex",
        name: "Codex CLI",
        kind: "cli",
        detect: "which codex",
        install: "npm install -g @openai/codex",
        launch: "codex",
        note: "开源（openai/codex，136k★）",
    },
    AgentEntry {
        id: "opencode",
        name: "opencode",
        kind: "cli",
        detect: "which opencode",
        install: "curl -fsSL https://opencode.ai/install | bash",
        launch: "opencode",
        note: "开源（sst/opencode，229k★）",
    },
    AgentEntry {
        id: "gemini-cli",
        name: "Gemini CLI",
        kind: "cli",
        detect: "which gemini",
        install: "npm install -g @google/gemini-cli",
        launch: "gemini",
        note: "开源（google-gemini/gemini-cli，109k★）",
    },
    AgentEntry {
        id: "aider",
        name: "aider",
        kind: "cli",
        detect: "which aider",
        install: "pip install aider-chat || pipx install aider-chat",
        launch: "aider",
        note: "开源（paul-gauthier/aider，50k★）",
    },
    AgentEntry {
        id: "goose",
        name: "goose",
        kind: "cli",
        detect: "which goose",
        install: "curl -fsSL https://github.com/block/goose/releases/latest/download/install.sh | bash",
        launch: "goose",
        note: "开源（block/goose，57k★）",
    },
    AgentEntry {
        id: "antigravity",
        name: "Antigravity",
        kind: "desktop",
        detect: "test -d /opt/antigravity || which antigravity",
        install: "",
        launch: "antigravity",
        note: "官方 Linux 桌面版；需手工装一次。若提示未装而实际已装，可能是老 provision 缺桌面资产——重建环境",
    },
    AgentEntry {
        id: "browser",
        name: "浏览器",
        kind: "web",
        // web/desktop 类检测的是串流基础设施而非应用二进制——
        // 缺基础设施=老 provision，错误文案指向重建环境而非手工安装
        // -f 而非 -x：调用永远经 `sh <script>` 不需要执行位
        // （0.8.9 实测：旧 provision chmod 漏了它，-x 误杀所有老 guest）
        detect: "test -f /usr/local/bin/creance-oauth",
        install: "",
        launch: "chromium",
        note: "内置浏览器通道——OAuth 授权与网页访问",
    },
    AgentEntry {
        id: "terminal",
        name: "终端",
        kind: "cli",
        detect: "true",
        install: "",
        launch: "bash",
        note: "guest 内的裸 shell",
    },
    AgentEntry {
        id: "kiro",
        name: "Kiro CLI",
        kind: "cli",
        detect: "which kiro",
        install: "",
        launch: "kiro",
        note: "亚马逊；Linux 版核实中（0.8.6）",
    },
];

pub fn registry_json() -> serde_json::Value {
    serde_json::json!(
        REGISTRY
            .iter()
            .map(|a| serde_json::json!({
                "id": a.id, "name": a.name, "kind": a.kind,
                "installable": !a.install.is_empty(), "note": a.note,
            }))
            .collect::<Vec<_>>()
    )
}

pub fn find(id: &str) -> Option<&'static AgentEntry> {
    REGISTRY.iter().find(|a| a.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_ids_unique_and_kinds_valid() {
        let mut seen = std::collections::HashSet::new();
        for a in REGISTRY {
            assert!(seen.insert(a.id), "dup id {}", a.id);
            assert!(matches!(a.kind, "cli" | "desktop" | "web"));
            assert!(!a.launch.is_empty());
            assert!(!a.detect.is_empty());
        }
    }

    #[test]
    fn commands_carry_no_shell_interpolation_points() {
        // 安装/启动命令是常量模板；若未来支持参数化，必须走 argv 而非拼接
        for a in REGISTRY {
            assert!(
                !a.install.contains("${"),
                "{} install has interpolation",
                a.id
            );
            assert!(
                !a.launch.contains("${"),
                "{} launch has interpolation",
                a.id
            );
        }
    }
}
