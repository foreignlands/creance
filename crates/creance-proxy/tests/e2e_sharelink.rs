#[test]
fn e2e_base64_sharelink_subscription_imports() {
    use base64::Engine;
    let lines = concat!(
        "ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388#node-a\n",
        "vless://11111111-2222-3333-4444-555555555555@cdn.example.com:443?security=reality&flow=xtls-rprx-vision&pbk=PUB&sid=aa&sni=x.com#node-b\n",
        "trojan://pw@t.example.com:443#node-c\n",
        "garbage line without scheme\n"
    );
    let blob = base64::engine::general_purpose::STANDARD.encode(lines);
    let (nodes, issues) = creance_proxy::import::parse_nodes(blob.as_bytes(), "testsrc").unwrap();
    assert_eq!(nodes.len(), 3, "expected 3 usable nodes, got {nodes:?}");
    assert!(
        !issues.is_empty(),
        "garbage line must surface as skipped issue"
    );
    let names: Vec<&str> = nodes.iter().map(|n| n.name.as_str()).collect();
    assert!(names.contains(&"node-a") && names.contains(&"node-b") && names.contains(&"node-c"));
    let b = nodes.iter().find(|n| n.name == "node-b").unwrap();
    assert_eq!(
        b.config.get("server").and_then(|v| v.as_str()),
        Some("cdn.example.com")
    );
}

#[test]
fn e2e_plaintext_sharelink_list_imports() {
    let text = "trojan://pw@t.example.com:443#only-node\n";
    let (nodes, _) = creance_proxy::import::parse_nodes(text.as_bytes(), "s").unwrap();
    assert_eq!(nodes.len(), 1);
}
