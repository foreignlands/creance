fn truncate_utf8(s: &str, max: usize) -> &str {
    match s.char_indices().nth_back(s.chars().count().saturating_sub(max)) {
        Some((i, _)) if s.len() > max => &s[..i.min(s.len())],
        _ if s.len() <= max => s,
        _ => s,
    }
}
fn main() {
    // ASCII 300B
    let a = "x".repeat(300);
    println!("ascii300 -> {}B", truncate_utf8(&a, 200).len());
    // 150 chars × 3B = 450B（CJK）
    let c: String = " cage·好".chars().take(1).cycle().take(150).collect();
    let c: String = "好".repeat(150);
    println!("cjk150x3B({}B) -> {}B", c.len(), truncate_utf8(&c, 200).len());
    // 100 chars × 3B = 300B
    let c3 = "好".repeat(100);
    println!("cjk100({}B) -> {}B", c3.len(), truncate_utf8(&c3, 200).len());
    // 300 chars × 3B = 900B
    let c4 = "好".repeat(300);
    println!("cjk300({}B) -> {}B", c4.len(), truncate_utf8(&c4, 200).len());
    // emoji 4B
    let e = "😀".repeat(100); // 400B, 100 chars
    println!("emoji100({}B) -> {}B", e.len(), truncate_utf8(&e, 200).len());
}
