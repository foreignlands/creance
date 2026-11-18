//! 库层验证：超 i64/u64 范围的整数标量是否让 serde_yaml 0.9.34 from_slice 失败。
fn main() {
    for y in [
        "a: 99999999999999999999\n",
        "a: 123456789012345678901234567890\n",
        "a: -99999999999999999999\n",
        "a: 18446744073709551615\n",  // u64::MAX
        "a: 18446744073709551616\n",  // u64::MAX+1
        "a: 1e999\n",
        "a: 0.0000000000000000000000001\n",
    ] {
        match serde_yaml::from_slice::<serde_yaml::Value>(y.as_bytes()) {
            Ok(v) => println!("OK   {y:?} -> {v:?}"),
            Err(e) => println!("ERR  {y:?} -> {}", e),
        }
    }
}
