//! 区分 O(n²) 归属：直接拉取 libyaml 事件流（不做 Value 构建）。
//! 用法: libyaml-probe <depth>
use std::time::Instant;

fn main() {
    let depth: usize = std::env::args().nth(1).unwrap().parse().unwrap();
    let mut data = String::from("proxies: ");
    data.push_str(&"[".repeat(depth));
    data.push_str(&"]".repeat(depth));
    let t0 = Instant::now();
    let mut parser: unsafe_libyaml::yaml_parser_t = unsafe { std::mem::zeroed() };
    unsafe { unsafe_libyaml::yaml_parser_initialize(&mut parser) };
    let len = data.len();
    let cstr = std::ffi::CString::new(data).unwrap();
    unsafe {
        unsafe_libyaml::yaml_parser_set_input_string(
            &mut parser,
            cstr.as_ptr() as *const u8,
            len as u64,
        )
    };
    let mut events = 0u64;
    loop {
        let mut event = unsafe { std::mem::zeroed::<unsafe_libyaml::yaml_event_t>() };
        let ok = unsafe { unsafe_libyaml::yaml_parser_parse(&mut parser, &mut event) };
        if !ok.ok {
            println!(
                "PARSE-STOP events={events} elapsed_ms={} err={}",
                t0.elapsed().as_millis(),
                unsafe {
                    std::ffi::CStr::from_ptr(parser.problem).to_string_lossy()
                }
            );
            break;
        }
        events += 1;
        let et = event.type_;
        unsafe { unsafe_libyaml::yaml_event_delete(&mut event) };
        if et == unsafe_libyaml::yaml_event_type_t::YAML_DOCUMENT_END_EVENT {
            println!("DOC-END events={events} elapsed_ms={}", t0.elapsed().as_millis());
            break;
        }
    }
}
