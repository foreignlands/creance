// Fills a unix-socket listen backlog with N pending connections from ONE
// process (nonblocking connect, sockets kept open). Prints per-connect
// errno counts so the caller can see when the backlog starts refusing.
use std::ffi::CString;
use std::os::unix::io::RawFd;

const AF_UNIX: i32 = 1;
const SOCK_STREAM: i32 = 1;
const SOCK_NONBLOCK: i32 = 0x4000;
const F_GETFL: i32 = 3;
const F_SETFL: i32 = 4;
const O_NONBLOCK: i32 = 0x4000;

unsafe extern "C" {
    fn socket(domain: i32, ty: i32, proto: i32) -> RawFd;
    fn connect(fd: RawFd, addr: *const SockAddr, len: u32) -> i32;
    fn close(fd: RawFd) -> i32;
    fn fcntl(fd: RawFd, cmd: i32, arg: i32) -> i32;
    fn __error() -> *const i32;
}
#[repr(C)]
struct SockAddr {
    len: u8,
    family: u8,
    path: [u8; 104],
}

fn errno() -> i32 {
    unsafe { *__error() }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let path = args.get(1).expect("socket path");
    let n: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(200);
    let mut cpath = [0u8; 104];
    let pb = path.as_bytes();
    assert!(pb.len() < 104, "path too long");
    cpath[..pb.len()].copy_from_slice(pb);
    let addr = SockAddr {
        len: (2 + pb.len() + 1) as u8,
        family: AF_UNIX as u8,
        path: cpath,
    };
    let aptr = &addr as *const SockAddr;
    let mut refused = 0;
    let mut pending = 0;
    let mut other = 0;
    let mut fds = Vec::new();
    for _ in 0..n {
        unsafe {
            let fd = socket(AF_UNIX, SOCK_STREAM, 0);
            if fd < 0 {
                other += 1;
                continue;
            }
            // macOS has no SOCK_NONBLOCK in socket(): set it via fcntl.
            fcntl(fd, F_SETFL, O_NONBLOCK);
            let r = connect(fd, aptr, addr.len as u32);
            let e = errno();
            if r == 0 {
                pending += 1; // connected & queued (daemon stopped => stays)
            } else if e == 35 {
                pending += 1; // EINPROGRESS
            } else if e == 61 {
                refused += 1; // ECONNREFUSED
            } else {
                other += 1;
            }
            fds.push(fd);
        }
    }
    // keep every socket open so pending connects stay queued
    std::thread::sleep(std::time::Duration::from_secs(6));
    for fd in &fds {
        unsafe {
            close(*fd);
        }
    }
    println!(
        "filler done: n={n} queued_or_connected={pending} refused={refused} other={other} (61=ECONNREFUSED)"
    );
    // silence unused warnings for fcntl consts
    let _ = (F_GETFL, F_SETFL, O_NONBLOCK, CString::new("x".to_string()));
}
