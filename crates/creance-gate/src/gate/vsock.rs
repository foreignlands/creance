//! The own-wire dataplane: an AF_VSOCK listener the gate daemon bridges
//! to the managed core's loopback port. Replaces `ssh -R` on the hot
//! path — no ssh encryption, no sshd in the wire — for instances with a
//! vhost-vsock device (hw_cid > 0). Lifecycle is trivially coupled: the
//! bridge lives and dies with the gate state the watchdog already owns.

#![allow(unsafe_code)] // libc AF_VSOCK plumbing — audited, fd lifetime audited

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;

// linux/vm_sockets.h — AF_VSOCK is not exported by libc's linux API.
const AF_VSOCK: i32 = 40;
const VMADDR_CID_ANY: u32 = 0xFFFF_FFFF;

#[repr(C)]
#[derive(Clone, Copy)]
struct SockaddrVm {
    svm_family: u16,
    svm_reserved1: u16,
    svm_port: u32,
    svm_cid: u32,
    svm_zero: [u8; 4],
}

fn errno() -> String {
    std::io::Error::last_os_error().to_string()
}

/// A running bridge: listener thread + shared stop flag. `stop()` is
/// idempotent; Drop stops it.
pub struct VsockBridge {
    stop: Arc<AtomicBool>,
    listener_fd: i32,
    handle: Option<JoinHandle<()>>,
}

impl VsockBridge {
    /// Binds AF_VSOCK:port (CID_ANY) and bridges every accepted guest
    /// stream to 127.0.0.1:port until `stop`.
    pub fn start(port: u16) -> Result<VsockBridge, String> {
        let fd = unsafe { libc::socket(AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(format!("vsock socket: {}", errno()));
        }
        let addr = SockaddrVm {
            svm_family: AF_VSOCK as u16,
            svm_reserved1: 0,
            svm_port: port as u32,
            svm_cid: VMADDR_CID_ANY,
            svm_zero: [0; 4],
        };
        let ok = unsafe {
            libc::bind(
                fd,
                &addr as *const SockaddrVm as *const libc::sockaddr,
                std::mem::size_of::<SockaddrVm>() as u32,
            ) == 0
                && libc::listen(fd, 128) == 0
        };
        if !ok {
            let e = errno();
            unsafe { libc::close(fd) };
            return Err(format!("vsock bind/listen {port}: {e}"));
        }
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let handle = std::thread::spawn(move || accept_loop(fd, port, flag));
        Ok(VsockBridge {
            stop,
            listener_fd: fd,
            handle: Some(handle),
        })
    }

    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wake the accept poll immediately. fd ownership discipline
        // (F-R33-2): the accept loop NEVER closes the listener — stop()
        // does, exactly once, after the join. Without the -1 sentinel a
        // second stop() (Drop after an explicit stop) would shutdown() a
        // closed fd number — one the allocator may already have reused
        // for an innocent socket.
        if self.listener_fd >= 0 {
            unsafe { libc::shutdown(self.listener_fd, libc::SHUT_RDWR) };
        }
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        if self.listener_fd >= 0 {
            unsafe { libc::close(self.listener_fd) };
            self.listener_fd = -1;
        }
    }
}

impl Drop for VsockBridge {
    fn drop(&mut self) {
        self.stop();
    }
}

fn accept_loop(listener: i32, port: u16, stop: Arc<AtomicBool>) {
    loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        let mut pfd = libc::pollfd {
            fd: listener,
            events: libc::POLLIN,
            revents: 0,
        };
        let n = unsafe { libc::poll(&mut pfd, 1, 250) };
        if n <= 0 || pfd.revents & libc::POLLIN == 0 {
            continue;
        }
        let conn = unsafe {
            libc::accept4(
                listener,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_CLOEXEC,
            )
        };
        if conn < 0 {
            continue;
        }
        // The wire's far end: the managed core's loopback listener. A
        // refused connect drops the guest stream — the same shape a dead
        // ssh -R endpoint produced.
        let upstream = match std::net::TcpStream::connect(("127.0.0.1", port)) {
            Ok(s) => s,
            Err(_) => {
                unsafe { libc::close(conn) };
                continue;
            }
        };
        use std::os::unix::io::IntoRawFd;
        let up_fd = upstream.into_raw_fd();
        let flag = stop.clone();
        std::thread::spawn(move || splice(conn, up_fd, flag));
    }
}

/// Bidirectional copy between the vsock conn and the upstream TCP fd.
/// Polls with a quarter-second deadline so the stop flag lands promptly;
/// the guest sees the same hard cut a dead ssh channel produced.
pub(crate) fn splice(a: i32, b: i32, stop: Arc<AtomicBool>) {
    let mut buf = [0u8; 65536];
    let mut fds = [
        libc::pollfd {
            fd: a,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: b,
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        let n = unsafe { libc::poll(fds.as_mut_ptr(), 2, 250) };
        if n < 0 {
            break;
        }
        if n == 0 {
            continue;
        }
        let mut dead = false;
        for (i, fd) in fds.iter().enumerate() {
            let (from, to) = if i == 0 { (a, b) } else { (b, a) };
            if fd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) == 0 {
                continue;
            }
            let r = unsafe { libc::read(from, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if r <= 0 {
                // This connection is over — THIS splice dies (F-R33-1:
                // the break must reach the OUTER loop — an EOF fd stays
                // poll-ready forever, and breaking only the fds loop
                // left one permanently spinning thread per finished
                // connection). It must never touch the shared stop flag:
                // one guest stream closing is not the bridge closing
                // (F-A2). Hard-cut shape: the same semantics a dead ssh
                // channel produced.
                dead = true;
                break;
            }
            let mut off = 0usize;
            while off < r as usize {
                let w = unsafe {
                    libc::write(
                        to,
                        buf[off..].as_ptr() as *const libc::c_void,
                        r as usize - off,
                    )
                };
                if w <= 0 {
                    // The write end is gone — continuing to read would
                    // silently drop every byte (F-R33-3).
                    dead = true;
                    break;
                }
                off += w as usize;
            }
            if dead {
                break;
            }
        }
        if dead {
            break;
        }
    }
    unsafe {
        libc::shutdown(a, libc::SHUT_RDWR);
        libc::close(a);
        libc::close(b);
    }
}
