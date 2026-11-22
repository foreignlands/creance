//! Shared wire helpers for every HTTP-over-anything reader in the crate
//! (egress tunnels, the gate's unix socket, the workbench's TCP listener).
//!
//! One buffered implementation instead of four byte-at-a-time copies. The
//! reader returns the header block plus a [`PrefacedReader`] that replays
//! whatever was read past the terminator — body bytes are never lost.

use std::io::{self, Read, Write};

/// Reads one HTTP header block (through the first `\r\n\r\n`) in buffered
/// chunks. The returned reader replays any bytes read past the terminator,
/// so the caller's body reads see the full stream.
pub fn read_header_block<R: Read>(
    stream: R,
    max: usize,
) -> io::Result<(Vec<u8>, PrefacedReader<R>)> {
    let mut inner = stream;
    let mut block = Vec::with_capacity(1024);
    let mut chunk = [0u8; 8192];
    let mut leftover: Vec<u8> = Vec::new();
    let mut terminated = false;
    loop {
        let n = inner.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        // Find the terminator within the newly read bytes.
        let start = block.len();
        block.extend_from_slice(&chunk[..n]);
        if block.len() > max {
            return Err(io::Error::other("HTTP response header too large"));
        }
        if let Some(pos) = find_terminator(&block, start.saturating_sub(3)) {
            leftover.extend_from_slice(&block[pos + 4..]);
            block.truncate(pos + 4);
            terminated = true;
            break;
        }
    }
    // FINDING-006: a non-empty header block that never reached its blank
    // line is a truncated response, not a success.
    if !block.is_empty() && !terminated {
        return Err(io::Error::other("HTTP header incomplete"));
    }
    Ok((
        block,
        PrefacedReader {
            inner,
            preface: leftover,
            pos: 0,
        },
    ))
}

/// Splits a header block into the request/status line and the header
/// fields as (name, value) pairs — names verbatim, values trimmed.
/// Shared by the gate, the workbench, and tunnel readers so the
/// per-field iteration lives in exactly one place.
pub fn parse_header_block(block: &[u8]) -> (String, Vec<(String, String)>) {
    let text = String::from_utf8_lossy(block);
    let mut lines = text.lines();
    let first = lines.next().unwrap_or_default().to_owned();
    let fields = lines
        .filter_map(|line| {
            line.split_once(':')
                .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        })
        .collect();
    (first, fields)
}

/// FINDING-006 over parsed fields: at most one `Content-Length`, and it
/// must be a valid usize. `Ok(None)` is absent, `Ok(Some(n))` one valid
/// value, `Err` a duplicate or invalid header — an ambiguity-smuggling
/// vector every reader must refuse identically.
pub fn strict_content_length(fields: &[(String, String)]) -> Result<Option<usize>, &'static str> {
    let mut len = None;
    for (k, v) in fields {
        if k.eq_ignore_ascii_case("content-length") {
            match (len, v.parse::<usize>()) {
                (None, Ok(n)) => len = Some(n),
                _ => return Err("duplicate or invalid content-length"),
            }
        }
    }
    Ok(len)
}

fn find_terminator(block: &[u8], from: usize) -> Option<usize> {
    if block.len() < 4 {
        return None;
    }
    block[from..]
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + from)
}

/// Replays bytes read past a header block, then reads on from the inner
/// stream.
pub struct PrefacedReader<R> {
    inner: R,
    preface: Vec<u8>,
    pos: usize,
}

impl<R: Read> Read for PrefacedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos < self.preface.len() {
            let n = (self.preface.len() - self.pos).min(buf.len());
            buf[..n].copy_from_slice(&self.preface[self.pos..self.pos + n]);
            self.pos += n;
            return Ok(n);
        }
        self.inner.read(buf)
    }
}

impl<R: Write> Write for PrefacedReader<R> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_bytes_past_the_terminator_survive() {
        let wire = b"HTTP/1.1 200 OK\r\nX: 1\r\n\r\nTRAILING-BODY".as_slice();
        let (block, mut reader) = read_header_block(wire, 16 << 10).unwrap();
        assert_eq!(block, b"HTTP/1.1 200 OK\r\nX: 1\r\n\r\n".to_vec());
        let mut rest = Vec::new();
        reader.read_to_end(&mut rest).unwrap();
        assert_eq!(rest, b"TRAILING-BODY");
    }

    #[test]
    fn terminator_split_across_reads_is_still_found() {
        // Hand-feed the reader one byte at a time so the terminator spans
        // read boundaries.
        struct Dribble<'a>(&'a [u8], usize);
        impl Read for Dribble<'_> {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if self.1 >= self.0.len() || buf.is_empty() {
                    return Ok(0);
                }
                buf[0] = self.0[self.1];
                self.1 += 1;
                Ok(1)
            }
        }
        let wire = b"A\r\n\r\nBODY".as_slice();
        let (block, mut reader) = read_header_block(Dribble(wire, 0), 16 << 10).unwrap();
        assert_eq!(block, b"A\r\n\r\n".to_vec());
        let mut rest = Vec::new();
        reader.read_to_end(&mut rest).unwrap();
        assert_eq!(rest, b"BODY");
    }

    #[test]
    fn enforces_the_max() {
        let wire = vec![b'x'; 100];
        assert!(read_header_block(wire.as_slice(), 10).is_err());
    }

    #[test]
    fn empty_stream_is_not_an_error() {
        let (block, _) = read_header_block(b"".as_slice(), 16 << 10).unwrap();
        assert_eq!(block, Vec::<u8>::new());
    }

    #[test]
    fn truncated_headers_are_rejected() {
        // FINDING-006: a half header block ("HTTP/1.1 200 OK\r\nX" + EOF)
        // must error instead of passing as a 200 with an empty body.
        let wire = b"HTTP/1.1 200 OK\r\nX".as_slice();
        assert!(read_header_block(wire, 16 << 10).is_err());
    }
}
