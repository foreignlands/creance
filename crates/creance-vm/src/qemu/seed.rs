//! The cloud-init NoCloud seed: a vFAT volume labelled `CIDATA` carrying
//! `user-data` and `meta-data`.
//!
//! NoCloud accepts a FAT or iso9660 volume by label on any block device
//! (`DataSourceNoCloud`), so the seed ships as a small raw disk on virtio-blk
//! — built entirely in Rust, no genisoimage/xorriso on the host.

use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// The volume label cloud-init looks for (11 bytes, space padded).
const LABEL: &[u8; 11] = b"CIDATA     ";

/// Seed image size: small volumes format FAT12/FAT16 (label lives at boot
/// offset 0x2B); far above any user-data this project generates.
const SEED_BYTES: u64 = 8 << 20;

/// Builds `<dir>/seed.img` holding the given documents. The file is created
/// fresh every call — a seed is per-instance, per-setup.
pub fn build(dir: &Path, user_data: &str, meta_data: &str) -> Result<PathBuf, String> {
    let path = dir.join("seed.img");
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .map_err(|e| format!("cannot create seed image: {e}"))?;
    file.set_len(SEED_BYTES)
        .map_err(|e| format!("cannot size seed image: {e}"))?;
    file.seek(SeekFrom::Start(0))
        .map_err(|e| format!("cannot rewind seed image: {e}"))?;
    // fatfs' format_volume only lays the filesystem down; the volume is
    // then reopened to place the documents.
    fatfs::format_volume(
        file.try_clone().map_err(|e| e.to_string())?,
        fatfs::FormatVolumeOptions::new().volume_label(*LABEL),
    )
    .map_err(|e| format!("cannot format seed volume: {e}"))?;
    file.seek(SeekFrom::Start(0))
        .map_err(|e| format!("cannot rewind seed image: {e}"))?;
    let fs = fatfs::FileSystem::new(
        file.try_clone().map_err(|e| e.to_string())?,
        fatfs::FsOptions::new(),
    )
    .map_err(|e| format!("cannot reopen seed volume: {e}"))?;
    {
        let root = fs.root_dir();
        let mut ud = root
            .create_file("user-data")
            .map_err(|e| format!("cannot add user-data to the seed: {e}"))?;
        ud.write_all(user_data.as_bytes())
            .map_err(|e| format!("cannot write user-data into the seed: {e}"))?;
        let mut md = root
            .create_file("meta-data")
            .map_err(|e| format!("cannot add meta-data to the seed: {e}"))?;
        md.write_all(meta_data.as_bytes())
            .map_err(|e| format!("cannot write meta-data into the seed: {e}"))?;
    }
    drop(fs);
    file.flush().map_err(|e| e.to_string())?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_carries_both_documents_with_the_cidata_label() {
        let dir =
            std::env::temp_dir().join(format!("creance-seed-{}", crate::token()[..8].to_owned()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = build(&dir, "#cloud-config\nruncmd: []\n", "instance-id: t1\n").unwrap();
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(bytes.len() as u64, SEED_BYTES);
        // At this size the volume is FAT12/16 — the boot-sector label sits
        // at 0x2B. (A FAT32 volume would carry it at 0x47.)
        assert_eq!(&bytes[0x2b..0x36], b"CIDATA     ");
        // Both documents are in the data region, in creation order.
        let hay = String::from_utf8_lossy(&bytes);
        let ud = hay.find("#cloud-config").expect("user-data present");
        let md = hay.find("instance-id: t1").expect("meta-data present");
        assert!(ud < md, "user-data is written first");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
