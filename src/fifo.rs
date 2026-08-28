//! `--fifo`: a named pipe for runtime commands (`echo reconnect > fifo.file`).

use crate::consts::BUF_LEN;
use std::io;
use std::os::fd::{IntoRawFd, RawFd};
use std::path::Path;

pub fn create_fifo(path: &str) -> io::Result<RawFd> {
    crate::secure_file::open_owner_only_fifo(Path::new(path))
        .map(IntoRawFd::into_raw_fd)
        .map_err(|e| io::Error::new(e.kind(), format!("secure FIFO {path} failed: {e}")))
}

/// Read one command (trailing newlines stripped).
pub fn read_command(fd: RawFd) -> Option<String> {
    let mut buf = vec![0u8; BUF_LEN];
    let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len() - 1) };
    if n < 0 {
        log::warn!("fifo read failed,errno={}", io::Error::last_os_error());
        return None;
    }
    let mut n = n as usize;
    while n > 0 && buf[n - 1] == b'\n' {
        n -= 1;
    }
    Some(String::from_utf8_lossy(&buf[..n]).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt, symlink};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

    struct TestDir(std::path::PathBuf);

    impl TestDir {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "udp2raw-fifo-{label}-{}-{}",
                std::process::id(),
                NEXT_DIR.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
            TestDir(path)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn mkfifo(path: &Path, mode: u32) {
        let path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), mode as libc::mode_t) }, 0);
    }

    fn close(fd: RawFd) {
        assert_eq!(unsafe { libc::close(fd) }, 0);
    }

    #[test]
    fn newly_created_command_fifo_is_exactly_owner_only() {
        let dir = TestDir::new("create");
        let path = dir.0.join("commands");
        let fd = create_fifo(path.to_str().unwrap()).unwrap();
        let metadata = fs::symlink_metadata(&path).unwrap();
        assert!(metadata.file_type().is_fifo());
        assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
        assert_eq!(metadata.mode() & 0o7777, 0o600);
        assert_eq!(metadata.nlink(), 1);
        close(fd);
    }

    #[test]
    fn safe_preexisting_fifo_is_accepted_but_unsafe_metadata_is_rejected() {
        let dir = TestDir::new("existing");
        let safe = dir.0.join("safe");
        mkfifo(&safe, 0o600);
        close(create_fifo(safe.to_str().unwrap()).unwrap());

        let writable = dir.0.join("writable");
        mkfifo(&writable, 0o600);
        fs::set_permissions(&writable, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(create_fifo(writable.to_str().unwrap()).is_err());

        let linked = dir.0.join("linked");
        let alias = dir.0.join("linked-alias");
        mkfifo(&linked, 0o600);
        fs::hard_link(&linked, &alias).unwrap();
        assert!(create_fifo(linked.to_str().unwrap()).is_err());
    }

    #[test]
    fn malicious_symlink_and_non_fifo_are_rejected_without_touching_target() {
        let dir = TestDir::new("symlink");
        let target = dir.0.join("target");
        fs::write(&target, b"must stay unchanged").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        let commands = dir.0.join("commands");
        symlink(&target, &commands).unwrap();

        assert!(create_fifo(commands.to_str().unwrap()).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"must stay unchanged");
        assert!(fs::symlink_metadata(&commands).unwrap().file_type().is_symlink());
        assert!(create_fifo(target.to_str().unwrap()).is_err());
    }

    #[test]
    fn untrusted_or_symlinked_parent_cannot_host_command_authority() {
        let dir = TestDir::new("parent");
        let unsafe_parent = dir.0.join("unsafe");
        fs::create_dir(&unsafe_parent).unwrap();
        fs::set_permissions(&unsafe_parent, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(create_fifo(unsafe_parent.join("commands").to_str().unwrap()).is_err());

        let real_parent = dir.0.join("real");
        fs::create_dir(&real_parent).unwrap();
        fs::set_permissions(&real_parent, fs::Permissions::from_mode(0o755)).unwrap();
        let alias = dir.0.join("alias");
        symlink(&real_parent, &alias).unwrap();
        assert!(create_fifo(alias.join("commands").to_str().unwrap()).is_err());
        assert!(!real_parent.join("commands").exists());
    }
}
