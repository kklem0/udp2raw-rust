//! Strict, owner-only state-file I/O.
//!
//! Reads reject anything other than a small regular file owned by the effective user with
//! exactly mode 0600 and one link. Writes use an exclusive, unpredictable temporary file in
//! the destination directory, sync it, atomically replace the destination, then sync the
//! directory. This module is intended for daemon state, not general-purpose user documents.

use crate::util::{hex, secure_random_bytes};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

const OWNER_ONLY_MODE: u32 = 0o600;
const TEMP_CREATE_ATTEMPTS: usize = 128;

fn invalid(path: &Path, why: impl std::fmt::Display) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("unsafe state file {}: {why}", path.display()),
    )
}

#[cfg(unix)]
fn validate_metadata(path: &Path, metadata: &fs::Metadata, require_mode: bool) -> io::Result<()> {
    if !metadata.file_type().is_file() {
        return Err(invalid(path, "not a regular file"));
    }
    let euid = unsafe { libc::geteuid() };
    if metadata.uid() != euid {
        return Err(invalid(
            path,
            format!("owner uid {} is not effective uid {euid}", metadata.uid()),
        ));
    }
    if metadata.nlink() != 1 {
        return Err(invalid(
            path,
            format!("link count {} is not 1", metadata.nlink()),
        ));
    }
    if require_mode && metadata.mode() & 0o7777 != OWNER_ONLY_MODE {
        return Err(invalid(
            path,
            format!("mode {:04o} is not 0600", metadata.mode() & 0o7777),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "owner-only state files require Unix filesystem semantics",
    )
}

/// Read at most `max_len` bytes from a strict owner-only regular file.
///
/// A missing path returns `Ok(None)`. Symlinks, non-regular files, files not owned by the
/// effective uid, files whose mode is not exactly 0600, and hard-linked files are errors.
/// The length is checked both before and during the read so concurrent growth cannot bypass
/// the bound. `O_NONBLOCK` ensures a raced FIFO cannot make the daemon wait indefinitely.
#[cfg(unix)]
pub fn read_owner_only(path: &Path, max_len: usize) -> io::Result<Option<Vec<u8>>> {
    let read_limit = max_len
        .checked_add(1)
        .and_then(|n| u64::try_from(n).ok())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "state-file length bound is too large",
            )
        })?;

    // Reject known special files before opening them. The fd metadata check below is still
    // authoritative and closes the lstat/open race.
    let initial = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    validate_metadata(path, &initial, true)?;
    if initial.len() > max_len as u64 {
        return Err(invalid(
            path,
            format!("length {} exceeds limit {max_len}", initial.len()),
        ));
    }

    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    let file = match options.open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let opened = file.metadata()?;
    validate_metadata(path, &opened, true)?;
    if opened.len() > max_len as u64 {
        return Err(invalid(
            path,
            format!("length {} exceeds limit {max_len}", opened.len()),
        ));
    }

    let mut bytes = Vec::with_capacity(opened.len().min(max_len as u64) as usize);
    file.take(read_limit).read_to_end(&mut bytes)?;
    if bytes.len() > max_len {
        return Err(invalid(path, format!("contents exceed limit {max_len}")));
    }
    Ok(Some(bytes))
}

#[cfg(not(unix))]
pub fn read_owner_only(_path: &Path, _max_len: usize) -> io::Result<Option<Vec<u8>>> {
    Err(unsupported())
}

#[cfg(unix)]
fn random_temp_path(destination: &Path) -> io::Result<PathBuf> {
    let file_name = destination.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} has no file name", destination.display()),
        )
    })?;
    let mut random = [0u8; 16];
    secure_random_bytes(&mut random);
    let mut temp_name = file_name.to_os_string();
    temp_name.push(".tmp.");
    temp_name.push(hex(&random));
    Ok(parent_dir(destination).join(temp_name))
}

fn parent_dir(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

#[cfg(unix)]
fn validate_destination(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_metadata(path, &metadata, true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(unix)]
fn set_exact_mode(file: &File) -> io::Result<()> {
    let rc = unsafe { libc::fchmod(file.as_raw_fd(), OWNER_ONLY_MODE as libc::mode_t) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(unix)]
struct PendingTemp {
    path: PathBuf,
    file: Option<File>,
    renamed: bool,
}

#[cfg(unix)]
impl Drop for PendingTemp {
    fn drop(&mut self) {
        self.file.take();
        if !self.renamed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[cfg(unix)]
fn create_temp_with<F>(mut next_path: F) -> io::Result<PendingTemp>
where
    F: FnMut() -> io::Result<PathBuf>,
{
    for _ in 0..TEMP_CREATE_ATTEMPTS {
        let path = next_path()?;
        let mut options = OpenOptions::new();
        options
            .write(true)
            .create_new(true)
            .mode(OWNER_ONLY_MODE)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let file = match options.open(&path) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        };

        // create_new makes this our inode. Verify that assumption before changing or writing
        // it, then force exact permissions in case the process umask removed owner bits. Arm
        // cleanup first so every validation/chmod error removes the inode we just created.
        let pending = PendingTemp {
            path,
            file: Some(file),
            renamed: false,
        };
        let file = pending
            .file
            .as_ref()
            .expect("pending temporary has an open file");
        validate_metadata(&pending.path, &file.metadata()?, false)?;
        set_exact_mode(file)?;
        validate_metadata(&pending.path, &file.metadata()?, true)?;
        return Ok(pending);
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not create a unique state-file temporary after 128 attempts",
    ))
}

#[cfg(unix)]
fn atomic_write_owner_only_with<F>(path: &Path, contents: &[u8], next_path: F) -> io::Result<()>
where
    F: FnMut() -> io::Result<PathBuf>,
{
    let directory = parent_dir(path);
    fs::create_dir_all(directory)?;
    validate_destination(path)?;

    let mut pending = create_temp_with(next_path)?;
    {
        let file = pending
            .file
            .as_mut()
            .expect("pending temporary has an open file");
        file.write_all(contents)?;
        file.sync_all()?;
        // Catch a hostile hard link or metadata change made after creation before publishing.
        validate_metadata(&pending.path, &file.metadata()?, true)?;
    }
    pending.file.take();

    // Recheck immediately before rename. Rename replaces a raced symlink rather than following
    // it, but an unsafe destination observed here is rejected instead of being modified.
    validate_destination(path)?;
    fs::rename(&pending.path, path)?;
    pending.renamed = true;

    // The rename is not crash-durable until the containing directory is synced.
    File::open(directory)?.sync_all()?;
    Ok(())
}

/// Durably and atomically replace `path` with owner-only `contents`.
///
/// The temporary name contains 128 bits from the OS CSPRNG and is opened with exclusive
/// create plus `O_NOFOLLOW`. Any existing destination must itself be a regular file owned by
/// the effective uid, mode 0600, with one link. The file and containing directory are both
/// synced before success is returned.
#[cfg(unix)]
pub fn atomic_write_owner_only(path: &Path, contents: &[u8]) -> io::Result<()> {
    atomic_write_owner_only_with(path, contents, || random_temp_path(path))
}

#[cfg(not(unix))]
pub fn atomic_write_owner_only(_path: &Path, _contents: &[u8]) -> io::Result<()> {
    Err(unsupported())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::os::unix::fs::{FileTypeExt, PermissionsExt, symlink};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

    struct TestDir(PathBuf);

    impl TestDir {
        fn new(name: &str) -> TestDir {
            let serial = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "udp2raw-secure-file-{name}-{}-{serial}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir(&path).unwrap();
            TestDir(path)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn force_paths(paths: Vec<PathBuf>) -> impl FnMut() -> io::Result<PathBuf> {
        let mut paths: VecDeque<_> = paths.into();
        move || {
            paths
                .pop_front()
                .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "forced path list exhausted"))
        }
    }

    fn write_plain_0600(path: &Path, contents: &[u8]) {
        fs::write(path, contents).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn bounded_read_requires_strict_owner_only_regular_file() {
        let dir = TestDir::new("read");
        let path = dir.0.join("state");
        assert_eq!(read_owner_only(&path, 4).unwrap(), None);

        write_plain_0600(&path, b"good");
        assert_eq!(read_owner_only(&path, 4).unwrap(), Some(b"good".to_vec()));
        assert!(read_owner_only(&path, 3).is_err());

        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(read_owner_only(&path, 4).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let hard_link = dir.0.join("hard-link");
        fs::hard_link(&path, &hard_link).unwrap();
        assert!(read_owner_only(&path, 4).is_err());
    }

    #[test]
    fn read_rejects_symlink_fifo_and_device_without_blocking() {
        let dir = TestDir::new("special-read");
        let target = dir.0.join("target");
        write_plain_0600(&target, b"safe");
        let link = dir.0.join("link");
        symlink(&target, &link).unwrap();
        assert!(read_owner_only(&link, 1024).is_err());

        let fifo = dir.0.join("fifo");
        let fifo_c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
        assert!(read_owner_only(&fifo, 1024).is_err());

        assert!(read_owner_only(Path::new("/dev/null"), 1024).is_err());
    }

    #[test]
    fn atomic_write_replaces_only_safe_destinations_and_is_readable() {
        let dir = TestDir::new("write");
        let path = dir.0.join("state");
        atomic_write_owner_only(&path, b"first").unwrap();
        assert_eq!(read_owner_only(&path, 32).unwrap(), Some(b"first".to_vec()));
        let metadata = fs::symlink_metadata(&path).unwrap();
        assert_eq!(metadata.mode() & 0o7777, 0o600);
        assert_eq!(metadata.nlink(), 1);

        atomic_write_owner_only(&path, b"second").unwrap();
        assert_eq!(
            read_owner_only(&path, 32).unwrap(),
            Some(b"second".to_vec())
        );

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(atomic_write_owner_only(&path, b"must not replace").is_err());
        assert_eq!(fs::read(&path).unwrap(), b"second");
        assert!(fs::read_dir(&dir.0).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".tmp.")
        }));
    }

    #[test]
    fn forced_temp_collisions_never_open_symlink_fifo_or_device() {
        let dir = TestDir::new("collisions");
        let destination = dir.0.join("cache");
        let sentinel = dir.0.join("sentinel");
        write_plain_0600(&sentinel, b"unchanged");

        let link = dir.0.join("forced-link");
        symlink(&sentinel, &link).unwrap();
        let fifo = dir.0.join("forced-fifo");
        let fifo_c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
        let fresh = dir.0.join("fresh-temp");

        // /dev/null supplies a real device collision without requiring mknod privileges. The
        // production generator only returns same-directory paths; this private hook exercises
        // the exclusive-open collision branch with each hostile inode type deterministically.
        atomic_write_owner_only_with(
            &destination,
            b"new cache",
            force_paths(vec![
                link.clone(),
                fifo.clone(),
                PathBuf::from("/dev/null"),
                fresh,
            ]),
        )
        .unwrap();

        assert_eq!(fs::read(&sentinel).unwrap(), b"unchanged");
        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(fs::symlink_metadata(&fifo).unwrap().file_type().is_fifo());
        assert_eq!(
            read_owner_only(&destination, 64).unwrap(),
            Some(b"new cache".to_vec())
        );
    }

    #[test]
    fn old_predictable_pid_temp_symlink_is_ignored_and_target_unchanged() {
        let dir = TestDir::new("old-pid-name");
        let cache = dir.0.join("cache");
        let sentinel = dir.0.join("sentinel");
        write_plain_0600(&sentinel, b"do not overwrite");
        let old_temp = dir.0.join(format!("cache.tmp.{}", std::process::id()));
        symlink(&sentinel, &old_temp).unwrap();

        atomic_write_owner_only(&cache, b"cache contents").unwrap();

        assert_eq!(fs::read(&sentinel).unwrap(), b"do not overwrite");
        assert!(
            fs::symlink_metadata(&old_temp)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            read_owner_only(&cache, 64).unwrap(),
            Some(b"cache contents".to_vec())
        );
    }

    #[test]
    fn unsafe_existing_destination_is_rejected_without_touching_target() {
        let dir = TestDir::new("unsafe-destination");
        let target = dir.0.join("target");
        write_plain_0600(&target, b"unchanged");
        let destination = dir.0.join("cache");
        symlink(&target, &destination).unwrap();

        assert!(atomic_write_owner_only(&destination, b"attack").is_err());
        assert_eq!(fs::read(&target).unwrap(), b"unchanged");
        assert!(
            fs::symlink_metadata(&destination)
                .unwrap()
                .file_type()
                .is_symlink()
        );

        fs::remove_file(&destination).unwrap();
        let fifo_c = std::ffi::CString::new(destination.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
        assert!(atomic_write_owner_only(&destination, b"attack").is_err());
        assert!(
            fs::symlink_metadata(&destination)
                .unwrap()
                .file_type()
                .is_fifo()
        );

        // A device destination is rejected from metadata without opening or writing it.
        assert!(atomic_write_owner_only(Path::new("/dev/null"), b"attack").is_err());
    }
}
