//! Strict, owner-only state-file I/O.
//!
//! Reads reject anything other than a small regular file owned by the effective user with
//! exactly mode 0600 and one link. Writes use an exclusive, unpredictable temporary file in
//! the destination directory, sync it, atomically replace the destination, then sync the
//! directory. Every operation also requires that containing directory to be a real,
//! effective-user-owned directory without group/world write permission. This module is
//! intended for daemon state, not general-purpose user documents.

use crate::util::{hex, secure_random_bytes};
#[cfg(unix)]
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
#[cfg(unix)]
use std::sync::{Arc, Mutex, OnceLock, Weak};

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

#[cfg(unix)]
fn validate_directory_metadata(path: &Path, metadata: &fs::Metadata) -> io::Result<()> {
    if !metadata.file_type().is_dir() {
        return Err(invalid(path, "containing path is not a real directory"));
    }
    let euid = unsafe { libc::geteuid() };
    if metadata.uid() != euid {
        return Err(invalid(
            path,
            format!(
                "containing directory owner uid {} is not effective uid {euid}",
                metadata.uid()
            ),
        ));
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(invalid(
            path,
            format!(
                "containing directory mode {:04o} permits group/world writes",
                metadata.mode() & 0o7777
            ),
        ));
    }
    Ok(())
}

/// An opened, revalidatable handle to the state file's containing directory. The lexical
/// path is retained as well as its canonical path so a final-component symlink or a raced
/// replacement is rejected rather than silently followed.
#[cfg(unix)]
struct TrustedDirectory {
    requested: PathBuf,
    canonical: PathBuf,
    file: File,
}

#[cfg(unix)]
impl TrustedDirectory {
    fn for_path(path: &Path, create: bool) -> io::Result<(TrustedDirectory, PathBuf)> {
        let file_name = path.file_name().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} has no state-file name", path.display()),
            )
        })?;
        let parent = parent_dir(path);
        let requested = if parent.is_absolute() {
            parent.to_path_buf()
        } else {
            std::env::current_dir()?.join(parent)
        };
        if create {
            fs::create_dir_all(&requested)?;
        }

        let initial = fs::symlink_metadata(&requested)?;
        validate_directory_metadata(&requested, &initial)?;
        let canonical = fs::canonicalize(&requested)?;
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let file = options.open(&canonical)?;
        validate_directory_metadata(&canonical, &file.metadata()?)?;

        let directory = TrustedDirectory {
            requested,
            canonical,
            file,
        };
        directory.revalidate()?;
        let child = directory.canonical.join(file_name);
        Ok((directory, child))
    }

    fn revalidate(&self) -> io::Result<()> {
        let opened = self.file.metadata()?;
        validate_directory_metadata(&self.canonical, &opened)?;

        // symlink_metadata deliberately rejects a final-component parent symlink. Comparing
        // both names to the held fd also detects replacement between lstat/canonicalize/open.
        for path in [&self.requested, &self.canonical] {
            let current = fs::symlink_metadata(path)?;
            validate_directory_metadata(path, &current)?;
            if opened.dev() != current.dev() || opened.ino() != current.ino() {
                return Err(invalid(
                    path,
                    "containing directory is not the inode held by the directory descriptor",
                ));
            }
        }
        Ok(())
    }

    fn sync(&self) -> io::Result<()> {
        self.file.sync_all()
    }
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
/// The containing directory must also be a real, effective-user-owned directory without
/// group/world write permission. The length is checked both before and during the read so
/// concurrent growth cannot bypass the bound. `O_NONBLOCK` ensures a raced FIFO cannot make
/// the daemon wait indefinitely.
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
    let (directory, path) = TrustedDirectory::for_path(path, false)?;

    // Reject known special files before opening them. The fd metadata check below is still
    // authoritative and closes the lstat/open race.
    let initial = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            directory.revalidate()?;
            return Ok(None);
        }
        Err(e) => return Err(e),
    };
    validate_metadata(&path, &initial, true)?;
    if initial.len() > max_len as u64 {
        return Err(invalid(
            &path,
            format!("length {} exceeds limit {max_len}", initial.len()),
        ));
    }

    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    let file = match options.open(&path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            directory.revalidate()?;
            return Ok(None);
        }
        Err(e) => return Err(e),
    };
    let opened = file.metadata()?;
    validate_metadata(&path, &opened, true)?;
    directory.revalidate()?;
    if opened.len() > max_len as u64 {
        return Err(invalid(
            &path,
            format!("length {} exceeds limit {max_len}", opened.len()),
        ));
    }

    let mut bytes = Vec::with_capacity(opened.len().min(max_len as u64) as usize);
    file.take(read_limit).read_to_end(&mut bytes)?;
    if bytes.len() > max_len {
        return Err(invalid(&path, format!("contents exceed limit {max_len}")));
    }
    directory.revalidate()?;
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
    let (directory, path) = TrustedDirectory::for_path(path, true)?;
    validate_destination(&path)?;

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
        directory.revalidate()?;
    }
    pending.file.take();

    // Recheck immediately before rename. Rename replaces a raced symlink rather than following
    // it, but an unsafe destination observed here is rejected instead of being modified.
    directory.revalidate()?;
    validate_destination(&path)?;
    fs::rename(&pending.path, &path)?;
    pending.renamed = true;

    // The rename is not crash-durable until the containing directory is synced.
    directory.revalidate()?;
    directory.sync()?;
    Ok(())
}

/// Durably and atomically replace `path` with owner-only `contents`.
///
/// The temporary name contains 128 bits from the OS CSPRNG and is opened with exclusive
/// create plus `O_NOFOLLOW`. Any existing destination must itself be a regular file owned by
/// the effective uid, mode 0600, with one link. Its containing directory must be a real,
/// effective-user-owned directory without group/world write permission. The file and
/// containing directory are both synced before success is returned.
#[cfg(unix)]
pub fn atomic_write_owner_only(path: &Path, contents: &[u8]) -> io::Result<()> {
    atomic_write_owner_only_with(path, contents, || random_temp_path(path))
}

#[cfg(not(unix))]
pub fn atomic_write_owner_only(_path: &Path, _contents: &[u8]) -> io::Result<()> {
    Err(unsupported())
}

#[cfg(all(unix, test))]
fn canonical_lock_path(path: &Path) -> io::Result<PathBuf> {
    TrustedDirectory::for_path(path, true).map(|(_, child)| child)
}

/// `flock` is sufficient between processes, but its same-process semantics differ between
/// Unix implementations. Serialize identical canonical paths locally as well so independent
/// threads have the same behavior everywhere we support.
#[cfg(unix)]
fn local_lock(path: &Path) -> Arc<Mutex<()>> {
    static LOCKS: OnceLock<Mutex<HashMap<PathBuf, Weak<Mutex<()>>>>> = OnceLock::new();
    let locks = LOCKS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut locks = locks.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    locks.retain(|_, lock| lock.strong_count() != 0);
    if let Some(lock) = locks.get(path).and_then(Weak::upgrade) {
        return lock;
    }
    let lock = Arc::new(Mutex::new(()));
    locks.insert(path.to_path_buf(), Arc::downgrade(&lock));
    lock
}

#[cfg(unix)]
fn open_existing_lock(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        // A raced FIFO must not block us, and neither a symlink nor a descriptor may escape
        // through exec. `O_NONBLOCK` has no effect on regular-file reads or `flock` below.
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    options.open(path)
}

#[cfg(unix)]
fn create_lock(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create_new(true)
        .mode(OWNER_ONLY_MODE)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    options.open(path)
}

#[cfg(unix)]
fn open_or_create_lock(path: &Path) -> io::Result<(File, bool)> {
    for _ in 0..TEMP_CREATE_ATTEMPTS {
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                // This early rejection avoids opening known FIFOs and devices. The fd check
                // remains authoritative if the directory entry changes after this lstat.
                validate_metadata(path, &metadata, true)?;
                match open_existing_lock(path) {
                    Ok(file) => {
                        validate_metadata(path, &file.metadata()?, true)?;
                        return Ok((file, false));
                    }
                    Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                    Err(e) => return Err(e),
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => match create_lock(path) {
                Ok(file) => {
                    // create_new gave us a new inode, but umask may have removed owner bits.
                    // Force and then verify the exact durable metadata before publishing use.
                    validate_metadata(path, &file.metadata()?, false)?;
                    set_exact_mode(&file)?;
                    validate_metadata(path, &file.metadata()?, true)?;
                    return Ok((file, true));
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            },
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::WouldBlock,
        "lock-file path changed too often while opening",
    ))
}

#[cfg(unix)]
fn lock_exclusive(file: &File) -> io::Result<()> {
    loop {
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

#[cfg(unix)]
fn validate_lock_path(path: &Path, file: &File) -> io::Result<()> {
    let opened = file.metadata()?;
    validate_metadata(path, &opened, true)?;
    let current = fs::symlink_metadata(path)?;
    validate_metadata(path, &current, true)?;
    if opened.dev() != current.dev() || opened.ino() != current.ino() {
        return Err(invalid(
            path,
            "directory entry is not the inode held by the lock descriptor",
        ));
    }
    Ok(())
}

/// Run `action` while holding a stable, owner-only advisory lock at `path`.
///
/// The lock file is created exclusively when absent and otherwise must be a regular file
/// owned by the effective uid, mode 0600, with exactly one link. It is opened with
/// `O_NOFOLLOW|O_CLOEXEC`, locked with `flock(LOCK_EX)`, and its path is revalidated against
/// the locked descriptor's device/inode before `action` runs. The containing directory must
/// be a real, effective-user-owned directory without group/world write permission. A newly
/// created file and its directory entry are synced before success. Closing the descriptor
/// releases the lock, so normal returns, unwinding, and process crashes cannot leave a held
/// advisory lock behind.
#[cfg(unix)]
pub fn with_owner_only_lock<T, F>(path: &Path, action: F) -> io::Result<T>
where
    F: FnOnce() -> io::Result<T>,
{
    let (directory, path) = TrustedDirectory::for_path(path, true)?;
    let local = local_lock(&path);
    let _local_guard = local.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let (file, created) = open_or_create_lock(&path)?;

    // Lock the newly visible inode before durability work so another process cannot enter
    // its action while the creator has not yet synced the stable lock-file directory entry.
    lock_exclusive(&file)?;
    if created {
        file.sync_all()?;
        directory.sync()?;
    }

    directory.revalidate()?;
    validate_lock_path(&path, &file)?;
    action()
    // `file` is dropped after the action result is formed, releasing the advisory lock.
}

#[cfg(not(unix))]
pub fn with_owner_only_lock<T, F>(_path: &Path, _action: F) -> io::Result<T>
where
    F: FnOnce() -> io::Result<T>,
{
    Err(unsupported())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::os::unix::fs::{FileTypeExt, PermissionsExt, symlink};
    use std::process::{Child, Command, ExitStatus};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

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
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
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
                .ok_or_else(|| io::Error::other("forced path list exhausted"))
        }
    }

    fn write_plain_0600(path: &Path, contents: &[u8]) {
        fs::write(path, contents).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    struct ChildGuard(Option<Child>);

    impl ChildGuard {
        fn wait(mut self) -> io::Result<ExitStatus> {
            self.0.take().expect("child guard is populated").wait()
        }

        fn child_mut(&mut self) -> &mut Child {
            self.0.as_mut().expect("child guard is populated")
        }
    }

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            if let Some(child) = self.0.as_mut() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    const LOCK_HELPER_PATH: &str = "UDP2RAW_TEST_OWNER_LOCK_PATH";
    const LOCK_HELPER_READY: &str = "UDP2RAW_TEST_OWNER_LOCK_READY";
    const LOCK_HELPER_ACQUIRED: &str = "UDP2RAW_TEST_OWNER_LOCK_ACQUIRED";
    const LOCK_HELPER_MODE: &str = "UDP2RAW_TEST_OWNER_LOCK_MODE";

    fn spawn_lock_helper(
        lock: &Path,
        ready: &Path,
        acquired: &Path,
        mode: &str,
    ) -> ChildGuard {
        let child = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("secure_file::tests::owner_only_lock_process_helper")
            .arg("--nocapture")
            .env(LOCK_HELPER_PATH, lock)
            .env(LOCK_HELPER_READY, ready)
            .env(LOCK_HELPER_ACQUIRED, acquired)
            .env(LOCK_HELPER_MODE, mode)
            .spawn()
            .unwrap();
        ChildGuard(Some(child))
    }

    fn wait_for_path(path: &Path) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !path.exists() {
            assert!(Instant::now() < deadline, "timed out waiting for {}", path.display());
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn owner_only_lock_process_helper() {
        let Some(lock) = std::env::var_os(LOCK_HELPER_PATH) else {
            return;
        };
        let ready = PathBuf::from(std::env::var_os(LOCK_HELPER_READY).unwrap());
        let acquired = PathBuf::from(std::env::var_os(LOCK_HELPER_ACQUIRED).unwrap());
        let mode = std::env::var(LOCK_HELPER_MODE).unwrap();
        fs::write(ready, b"ready").unwrap();
        with_owner_only_lock(Path::new(&lock), || {
            fs::write(acquired, b"acquired")?;
            if mode == "hold" {
                loop {
                    std::thread::sleep(Duration::from_secs(60));
                }
            }
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn owner_only_lock_creates_stable_strict_file() {
        let dir = TestDir::new("lock-create");
        let path = dir.0.join("state.lock");
        let value = with_owner_only_lock(&path, || Ok(42)).unwrap();
        assert_eq!(value, 42);
        let metadata = fs::symlink_metadata(path).unwrap();
        assert!(metadata.file_type().is_file());
        assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
        assert_eq!(metadata.mode() & 0o7777, OWNER_ONLY_MODE);
        assert_eq!(metadata.nlink(), 1);
    }

    fn assert_parent_rejected_by_all_operations(path: &Path) {
        assert!(read_owner_only(path, 1024).is_err());
        assert!(atomic_write_owner_only(path, b"must not write").is_err());
        assert!(
            with_owner_only_lock(path, || -> io::Result<()> {
                panic!("lock closure ran for an untrusted parent")
            })
            .is_err()
        );
    }

    #[test]
    fn owner_only_operations_reject_group_or_world_writable_parent() {
        for mode in [0o775, 0o757] {
            let dir = TestDir::new("untrusted-parent-mode");
            let path = dir.0.join("state");
            write_plain_0600(&path, b"unchanged");
            fs::set_permissions(&dir.0, fs::Permissions::from_mode(mode)).unwrap();

            assert_parent_rejected_by_all_operations(&path);
            assert_eq!(fs::read(&path).unwrap(), b"unchanged");
            fs::set_permissions(&dir.0, fs::Permissions::from_mode(0o755)).unwrap();
        }
    }

    #[test]
    fn owner_only_operations_reject_symlinked_parent() {
        let dir = TestDir::new("symlinked-parent");
        let real = dir.0.join("real");
        fs::create_dir(&real).unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o755)).unwrap();
        let path = real.join("state");
        write_plain_0600(&path, b"unchanged");
        let alias = dir.0.join("alias");
        symlink(&real, &alias).unwrap();

        let aliased_path = alias.join("state");
        assert_parent_rejected_by_all_operations(&aliased_path);
        assert_eq!(fs::read(path).unwrap(), b"unchanged");
    }

    #[test]
    fn owner_only_operations_reject_wrong_owner_parent_when_privileged() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let dir = TestDir::new("wrong-owner-parent");
        let path = dir.0.join("state");
        write_plain_0600(&path, b"unchanged");
        let c_path = std::ffi::CString::new(dir.0.as_os_str().as_encoded_bytes()).unwrap();
        let original = fs::symlink_metadata(&dir.0).unwrap();
        assert_eq!(unsafe { libc::chown(c_path.as_ptr(), 1, original.gid()) }, 0);

        assert_parent_rejected_by_all_operations(&path);
        assert_eq!(fs::read(&path).unwrap(), b"unchanged");
        assert_eq!(
            unsafe { libc::chown(c_path.as_ptr(), original.uid(), original.gid()) },
            0
        );
    }

    #[test]
    fn owner_only_lock_serializes_threads() {
        let dir = TestDir::new("lock-threads");
        let path = dir.0.join("state.lock");
        let (held_tx, held_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let first_path = path.clone();
        let first = std::thread::spawn(move || {
            with_owner_only_lock(&first_path, || {
                held_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Ok(())
            })
            .unwrap();
        });
        held_rx.recv_timeout(Duration::from_secs(5)).unwrap();

        let (started_tx, started_rx) = mpsc::channel();
        let (entered_tx, entered_rx) = mpsc::channel();
        let second = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            with_owner_only_lock(&path, || {
                entered_tx.send(()).unwrap();
                Ok(())
            })
            .unwrap();
        });
        started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(
            entered_rx.recv_timeout(Duration::from_millis(150)),
            Err(mpsc::RecvTimeoutError::Timeout)
        );
        release_tx.send(()).unwrap();
        entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        first.join().unwrap();
        second.join().unwrap();
    }

    #[test]
    fn owner_only_lock_serializes_processes() {
        let dir = TestDir::new("lock-processes");
        let lock = dir.0.join("state.lock");
        let ready = dir.0.join("ready");
        let acquired = dir.0.join("acquired");
        let mut child = None;

        with_owner_only_lock(&lock, || {
            child = Some(spawn_lock_helper(&lock, &ready, &acquired, "once"));
            wait_for_path(&ready);
            std::thread::sleep(Duration::from_millis(150));
            assert!(!acquired.exists(), "child entered while the parent held the lock");
            assert!(child.as_mut().unwrap().child_mut().try_wait()?.is_none());
            Ok(())
        })
        .unwrap();

        assert!(child.unwrap().wait().unwrap().success());
        assert_eq!(fs::read(acquired).unwrap(), b"acquired");
    }

    #[test]
    fn crashed_process_releases_owner_only_lock() {
        let dir = TestDir::new("lock-crash");
        let lock = dir.0.join("state.lock");
        let ready = dir.0.join("ready");
        let acquired = dir.0.join("acquired");
        let mut child = spawn_lock_helper(&lock, &ready, &acquired, "hold");
        wait_for_path(&acquired);
        assert!(child.child_mut().try_wait().unwrap().is_none());
        child.child_mut().kill().unwrap();
        let _ = child.child_mut().wait();

        let after_crash = dir.0.join("after-crash");
        with_owner_only_lock(&lock, || fs::write(&after_crash, b"reacquired")).unwrap();
        assert_eq!(fs::read(after_crash).unwrap(), b"reacquired");
    }

    #[test]
    fn owner_only_lock_rejects_path_replaced_after_open() {
        let dir = TestDir::new("lock-replaced-inode");
        let requested = dir.0.join("state.lock");
        let path = canonical_lock_path(&requested).unwrap();
        let (file, created) = open_or_create_lock(&path).unwrap();
        assert!(created);
        lock_exclusive(&file).unwrap();

        let displaced = dir.0.join("displaced-lock");
        fs::rename(&path, displaced).unwrap();
        write_plain_0600(&path, b"replacement inode");
        assert!(validate_lock_path(&path, &file).is_err());
    }

    #[test]
    fn owner_only_lock_rejects_unsafe_paths_without_running_closure() {
        let dir = TestDir::new("lock-unsafe");
        let target = dir.0.join("target");
        write_plain_0600(&target, b"unchanged");

        let link = dir.0.join("link");
        symlink(&target, &link).unwrap();
        assert!(with_owner_only_lock(&link, || -> io::Result<()> { panic!("symlink closure ran") }).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"unchanged");

        let fifo = dir.0.join("fifo");
        let fifo_c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
        assert!(with_owner_only_lock(&fifo, || -> io::Result<()> { panic!("FIFO closure ran") }).is_err());

        assert!(with_owner_only_lock(Path::new("/dev/null"), || -> io::Result<()> { panic!("device closure ran") }).is_err());

        let wrong_mode = dir.0.join("wrong-mode");
        fs::write(&wrong_mode, b"").unwrap();
        fs::set_permissions(&wrong_mode, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(with_owner_only_lock(&wrong_mode, || -> io::Result<()> { panic!("wrong-mode closure ran") }).is_err());

        let hard_link = dir.0.join("hard-link");
        fs::hard_link(&target, &hard_link).unwrap();
        assert!(with_owner_only_lock(&hard_link, || -> io::Result<()> { panic!("hard-link closure ran") }).is_err());
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
