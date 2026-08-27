//! Ordered crypto pipeline.
//!
//! The I/O thread owns every socket and all connection state. It hands each packet's
//! encrypt/decrypt work to one of `n` worker threads in strict round-robin and collects
//! the results in the same round-robin order, so completions are delivered in submission
//! order without any reorder buffer (each worker's queue is FIFO). With `n == 0` the work
//! is done inline and the API is unchanged.
//!
//! Workers signal the I/O thread through a shared `eventfd`, which the caller registers
//! with its poller.

use crate::conn::{decrypt_safer, encrypt_safer};
use crate::crypto::Crypto;
use crate::faketcp::RecvMeta;
use std::collections::VecDeque;
use std::io;
use std::os::fd::RawFd;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TryRecvError, TrySendError};
use std::sync::Arc;
use std::thread::JoinHandle;

/// Identifies the connection a job belongs to; `generation` guards against slot reuse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JobKey {
    pub slot: usize,
    pub generation: u64,
}

pub enum Job {
    /// Encrypt a prepared safer plaintext (data or heartbeat).
    Encrypt { key: JobKey, plain: Vec<u8> },
    /// Decrypt (and GRO-split) a received raw payload.
    Decrypt { key: JobKey, wire: Vec<u8>, meta: RecvMeta },
}

pub enum Done {
    Encrypted { key: JobKey, wire: Option<Vec<u8>> },
    Decrypted { key: JobKey, plains: Vec<Vec<u8>>, meta: RecvMeta },
}

fn process(job: Job, crypto: &Crypto, fix_gro: bool) -> Done {
    match job {
        Job::Encrypt { key, plain } => Done::Encrypted { key, wire: encrypt_safer(crypto, &plain, fix_gro) },
        Job::Decrypt { key, mut wire, meta } => {
            let plains = decrypt_safer(crypto, &mut wire, fix_gro);
            Done::Decrypted { key, plains, meta }
        }
    }
}

struct Worker {
    tx: SyncSender<Job>,
    rx: Receiver<Done>,
    handle: Option<JoinHandle<()>>,
}

pub struct Pipeline {
    workers: Vec<Worker>,
    wake_fd: RawFd,
    next_dispatch: usize,
    next_collect: usize,
    in_flight: usize,
    inline_done: VecDeque<Done>,
    crypto: Arc<Crypto>,
    fix_gro: bool,
    dropped: u64,
}

/// Queue depth per worker; beyond this the I/O thread drops packets (overload).
pub const QUEUE_DEPTH: usize = 512;

impl Pipeline {
    pub fn new(threads: usize, crypto: Arc<Crypto>, fix_gro: bool) -> io::Result<Pipeline> {
        let wake_fd = if threads > 0 {
            let fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            fd
        } else {
            -1
        };
        let mut workers = Vec::with_capacity(threads);
        for i in 0..threads {
            let (job_tx, job_rx) = sync_channel::<Job>(QUEUE_DEPTH);
            let (done_tx, done_rx) = sync_channel::<Done>(QUEUE_DEPTH);
            let crypto = crypto.clone();
            let handle = std::thread::Builder::new().name(format!("udp2raw-crypto-{i}")).spawn(move || {
                while let Ok(job) = job_rx.recv() {
                    let done = process(job, &crypto, fix_gro);
                    if done_tx.send(done).is_err() {
                        break;
                    }
                    let one: u64 = 1;
                    unsafe {
                        libc::write(wake_fd, &one as *const u64 as *const libc::c_void, 8);
                    }
                }
            })?;
            workers.push(Worker { tx: job_tx, rx: done_rx, handle: Some(handle) });
        }
        Ok(Pipeline { workers, wake_fd, next_dispatch: 0, next_collect: 0, in_flight: 0, inline_done: VecDeque::new(), crypto, fix_gro, dropped: 0 })
    }

    pub fn threads(&self) -> usize {
        self.workers.len()
    }

    /// The eventfd to register for readability (only when `threads() > 0`).
    pub fn wake_fd(&self) -> RawFd {
        self.wake_fd
    }

    pub fn in_flight(&self) -> usize {
        self.in_flight
    }

    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Submit a job. Returns `false` if it had to be dropped because the target worker's
    /// queue is full (the I/O thread never blocks).
    pub fn submit(&mut self, job: Job) -> bool {
        if self.workers.is_empty() {
            let done = process(job, &self.crypto, self.fix_gro);
            self.inline_done.push_back(done);
            return true;
        }
        let w = &self.workers[self.next_dispatch];
        match w.tx.try_send(job) {
            Ok(()) => {
                self.next_dispatch = (self.next_dispatch + 1) % self.workers.len();
                self.in_flight += 1;
                true
            }
            Err(TrySendError::Full(_)) => {
                self.dropped += 1;
                if self.dropped.is_power_of_two() {
                    log::warn!("crypto pipeline overloaded, dropped {} packets so far", self.dropped);
                }
                false
            }
            Err(TrySendError::Disconnected(_)) => {
                log::error!("crypto worker exited");
                false
            }
        }
    }

    /// Deliver every completed job, in submission order, to `f`.
    pub fn collect(&mut self, mut f: impl FnMut(Done)) {
        if self.workers.is_empty() {
            while let Some(d) = self.inline_done.pop_front() {
                f(d);
            }
            return;
        }
        // drain the eventfd counter
        let mut v: u64 = 0;
        unsafe {
            libc::read(self.wake_fd, &mut v as *mut u64 as *mut libc::c_void, 8);
        }
        while self.in_flight > 0 {
            let w = &self.workers[self.next_collect];
            match w.rx.try_recv() {
                Ok(done) => {
                    self.next_collect = (self.next_collect + 1) % self.workers.len();
                    self.in_flight -= 1;
                    f(done);
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    log::error!("crypto worker exited");
                    break;
                }
            }
        }
    }
}

impl Drop for Pipeline {
    fn drop(&mut self) {
        for w in &mut self.workers {
            // dropping the sender ends the worker loop
            let (dummy_tx, _) = sync_channel::<Job>(1);
            let tx = std::mem::replace(&mut w.tx, dummy_tx);
            drop(tx);
        }
        for w in &mut self.workers {
            if let Some(h) = w.handle.take() {
                let _ = h.join();
            }
        }
        if self.wake_fd >= 0 {
            unsafe { libc::close(self.wake_fd) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{AuthMode, CipherMode, Keys};
    use crate::wire::{build_safer, SaferHeader};

    fn crypto() -> Arc<Crypto> {
        Arc::new(Crypto::new(CipherMode::Aes128Cbc, AuthMode::Md5, false, Keys::derive("k", true)))
    }

    fn plain(i: u64) -> Vec<u8> {
        build_safer(&SaferHeader { my_id: 1, oppsite_id: 2, seq: i, ptype: b'd', roller: 0 }, &[i as u8; 200])
    }

    #[test]
    fn inline_mode_preserves_order() {
        let mut p = Pipeline::new(0, crypto(), false).unwrap();
        for i in 0..10u64 {
            assert!(p.submit(Job::Encrypt { key: JobKey { slot: i as usize, generation: 0 }, plain: plain(i) }));
        }
        let mut seen = Vec::new();
        p.collect(|d| {
            if let Done::Encrypted { key, wire } = d {
                assert!(wire.is_some());
                seen.push(key.slot);
            }
        });
        assert_eq!(seen, (0..10).collect::<Vec<_>>());
    }

    #[test]
    fn threaded_mode_preserves_order_and_roundtrips() {
        let c = crypto();
        let server = Crypto::new(CipherMode::Aes128Cbc, AuthMode::Md5, false, Keys::derive("k", false));
        let mut p = Pipeline::new(3, c, false).unwrap();
        let n = 200u64;
        for i in 0..n {
            assert!(p.submit(Job::Encrypt { key: JobKey { slot: i as usize, generation: 7 }, plain: plain(i) }));
        }
        let mut seen = Vec::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while seen.len() < n as usize {
            p.collect(|d| {
                if let Done::Encrypted { key, wire } = d {
                    assert_eq!(key.generation, 7);
                    let pt = server.decrypt(&wire.unwrap()).unwrap();
                    assert_eq!(pt, plain(key.slot as u64));
                    seen.push(key.slot);
                }
            });
            if std::time::Instant::now() > deadline {
                panic!("timeout, got {} of {n}", seen.len());
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert_eq!(seen, (0..n as usize).collect::<Vec<_>>());
        assert_eq!(p.in_flight(), 0);
    }
}
