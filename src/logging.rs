//! Logger matching the C++ output format: `[YYYY-mm-dd HH:MM:SS][LEVEL]message`,
//! with the same colours and the same numeric `--log-level` scale (0 never … 6 trace).

use log::{Level, LevelFilter, Log, Metadata, Record};
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};

pub const RED: &str = "\x1B[31m";
pub const GRN: &str = "\x1B[32m";
pub const YEL: &str = "\x1B[33m";
pub const MAG: &str = "\x1B[35m";
pub const RESET: &str = "\x1B[0m";

pub struct Logger {
    color: AtomicBool,
    position: AtomicBool,
}

static LOGGER: Logger = Logger {
    color: AtomicBool::new(true),
    position: AtomicBool::new(false),
};

/// Map the C++ numeric level (0..=6) to a `LevelFilter`.
pub fn level_filter_from_num(n: i32) -> LevelFilter {
    match n {
        i32::MIN..=0 => LevelFilter::Off,
        1 | 2 => LevelFilter::Error, // fatal / error
        3 => LevelFilter::Warn,
        4 => LevelFilter::Info,
        5 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    }
}

pub fn level_name(n: i32) -> &'static str {
    match n {
        0 => "NEVER",
        1 => "FATAL",
        2 => "ERROR",
        3 => "WARN",
        4 => "INFO",
        5 => "DEBUG",
        6 => "TRACE",
        _ => "",
    }
}

pub fn init(level_num: i32, color: bool, position: bool) {
    LOGGER.color.store(color, Ordering::Relaxed);
    LOGGER.position.store(position, Ordering::Relaxed);
    // set_logger fails if called twice (tests); that's harmless.
    let _ = log::set_logger(&LOGGER);
    log::set_max_level(level_filter_from_num(level_num));
}

pub fn color_enabled() -> bool {
    LOGGER.color.load(Ordering::Relaxed)
}

fn timestamp() -> String {
    // localtime, like the C++ (strftime "%Y-%m-%d %H:%M:%S")
    let mut buf = [0u8; 64];
    unsafe {
        let now = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        libc::localtime_r(&now, &mut tm);
        let fmt = b"%Y-%m-%d %H:%M:%S\0";
        let n = libc::strftime(
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
            fmt.as_ptr() as *const libc::c_char,
            &tm,
        );
        String::from_utf8_lossy(&buf[..n]).into_owned()
    }
}

impl Log for Logger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let (name, color) = match record.level() {
            Level::Error => ("ERROR", RED),
            Level::Warn => ("WARN", YEL),
            Level::Info => ("INFO", GRN),
            Level::Debug => ("DEBUG", MAG),
            Level::Trace => ("TRACE", ""),
        };
        let use_color = self.color.load(Ordering::Relaxed);
        let mut line = String::with_capacity(160);
        if use_color {
            line.push_str(color);
        }
        line.push('[');
        line.push_str(&timestamp());
        line.push_str("][");
        line.push_str(name);
        line.push(']');
        if self.position.load(Ordering::Relaxed) {
            line.push_str(&format!(
                "[{},line:{}]",
                record.file().unwrap_or("?"),
                record.line().unwrap_or(0)
            ));
        }
        line.push_str(&record.args().to_string());
        if use_color {
            line.push_str(RESET);
        }
        line.push('\n');
        let stdout = std::io::stdout();
        let mut h = stdout.lock();
        let _ = h.write_all(line.as_bytes());
        let _ = h.flush();
    }

    fn flush(&self) {
        let _ = std::io::stdout().flush();
    }
}
