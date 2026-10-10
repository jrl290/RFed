//! The process-wide Reticulum log, captured for tests.
//!
//! The log is one destination for the whole process, and `cargo test` runs
//! tests side by side, so a test that installs its own callback takes the
//! lines of every other test and loses its own to the next one installed.
//! Here one callback is installed once, at rfed's default level (NOTICE: what
//! rfed.log holds), and each line is kept with the thread that wrote it. A
//! test reads only the lines its own thread wrote after its [`Mark`]: every
//! hand-off, verdict and summary line of an ingest is written on the thread
//! that ingests.

use std::sync::{Mutex, MutexGuard, Once};
use std::thread::ThreadId;

static LINES: Mutex<Vec<(ThreadId, String)>> = Mutex::new(Vec::new());
static INSTALL: Once = Once::new();

fn lines() -> MutexGuard<'static, Vec<(ThreadId, String)>> {
    LINES.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A point in the log: [`Mark::lines`] are the lines this thread wrote after it.
pub(crate) struct Mark(usize);

/// Start capturing (once per process) and mark the log here.
pub(crate) fn mark() -> Mark {
    INSTALL.call_once(|| {
        reticulum_rust::set_loglevel(reticulum_rust::LOG_NOTICE);
        reticulum_rust::ffi::set_log_callback(|line| {
            lines().push((std::thread::current().id(), line));
        });
    });
    Mark(lines().len())
}

impl Mark {
    /// The lines this thread wrote since the mark, oldest first, as rfed.log
    /// would hold them (`[time] [Level]    message`).
    pub(crate) fn lines(&self) -> Vec<String> {
        let me = std::thread::current().id();
        lines()[self.0..].iter().filter(|(thread, _)| *thread == me).map(|(_, line)| line.clone()).collect()
    }

    /// This thread's lines since the mark that contain `needle`.
    pub(crate) fn containing(&self, needle: &str) -> Vec<String> {
        self.lines().into_iter().filter(|line| line.contains(needle)).collect()
    }
}
