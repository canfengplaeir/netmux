//! Logging initialization for the netmux core and application.
//!
//! Emits structured logs a single tracing layer whose writer fans out to both
//! stderr and an optional (non-blocking) rolling file, avoiding the common
//! "incompatible layer types" composition error.

use std::io::{self, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};

use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::fmt::writer::MakeWriter;

/// A writer that forwards to any number of underlying writers.
#[derive(Clone)]
struct Rolling {
    targets: Arc<Mutex<Vec<Box<dyn Write + Send>>>>,
}

impl<'a> MakeWriter<'a> for Rolling {
    type Writer = RollingWriter;
    fn make_writer(&'a self) -> Self::Writer {
        RollingWriter {
            targets: Arc::clone(&self.targets),
        }
    }
}

/// Per-event guard writing to every target.
struct RollingWriter {
    targets: Arc<Mutex<Vec<Box<dyn Write + Send>>>>,
}

impl Write for RollingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Ok(mut g) = self.targets.lock() {
            for w in g.iter_mut() {
                let _ = w.write_all(buf);
            }
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        if let Ok(mut g) = self.targets.lock() {
            for w in g.iter_mut() {
                let _ = w.flush();
            }
        }
        Ok(())
    }
}

/// Initialize structured logging that mirrors to stderr and an optional file.
///
/// * `app_name` - used to name the on-disk log file (if `log_dir` is set).
/// * `log_dir`   - when `Some`, a rolling file appender is created there.
/// * `level`     - e.g. "info" or "debug".
pub fn init(app_name: &str, log_dir: Option<&Path>, level: &str) -> Result<(), String> {
    let filter = tracing_subscriber::EnvFilter::try_new(level.to_string())
        .or_else(|_| tracing_subscriber::EnvFilter::try_new("info"))
        .map_err(|e| e.to_string())?;

    let mut targets: Vec<Box<dyn Write + Send>> = vec![Box::new(io::stderr())];

    if let Some(dir) = log_dir {
        std::fs::create_dir_all(dir).map_err(|e| format!("cannot create log dir: {e}"))?;
        let file_appender = tracing_appender::rolling::daily(dir, format!("{app_name}.log"));
        let (file_writer, _guard) = tracing_appender::non_blocking(file_appender);
        // keep the guard alive for the lifetime of the process
        std::mem::forget(_guard);
        targets.push(Box::new(file_writer));
    }

    let writer = Rolling {
        targets: Arc::new(Mutex::new(targets)),
    };

    let layer = tracing_subscriber::fmt::layer()
        .with_target(true)
        .with_writer(writer);

    tracing_subscriber::registry()
        .with(filter)
        .with(layer)
        .try_init()
        .map_err(|e| e.to_string())
}