use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

use mw_node_b::{UserNotice, UserNotifier};

/// Append user notifications to a JSON Lines file and print a summary to stderr.
///
/// Delivery to the user app comes in M5. Notifications never contain secrets.
pub struct JsonlNotifier {
    path: PathBuf,
    lock: Mutex<()>,
}

impl JsonlNotifier {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            lock: Mutex::new(()),
        }
    }
}

impl UserNotifier for JsonlNotifier {
    fn notify(&self, notice: UserNotice) {
        let _guard = self.lock.lock().expect("notifier poisoned");
        let Ok(line) = serde_json::to_string(&notice) else {
            return;
        };
        eprintln!("[notice] {line}");
        let written = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .and_then(|mut f| writeln!(f, "{line}"));
        if let Err(e) = written {
            eprintln!("[notice] failed to write {}: {e}", self.path.display());
        }
    }
}
