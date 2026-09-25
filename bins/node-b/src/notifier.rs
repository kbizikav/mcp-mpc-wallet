use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

use mw_node_b::{UserNotice, UserNotifier};

/// ユーザー向けの通知を JSON Lines に追記し、要約を標準エラーに出す。
///
/// ユーザーアプリへの配信は M5 で作る。通知には秘密を含めない。
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
