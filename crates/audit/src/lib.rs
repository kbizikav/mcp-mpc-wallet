//! Hash-chained audit log (invariant 10).
//!
//! Each entry includes the hash of the previous one, so edits, deletions and reordering are detectable.
//! Never put secrets such as shares or API keys in a record (invariant 11).

use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use alloy_primitives::{Address, B256};
use mw_core::{PolicyHash, Verdict, canonical_hash};
use serde::{Deserialize, Serialize};

const ENTRY_DOMAIN: &str = "mcp-mpc-wallet/audit-entry/v1";

/// The record of one judgment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    pub wallet: Address,
    /// Hash of the proposal (the whole unsigned tx)
    pub proposal_hash: B256,
    /// Summary of the input. Attacker-controlled strings must already be escaped
    pub input_summary: String,
    pub policy_hash: Option<PolicyHash>,
    /// Hash of the Tenderly response body
    pub simulation_hash: Option<B256>,
    pub verdict: Verdict,
    pub reasons: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    pub seq: u64,
    pub timestamp_unix: u64,
    pub prev_hash: B256,
    pub record: AuditRecord,
    pub entry_hash: B256,
}

#[derive(Serialize)]
struct HashedFields<'a> {
    seq: u64,
    timestamp_unix: u64,
    prev_hash: B256,
    record: &'a AuditRecord,
}

impl AuditEntry {
    fn compute_hash(&self) -> B256 {
        canonical_hash(
            ENTRY_DOMAIN,
            &HashedFields {
                seq: self.seq,
                timestamp_unix: self.timestamp_unix,
                prev_hash: self.prev_hash,
                record: &self.record,
            },
        )
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("audit log I/O: {0}")]
    Io(#[from] io::Error),
    #[error("audit log entry is not valid JSON at line {line}: {source}")]
    Parse {
        line: usize,
        source: serde_json::Error,
    },
    #[error("audit chain is broken at seq {seq}")]
    BrokenChain { seq: u64 },
}

/// Check that a sequence of entries forms a valid chain.
pub fn verify_chain(entries: &[AuditEntry]) -> Result<(), AuditError> {
    let mut prev = B256::ZERO;
    for (expected_seq, entry) in (0u64..).zip(entries) {
        if entry.seq != expected_seq
            || entry.prev_hash != prev
            || entry.entry_hash != entry.compute_hash()
        {
            return Err(AuditError::BrokenChain { seq: expected_seq });
        }
        prev = entry.entry_hash;
    }
    Ok(())
}

/// Where the audit log is stored.
pub trait AuditSink {
    fn persist(&mut self, entry: &AuditEntry) -> Result<(), AuditError>;
}

/// A store that only keeps entries in memory (for tests).
#[derive(Default)]
pub struct MemorySink {
    pub entries: Vec<AuditEntry>,
}

impl AuditSink for MemorySink {
    fn persist(&mut self, entry: &AuditEntry) -> Result<(), AuditError> {
        self.entries.push(entry.clone());
        Ok(())
    }
}

/// A JSON Lines file with one entry per line. Fsyncs after every write.
pub struct JsonlSink {
    path: PathBuf,
    file: File,
}

impl JsonlSink {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AuditError> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self { path, file })
    }

    pub fn load(&self) -> Result<Vec<AuditEntry>, AuditError> {
        let reader = BufReader::new(File::open(&self.path)?);
        let mut entries = Vec::new();
        for (index, line) in reader.lines().enumerate() {
            let line = line?;
            entries.push(
                serde_json::from_str(&line).map_err(|source| AuditError::Parse {
                    line: index + 1,
                    source,
                })?,
            );
        }
        Ok(entries)
    }
}

impl AuditSink for JsonlSink {
    fn persist(&mut self, entry: &AuditEntry) -> Result<(), AuditError> {
        let mut line = serde_json::to_vec(entry).map_err(io::Error::other)?;
        line.push(b'\n');
        self.file.write_all(&line)?;
        self.file.sync_data()?;
        Ok(())
    }
}

pub struct AuditLog<S> {
    sink: S,
    next_seq: u64,
    head: B256,
}

impl<S: AuditSink> AuditLog<S> {
    pub fn new(sink: S) -> Self {
        Self {
            sink,
            next_seq: 0,
            head: B256::ZERO,
        }
    }

    /// Verify the existing entries, then open the log to append after them.
    pub fn resume(sink: S, existing: &[AuditEntry]) -> Result<Self, AuditError> {
        verify_chain(existing)?;
        Ok(Self {
            sink,
            next_seq: existing.len() as u64,
            head: existing.last().map_or(B256::ZERO, |e| e.entry_hash),
        })
    }

    /// Append and return the hash of the new entry (the head of the chain).
    pub fn append(&mut self, record: AuditRecord, timestamp_unix: u64) -> Result<B256, AuditError> {
        let mut entry = AuditEntry {
            seq: self.next_seq,
            timestamp_unix,
            prev_hash: self.head,
            record,
            entry_hash: B256::ZERO,
        };
        entry.entry_hash = entry.compute_hash();
        self.sink.persist(&entry)?;
        self.next_seq += 1;
        self.head = entry.entry_hash;
        Ok(entry.entry_hash)
    }

    pub fn head(&self) -> B256 {
        self.head
    }

    pub fn sink(&self) -> &S {
        &self.sink
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(verdict: Verdict) -> AuditRecord {
        AuditRecord {
            wallet: Address::repeat_byte(1),
            proposal_hash: B256::repeat_byte(2),
            input_summary: "transfer 0.01 ETH".into(),
            policy_hash: Some(B256::repeat_byte(3)),
            simulation_hash: Some(B256::repeat_byte(4)),
            verdict,
            reasons: vec!["within daily limit".into()],
        }
    }

    fn log_with_three() -> AuditLog<MemorySink> {
        let mut log = AuditLog::new(MemorySink::default());
        for (t, v) in [
            (1, Verdict::Approve),
            (2, Verdict::Reject),
            (3, Verdict::Approve),
        ] {
            log.append(record(v), t).unwrap();
        }
        log
    }

    #[test]
    fn valid_chain_verifies() {
        let log = log_with_three();
        verify_chain(&log.sink().entries).unwrap();
        assert_eq!(log.head(), log.sink().entries[2].entry_hash);
    }

    #[test]
    fn detects_modified_record() {
        let mut entries = log_with_three().sink().entries.clone();
        entries[1].record.verdict = Verdict::Approve;
        assert!(matches!(
            verify_chain(&entries),
            Err(AuditError::BrokenChain { seq: 1 })
        ));
    }

    #[test]
    fn detects_recomputed_entry_hash() {
        // Even with the tampered entry's hash recomputed, it no longer matches the next entry's prev_hash
        let mut entries = log_with_three().sink().entries.clone();
        entries[1].record.verdict = Verdict::Approve;
        entries[1].entry_hash = entries[1].compute_hash();
        assert!(matches!(
            verify_chain(&entries),
            Err(AuditError::BrokenChain { seq: 2 })
        ));
    }

    #[test]
    fn detects_deleted_and_reordered_entries() {
        let entries = log_with_three().sink().entries.clone();

        let mut deleted = entries.clone();
        deleted.remove(1);
        assert!(verify_chain(&deleted).is_err());

        let mut reordered = entries;
        reordered.swap(0, 1);
        assert!(verify_chain(&reordered).is_err());
    }

    #[test]
    fn jsonl_round_trip_and_resume() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");

        let mut log = AuditLog::new(JsonlSink::open(&path).unwrap());
        log.append(record(Verdict::Approve), 1).unwrap();
        log.append(record(Verdict::Reject), 2).unwrap();
        let head = log.head();
        drop(log);

        let sink = JsonlSink::open(&path).unwrap();
        let existing = sink.load().unwrap();
        let mut resumed = AuditLog::resume(sink, &existing).unwrap();
        assert_eq!(resumed.head(), head);
        resumed.append(record(Verdict::Approve), 3).unwrap();

        let all = JsonlSink::open(&path).unwrap().load().unwrap();
        assert_eq!(all.len(), 3);
        verify_chain(&all).unwrap();
    }

    #[test]
    fn resume_refuses_broken_chain() {
        let mut entries = log_with_three().sink().entries.clone();
        entries[0].timestamp_unix = 99;
        assert!(AuditLog::resume(MemorySink::default(), &entries).is_err());
    }
}
