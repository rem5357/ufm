//! Streaming File Transfers
//!
//! Handles large file transfers between UFM nodes using chunked streaming.

use std::collections::HashMap;
use std::hash::Hasher;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::RwLock;
use uuid::Uuid;

use super::config::Compression;
use super::protocol::PeerMessage;

/// Default chunk size for streaming (64KB)
pub const DEFAULT_CHUNK_SIZE: usize = 64 * 1024;

/// Maximum chunk size (1MB)
pub const MAX_CHUNK_SIZE: usize = 1024 * 1024;

/// Transfer state
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferState {
    /// Transfer is queued but not started
    Pending,
    /// Transfer is in progress
    InProgress,
    /// Transfer is paused
    Paused,
    /// Transfer completed successfully
    Completed,
    /// Transfer failed
    Failed(String),
    /// Transfer was aborted
    Aborted(String),
}

/// Direction of transfer
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferDirection {
    /// Sending data to a peer
    Outgoing,
    /// Receiving data from a peer
    Incoming,
}

/// Information about an active or completed transfer
#[derive(Debug, Clone)]
pub struct TransferInfo {
    /// Unique transfer ID
    pub id: u64,
    /// Source path (local or remote)
    pub source_path: String,
    /// Destination path (local or remote)
    pub dest_path: String,
    /// Remote peer UUID
    pub peer_uuid: Uuid,
    /// Transfer direction
    pub direction: TransferDirection,
    /// Total size in bytes (if known)
    pub total_bytes: Option<u64>,
    /// Bytes transferred so far
    pub transferred_bytes: u64,
    /// Current state
    pub state: TransferState,
    /// Compression being used
    pub compression: Compression,
    /// Start time
    pub started_at: Option<Instant>,
    /// Completion time
    pub completed_at: Option<Instant>,
}

impl TransferInfo {
    /// Calculate transfer speed in bytes per second
    pub fn bytes_per_second(&self) -> f64 {
        let elapsed = match (self.started_at, self.completed_at) {
            (Some(start), Some(end)) => end.duration_since(start).as_secs_f64(),
            (Some(start), None) => start.elapsed().as_secs_f64(),
            _ => return 0.0,
        };

        if elapsed > 0.0 {
            self.transferred_bytes as f64 / elapsed
        } else {
            0.0
        }
    }

    /// Get progress as a percentage (0-100)
    pub fn progress_percent(&self) -> f64 {
        match self.total_bytes {
            Some(total) if total > 0 => {
                (self.transferred_bytes as f64 / total as f64) * 100.0
            }
            _ => 0.0,
        }
    }
}

/// Incoming transfer receiver state
struct IncomingTransfer {
    info: TransferInfo,
    file: Option<tokio::fs::File>,
    expected_sequence: u64,
    checksum_hasher: Option<xxhash_rust::xxh3::Xxh3>,
}

/// Outgoing transfer sender state
struct OutgoingTransfer {
    info: TransferInfo,
    file: Option<tokio::fs::File>,
    current_sequence: u64,
    chunk_size: usize,
}

/// Manages streaming file transfers
pub struct TransferManager {
    /// Active incoming transfers
    incoming: RwLock<HashMap<u64, IncomingTransfer>>,
    /// Active outgoing transfers
    outgoing: RwLock<HashMap<u64, OutgoingTransfer>>,
    /// Next transfer ID
    next_id: AtomicU64,
    /// Chunk size for outgoing transfers
    chunk_size: usize,
    /// Default compression
    default_compression: Compression,
}

impl TransferManager {
    /// Create a new transfer manager
    pub fn new(chunk_size: usize, default_compression: Compression) -> Self {
        Self {
            incoming: RwLock::new(HashMap::new()),
            outgoing: RwLock::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            chunk_size: chunk_size.min(MAX_CHUNK_SIZE),
            default_compression,
        }
    }

    /// Generate a new transfer ID
    pub fn next_transfer_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::SeqCst)
    }

    /// Start receiving a file from a peer
    pub async fn start_incoming(
        &self,
        transfer_id: u64,
        peer_uuid: Uuid,
        source_path: String,
        dest_path: &Path,
        total_size: u64,
        compression: Compression,
    ) -> anyhow::Result<()> {
        // Create parent directories if needed
        if let Some(parent) = dest_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        // Open destination file
        let file = tokio::fs::File::create(dest_path).await?;

        let info = TransferInfo {
            id: transfer_id,
            source_path,
            dest_path: dest_path.to_string_lossy().to_string(),
            peer_uuid,
            direction: TransferDirection::Incoming,
            total_bytes: Some(total_size),
            transferred_bytes: 0,
            state: TransferState::InProgress,
            compression,
            started_at: Some(Instant::now()),
            completed_at: None,
        };

        let transfer = IncomingTransfer {
            info,
            file: Some(file),
            expected_sequence: 0,
            checksum_hasher: Some(xxhash_rust::xxh3::Xxh3::new()),
        };

        self.incoming.write().await.insert(transfer_id, transfer);
        tracing::info!(
            "Started incoming transfer {} from peer {} -> {}",
            transfer_id,
            peer_uuid,
            dest_path.display()
        );

        Ok(())
    }

    /// Process incoming data chunk
    pub async fn receive_chunk(
        &self,
        transfer_id: u64,
        sequence: u64,
        data: Vec<u8>,
    ) -> anyhow::Result<u64> {
        let mut incoming = self.incoming.write().await;
        let transfer = incoming
            .get_mut(&transfer_id)
            .ok_or_else(|| anyhow::anyhow!("Unknown transfer: {}", transfer_id))?;

        // Verify sequence
        if sequence != transfer.expected_sequence {
            anyhow::bail!(
                "Out of sequence chunk: expected {}, got {}",
                transfer.expected_sequence,
                sequence
            );
        }

        // Decompress if needed
        let decompressed = match transfer.info.compression {
            Compression::None => data,
            Compression::Gzip => decompress_gzip(&data)?,
            Compression::Zstd => decompress_zstd(&data)?,
        };

        // Write to file
        if let Some(ref mut file) = transfer.file {
            file.write_all(&decompressed).await?;
        }

        // Update checksum
        if let Some(ref mut hasher) = transfer.checksum_hasher {
            hasher.update(&decompressed);
        }

        // Update state
        transfer.info.transferred_bytes += decompressed.len() as u64;
        transfer.expected_sequence += 1;

        Ok(transfer.info.transferred_bytes)
    }

    /// Complete an incoming transfer
    pub async fn complete_incoming(
        &self,
        transfer_id: u64,
        expected_checksum: Option<&str>,
    ) -> anyhow::Result<TransferInfo> {
        let mut incoming = self.incoming.write().await;
        let mut transfer = incoming
            .remove(&transfer_id)
            .ok_or_else(|| anyhow::anyhow!("Unknown transfer: {}", transfer_id))?;

        // Finalize file
        if let Some(mut file) = transfer.file.take() {
            file.flush().await?;
        }

        // Verify checksum if provided
        if let (Some(expected), Some(hasher)) = (expected_checksum, transfer.checksum_hasher.take()) {
            let actual = format!("{:016x}", hasher.finish());
            if actual != expected {
                transfer.info.state = TransferState::Failed(format!(
                    "Checksum mismatch: expected {}, got {}",
                    expected, actual
                ));
                return Ok(transfer.info);
            }
        }

        transfer.info.state = TransferState::Completed;
        transfer.info.completed_at = Some(Instant::now());

        tracing::info!(
            "Completed incoming transfer {} ({} bytes in {:.2}s, {:.2} MB/s)",
            transfer_id,
            transfer.info.transferred_bytes,
            transfer.info.started_at.map(|s| s.elapsed().as_secs_f64()).unwrap_or(0.0),
            transfer.info.bytes_per_second() / 1_000_000.0
        );

        Ok(transfer.info)
    }

    /// Abort an incoming transfer
    pub async fn abort_incoming(&self, transfer_id: u64, reason: String) -> anyhow::Result<()> {
        let mut incoming = self.incoming.write().await;
        if let Some(mut transfer) = incoming.remove(&transfer_id) {
            transfer.info.state = TransferState::Aborted(reason.clone());

            // Try to clean up partial file
            let dest_path = PathBuf::from(&transfer.info.dest_path);
            let _ = tokio::fs::remove_file(&dest_path).await;

            tracing::warn!("Aborted incoming transfer {}: {}", transfer_id, reason);
        }
        Ok(())
    }

    /// Start sending a file to a peer
    pub async fn start_outgoing(
        &self,
        peer_uuid: Uuid,
        source_path: &Path,
        dest_path: String,
        compression: Option<Compression>,
    ) -> anyhow::Result<(u64, PeerMessage)> {
        let transfer_id = self.next_transfer_id();

        // Get file info
        let metadata = tokio::fs::metadata(source_path).await?;
        let total_size = metadata.len();
        let is_directory = metadata.is_dir();

        if is_directory {
            anyhow::bail!("Directory streaming not yet implemented - use archive tools");
        }

        // Open source file
        let file = tokio::fs::File::open(source_path).await?;

        let compression = compression.unwrap_or(self.default_compression);

        let info = TransferInfo {
            id: transfer_id,
            source_path: source_path.to_string_lossy().to_string(),
            dest_path: dest_path.clone(),
            peer_uuid,
            direction: TransferDirection::Outgoing,
            total_bytes: Some(total_size),
            transferred_bytes: 0,
            state: TransferState::InProgress,
            compression,
            started_at: Some(Instant::now()),
            completed_at: None,
        };

        let transfer = OutgoingTransfer {
            info,
            file: Some(file),
            current_sequence: 0,
            chunk_size: self.chunk_size,
        };

        self.outgoing.write().await.insert(transfer_id, transfer);

        // Create StreamStart message
        let start_msg = PeerMessage::StreamStart {
            transfer_id,
            path: dest_path,
            size: total_size,
            is_directory,
            compression,
        };

        tracing::info!(
            "Starting outgoing transfer {} to peer {} ({} bytes)",
            transfer_id,
            peer_uuid,
            total_size
        );

        Ok((transfer_id, start_msg))
    }

    /// Get next chunk of data for an outgoing transfer
    pub async fn get_next_chunk(&self, transfer_id: u64) -> anyhow::Result<Option<PeerMessage>> {
        let mut outgoing = self.outgoing.write().await;
        let transfer = outgoing
            .get_mut(&transfer_id)
            .ok_or_else(|| anyhow::anyhow!("Unknown transfer: {}", transfer_id))?;

        let file = transfer.file.as_mut()
            .ok_or_else(|| anyhow::anyhow!("Transfer file already closed"))?;

        // Read chunk
        let mut buffer = vec![0u8; transfer.chunk_size];
        let bytes_read = file.read(&mut buffer).await?;

        if bytes_read == 0 {
            return Ok(None); // End of file
        }

        buffer.truncate(bytes_read);

        // Compress if needed
        let data = match transfer.info.compression {
            Compression::None => buffer,
            Compression::Gzip => compress_gzip(&buffer)?,
            Compression::Zstd => compress_zstd(&buffer)?,
        };

        let sequence = transfer.current_sequence;
        transfer.current_sequence += 1;
        transfer.info.transferred_bytes += bytes_read as u64;

        Ok(Some(PeerMessage::StreamData {
            transfer_id,
            sequence,
            data,
        }))
    }

    /// Complete an outgoing transfer
    pub async fn complete_outgoing(&self, transfer_id: u64) -> anyhow::Result<(TransferInfo, PeerMessage)> {
        let mut outgoing = self.outgoing.write().await;
        let mut transfer = outgoing
            .remove(&transfer_id)
            .ok_or_else(|| anyhow::anyhow!("Unknown transfer: {}", transfer_id))?;

        transfer.info.state = TransferState::Completed;
        transfer.info.completed_at = Some(Instant::now());

        // Calculate checksum of original file for verification
        let checksum = if transfer.info.total_bytes.unwrap_or(0) < 100 * 1024 * 1024 {
            // Only calculate for files under 100MB
            calculate_file_checksum(&transfer.info.source_path).await.ok()
        } else {
            None
        };

        let end_msg = PeerMessage::StreamEnd {
            transfer_id,
            checksum,
        };

        tracing::info!(
            "Completed outgoing transfer {} ({} bytes in {:.2}s, {:.2} MB/s)",
            transfer_id,
            transfer.info.transferred_bytes,
            transfer.info.started_at.map(|s| s.elapsed().as_secs_f64()).unwrap_or(0.0),
            transfer.info.bytes_per_second() / 1_000_000.0
        );

        Ok((transfer.info, end_msg))
    }

    /// Abort an outgoing transfer
    pub async fn abort_outgoing(&self, transfer_id: u64, reason: String) -> anyhow::Result<PeerMessage> {
        let mut outgoing = self.outgoing.write().await;
        if let Some(mut transfer) = outgoing.remove(&transfer_id) {
            transfer.info.state = TransferState::Aborted(reason.clone());
            tracing::warn!("Aborted outgoing transfer {}: {}", transfer_id, reason);
        }

        Ok(PeerMessage::StreamAbort {
            transfer_id,
            reason,
        })
    }

    /// Get status of a transfer
    pub async fn get_transfer_info(&self, transfer_id: u64) -> Option<TransferInfo> {
        if let Some(t) = self.incoming.read().await.get(&transfer_id) {
            return Some(t.info.clone());
        }
        if let Some(t) = self.outgoing.read().await.get(&transfer_id) {
            return Some(t.info.clone());
        }
        None
    }

    /// List all active transfers
    pub async fn list_transfers(&self) -> Vec<TransferInfo> {
        let mut transfers = Vec::new();

        for t in self.incoming.read().await.values() {
            transfers.push(t.info.clone());
        }
        for t in self.outgoing.read().await.values() {
            transfers.push(t.info.clone());
        }

        transfers
    }
}

// Compression helpers

fn compress_gzip(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    use flate2::write::GzEncoder;
    use flate2::Compression;

    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(data)?;
    Ok(encoder.finish()?)
}

fn decompress_gzip(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    use flate2::read::GzDecoder;

    let mut decoder = GzDecoder::new(data);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed)?;
    Ok(decompressed)
}

fn compress_zstd(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    Ok(zstd::encode_all(std::io::Cursor::new(data), 3)?)
}

fn decompress_zstd(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    Ok(zstd::decode_all(std::io::Cursor::new(data))?)
}

async fn calculate_file_checksum(path: &str) -> anyhow::Result<String> {
    let data = tokio::fs::read(path).await?;
    let hash = xxhash_rust::xxh3::xxh3_64(&data);
    Ok(format!("{:016x}", hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compression_roundtrip() {
        let data = b"Hello, world! This is a test of compression.".repeat(100);

        // Gzip
        let compressed = compress_gzip(&data).unwrap();
        let decompressed = decompress_gzip(&compressed).unwrap();
        assert_eq!(data, decompressed.as_slice());

        // Zstd
        let compressed = compress_zstd(&data).unwrap();
        let decompressed = decompress_zstd(&compressed).unwrap();
        assert_eq!(data, decompressed.as_slice());
    }

    #[test]
    fn test_transfer_info_progress() {
        let mut info = TransferInfo {
            id: 1,
            source_path: "/test/source".to_string(),
            dest_path: "/test/dest".to_string(),
            peer_uuid: Uuid::new_v4(),
            direction: TransferDirection::Outgoing,
            total_bytes: Some(1000),
            transferred_bytes: 500,
            state: TransferState::InProgress,
            compression: Compression::None,
            started_at: None,
            completed_at: None,
        };

        assert!((info.progress_percent() - 50.0).abs() < 0.01);

        info.transferred_bytes = 1000;
        assert!((info.progress_percent() - 100.0).abs() < 0.01);
    }
}
