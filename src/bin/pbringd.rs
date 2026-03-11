use log::{error, info, warn};
use pbring::config::Config;
use pbring::crypto::EncryptionKey;
use pbring::db::Database;
use pbring::pasteboard::PasteboardReader;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    if let Err(e) = run() {
        error!("Fatal error: {e}");
        std::process::exit(1);
    }
}

fn run() -> pbring::error::Result<()> {
    let config = Config::load()?;
    info!("Config loaded (poll={}ms, max_entries={}, ttl={}s)",
        config.poll_interval_ms, config.max_entries, config.ttl_seconds);

    let key = EncryptionKey::load_or_create()?;
    info!("Encryption key loaded");

    let db_path = Config::db_path();
    let db = Database::open(&db_path)?;
    info!("Database opened at {}", db_path.display());

    let mut reader = PasteboardReader::new(&config);
    reader.init_change_count();
    info!("Pasteboard reader initialized");

    // Write PID file
    let pid_path = Config::pid_path();
    write_pid_file(&pid_path)?;
    info!("PID file written to {}", pid_path.display());

    // Signal handling
    let running = Arc::new(AtomicBool::new(true));
    {
        let r = running.clone();
        signal_hook::flag::register(signal_hook::consts::SIGTERM, r.clone())
            .map_err(|e| pbring::error::PbringError::Io(e))?;
        signal_hook::flag::register(signal_hook::consts::SIGINT, r)
            .map_err(|e| pbring::error::PbringError::Io(e))?;
    }

    let poll_duration = Duration::from_millis(config.poll_interval_ms);
    let ttl_check_interval = Duration::from_secs(300); // 5 minutes
    let mut last_ttl_check = Instant::now();
    let mut last_content_hash: Option<[u8; 32]> = None;

    info!("Daemon started, polling every {}ms", config.poll_interval_ms);

    while running.load(Ordering::Relaxed) {
        // Poll pasteboard
        if let Some(content) = reader.poll() {
            // Size check
            if content.data.len() > config.max_entry_bytes {
                info!("Skipping entry: too large ({} bytes)", content.data.len());
            } else if !config.record_types.contains(&content.media_type.to_string()) {
                info!("Skipping entry: type {} not in record_types", content.media_type);
            } else {
                // Dedup: hash comparison
                let hash = Sha256::digest(&content.data);
                let hash_arr: [u8; 32] = hash.into();

                if last_content_hash.as_ref() == Some(&hash_arr) {
                    info!("Skipping duplicate content");
                } else {
                    last_content_hash = Some(hash_arr);

                    match key.encrypt(&content.data) {
                        Ok((ciphertext, nonce)) => {
                            let timestamp = chrono::Utc::now().to_rfc3339();
                            match db.insert_entry(
                                &timestamp,
                                &ciphertext,
                                &nonce,
                                content.media_type,
                                &content.preview,
                                content.data.len() as i64,
                                content.source_app.as_deref(),
                            ) {
                                Ok(id) => {
                                    info!("Recorded entry #{id}: {} ({} bytes)",
                                        content.media_type, content.data.len());

                                    // Enforce max_entries
                                    if let Err(e) = db.delete_oldest_beyond(config.max_entries) {
                                        warn!("Failed to enforce max_entries: {e}");
                                    }
                                }
                                Err(e) => warn!("Failed to insert entry: {e}"),
                            }
                        }
                        Err(e) => warn!("Failed to encrypt entry: {e}"),
                    }
                }
            }
        }

        // Periodic TTL cleanup
        if config.ttl_seconds > 0 && last_ttl_check.elapsed() >= ttl_check_interval {
            match db.delete_expired(config.ttl_seconds) {
                Ok(n) if n > 0 => info!("Deleted {n} expired entries"),
                Ok(_) => {}
                Err(e) => warn!("Failed to delete expired entries: {e}"),
            }
            last_ttl_check = Instant::now();
        }

        std::thread::sleep(poll_duration);
    }

    info!("Shutting down...");

    // Cleanup PID file
    if pid_path.exists() {
        let _ = std::fs::remove_file(&pid_path);
    }

    info!("Daemon stopped");
    Ok(())
}

fn write_pid_file(path: &std::path::Path) -> pbring::error::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Check for stale PID file
    if path.exists() {
        if let Ok(content) = std::fs::read_to_string(path) {
            if let Ok(pid) = content.trim().parse::<i32>() {
                // Check if process is still running
                let result = unsafe { libc::kill(pid, 0) };
                if result == 0 {
                    return Err(pbring::error::PbringError::Io(std::io::Error::new(
                        std::io::ErrorKind::AddrInUse,
                        format!("Another pbringd is already running (pid: {pid})"),
                    )));
                }
                // Stale PID file, will be overwritten
                info!("Removing stale PID file (pid: {pid})");
            }
        }
    }

    std::fs::write(path, std::process::id().to_string())?;
    Ok(())
}
