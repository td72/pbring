use clap::{Parser, Subcommand};
use pbring::config::Config;
use pbring::crypto::EncryptionKey;
use pbring::db::Database;
use pbring::types::MediaType;
use std::io::{self, BufRead, Write};

#[derive(Parser)]
#[command(name = "pbring", about = "Secure macOS clipboard history CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List clipboard history entries
    List {
        /// Maximum number of entries to show
        #[arg(short, long, default_value = "100")]
        limit: usize,

        /// Filter by media type (text, image, file)
        #[arg(short = 't', long = "type")]
        type_filter: Option<String>,
    },

    /// Decrypt and output an entry (reads ID from stdin)
    Decrypt,

    /// Delete an entry (reads ID from stdin)
    Delete,

    /// Clear all entries
    Clear,

    /// Securely wipe all entries and the database file
    Wipe,
}

fn main() {
    let cli = Cli::parse();

    if let Err(e) = run(cli) {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> pbring::error::Result<()> {
    match cli.command {
        Commands::List { limit, type_filter } => cmd_list(limit, type_filter),
        Commands::Decrypt => cmd_decrypt(),
        Commands::Delete => cmd_delete(),
        Commands::Clear => cmd_clear(),
        Commands::Wipe => cmd_wipe(),
    }
}

fn cmd_list(limit: usize, type_filter: Option<String>) -> pbring::error::Result<()> {
    let db_path = Config::db_path();
    if !db_path.exists() {
        return Ok(());
    }
    let db = Database::open(&db_path)?;
    let filter = type_filter.and_then(|s| MediaType::from_str(&s));
    let entries = db.list_entries(limit, filter)?;

    let stdout = io::stdout();
    let mut out = stdout.lock();
    for entry in &entries {
        writeln!(
            out,
            "{}\t{}\t{}\t{}",
            entry.id, entry.timestamp, entry.media_type, entry.preview
        )
        .ok();
    }
    Ok(())
}

fn parse_id_from_stdin() -> pbring::error::Result<i64> {
    let stdin = io::stdin();
    let line = stdin
        .lock()
        .lines()
        .next()
        .ok_or_else(|| {
            pbring::error::PbringError::Config("no input on stdin".into())
        })?
        .map_err(pbring::error::PbringError::Io)?;

    let id_str = line.split('\t').next().unwrap_or(&line);
    id_str
        .trim()
        .parse::<i64>()
        .map_err(|e| pbring::error::PbringError::Config(format!("invalid ID: {e}")))
}

fn cmd_decrypt() -> pbring::error::Result<()> {
    let id = parse_id_from_stdin()?;
    let db_path = Config::db_path();
    let db = Database::open(&db_path)?;
    let entry = db.get_entry(id)?;
    let key = EncryptionKey::load_or_create()?;
    let plaintext = key.decrypt(&entry.content, &entry.nonce)?;

    let stdout = io::stdout();
    let mut out = stdout.lock();
    out.write_all(&plaintext)
        .map_err(pbring::error::PbringError::Io)?;
    out.flush().map_err(pbring::error::PbringError::Io)?;
    // plaintext is Zeroizing<Vec<u8>>, will be zeroized on drop
    Ok(())
}

fn cmd_delete() -> pbring::error::Result<()> {
    let id = parse_id_from_stdin()?;
    let db_path = Config::db_path();
    let db = Database::open(&db_path)?;
    if !db.delete_entry(id)? {
        return Err(pbring::error::PbringError::EntryNotFound(id));
    }
    Ok(())
}

fn cmd_clear() -> pbring::error::Result<()> {
    let db_path = Config::db_path();
    if !db_path.exists() {
        return Ok(());
    }
    let db = Database::open(&db_path)?;
    db.clear()?;
    Ok(())
}

fn cmd_wipe() -> pbring::error::Result<()> {
    let db_path = Config::db_path();
    if !db_path.exists() {
        return Ok(());
    }

    // Clear all entries first
    {
        let db = Database::open(&db_path)?;
        db.clear()?;
    }

    // Zero-fill the file
    let metadata = std::fs::metadata(&db_path)?;
    let size = metadata.len() as usize;
    let zeros = vec![0u8; size];
    std::fs::write(&db_path, &zeros)?;

    // Delete the file
    std::fs::remove_file(&db_path)?;

    Ok(())
}
