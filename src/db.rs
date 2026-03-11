use crate::error::{PbringError, Result};
use crate::types::{EncryptedEntry, Entry, MediaType};
use rusqlite::{params, Connection};
use std::path::Path;

pub struct Database {
    conn: Connection,
}

impl Database {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        let db = Self { conn };
        db.migrate()?;
        Ok(db)
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let db = Self { conn };
        db.migrate()?;
        Ok(db)
    }

    fn migrate(&self) -> Result<()> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS entries (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT NOT NULL,
                content     BLOB NOT NULL,
                nonce       BLOB NOT NULL,
                media_type  TEXT NOT NULL,
                preview     TEXT NOT NULL,
                byte_size   INTEGER NOT NULL,
                source_app  TEXT,
                created_at  TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_timestamp ON entries(timestamp);
            CREATE INDEX IF NOT EXISTS idx_media_type ON entries(media_type);",
        )?;
        Ok(())
    }

    pub fn insert_entry(
        &self,
        timestamp: &str,
        content: &[u8],
        nonce: &[u8],
        media_type: MediaType,
        preview: &str,
        byte_size: i64,
        source_app: Option<&str>,
    ) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO entries (timestamp, content, nonce, media_type, preview, byte_size, source_app)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                timestamp,
                content,
                nonce,
                media_type.to_string(),
                preview,
                byte_size,
                source_app,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn list_entries(
        &self,
        limit: usize,
        type_filter: Option<MediaType>,
    ) -> Result<Vec<Entry>> {
        let (sql, type_str);
        let params: Vec<Box<dyn rusqlite::types::ToSql>> = if let Some(mt) = type_filter {
            type_str = mt.to_string();
            sql = "SELECT id, timestamp, media_type, preview, byte_size, source_app
                   FROM entries WHERE media_type = ?1 ORDER BY id DESC LIMIT ?2";
            vec![
                Box::new(type_str.clone()),
                Box::new(limit as i64),
            ]
        } else {
            sql = "SELECT id, timestamp, media_type, preview, byte_size, source_app
                   FROM entries ORDER BY id DESC LIMIT ?1";
            vec![Box::new(limit as i64)]
        };

        let param_refs: Vec<&dyn rusqlite::types::ToSql> = params.iter().map(|p| p.as_ref()).collect();
        let mut stmt = self.conn.prepare(sql)?;
        let entries = stmt
            .query_map(param_refs.as_slice(), |row| {
                let mt_str: String = row.get(2)?;
                Ok(Entry {
                    id: row.get(0)?,
                    timestamp: row.get(1)?,
                    media_type: MediaType::from_str(&mt_str).unwrap_or(MediaType::Other),
                    preview: row.get(3)?,
                    byte_size: row.get(4)?,
                    source_app: row.get(5)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(entries)
    }

    pub fn get_entry(&self, id: i64) -> Result<EncryptedEntry> {
        let mut stmt = self.conn.prepare(
            "SELECT id, timestamp, content, nonce, media_type, preview, byte_size, source_app
             FROM entries WHERE id = ?1",
        )?;
        let entry = stmt
            .query_row(params![id], |row| {
                let mt_str: String = row.get(4)?;
                Ok(EncryptedEntry {
                    id: row.get(0)?,
                    timestamp: row.get(1)?,
                    content: row.get(2)?,
                    nonce: row.get(3)?,
                    media_type: MediaType::from_str(&mt_str).unwrap_or(MediaType::Other),
                    preview: row.get(5)?,
                    byte_size: row.get(6)?,
                    source_app: row.get(7)?,
                })
            })
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => PbringError::EntryNotFound(id),
                other => PbringError::Db(other),
            })?;
        Ok(entry)
    }

    pub fn delete_entry(&self, id: i64) -> Result<bool> {
        let count = self
            .conn
            .execute("DELETE FROM entries WHERE id = ?1", params![id])?;
        Ok(count > 0)
    }

    pub fn clear(&self) -> Result<()> {
        self.conn.execute("DELETE FROM entries", [])?;
        Ok(())
    }

    pub fn delete_expired(&self, ttl_seconds: u64) -> Result<usize> {
        let count = self.conn.execute(
            "DELETE FROM entries WHERE datetime(timestamp) < datetime('now', ?1)",
            params![format!("-{ttl_seconds} seconds")],
        )?;
        Ok(count)
    }

    pub fn delete_oldest_beyond(&self, max_entries: usize) -> Result<usize> {
        let count = self.conn.execute(
            "DELETE FROM entries WHERE id NOT IN (
                SELECT id FROM entries ORDER BY id DESC LIMIT ?1
            )",
            params![max_entries as i64],
        )?;
        Ok(count)
    }

    pub fn entry_count(&self) -> Result<usize> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM entries", [], |row| row.get(0))?;
        Ok(count as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert_and_list() {
        let db = Database::open_in_memory().unwrap();
        let id = db
            .insert_entry(
                "2024-01-01T00:00:00Z",
                b"encrypted_content",
                b"nonce123456!",
                MediaType::Text,
                "hello world",
                11,
                Some("com.apple.Terminal"),
            )
            .unwrap();
        assert!(id > 0);

        let entries = db.list_entries(10, None).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].preview, "hello world");
        assert_eq!(entries[0].media_type, MediaType::Text);
    }

    #[test]
    fn test_get_entry() {
        let db = Database::open_in_memory().unwrap();
        let id = db
            .insert_entry(
                "2024-01-01T00:00:00Z",
                b"encrypted",
                b"nonce123456!",
                MediaType::Image,
                "[image 100x100 PNG]",
                5000,
                None,
            )
            .unwrap();

        let entry = db.get_entry(id).unwrap();
        assert_eq!(entry.content, b"encrypted");
        assert_eq!(entry.nonce, b"nonce123456!");
        assert_eq!(entry.media_type, MediaType::Image);
    }

    #[test]
    fn test_entry_not_found() {
        let db = Database::open_in_memory().unwrap();
        let result = db.get_entry(999);
        assert!(matches!(result, Err(PbringError::EntryNotFound(999))));
    }

    #[test]
    fn test_delete_entry() {
        let db = Database::open_in_memory().unwrap();
        let id = db
            .insert_entry(
                "2024-01-01T00:00:00Z",
                b"data",
                b"nonce123456!",
                MediaType::Text,
                "test",
                4,
                None,
            )
            .unwrap();

        assert!(db.delete_entry(id).unwrap());
        assert!(!db.delete_entry(id).unwrap());
    }

    #[test]
    fn test_clear() {
        let db = Database::open_in_memory().unwrap();
        for i in 0..5 {
            db.insert_entry(
                &format!("2024-01-0{i}T00:00:00Z"),
                b"data",
                b"nonce123456!",
                MediaType::Text,
                "test",
                4,
                None,
            )
            .unwrap();
        }
        assert_eq!(db.entry_count().unwrap(), 5);
        db.clear().unwrap();
        assert_eq!(db.entry_count().unwrap(), 0);
    }

    #[test]
    fn test_delete_oldest_beyond() {
        let db = Database::open_in_memory().unwrap();
        for i in 1..=5 {
            db.insert_entry(
                &format!("2024-01-0{i}T00:00:00Z"),
                b"data",
                b"nonce123456!",
                MediaType::Text,
                &format!("entry {i}"),
                4,
                None,
            )
            .unwrap();
        }

        let deleted = db.delete_oldest_beyond(3).unwrap();
        assert_eq!(deleted, 2);
        assert_eq!(db.entry_count().unwrap(), 3);

        let entries = db.list_entries(10, None).unwrap();
        assert_eq!(entries[0].preview, "entry 5");
        assert_eq!(entries[2].preview, "entry 3");
    }

    #[test]
    fn test_type_filter() {
        let db = Database::open_in_memory().unwrap();
        db.insert_entry(
            "2024-01-01T00:00:00Z",
            b"data",
            b"nonce123456!",
            MediaType::Text,
            "text entry",
            4,
            None,
        )
        .unwrap();
        db.insert_entry(
            "2024-01-01T00:00:01Z",
            b"data",
            b"nonce123456!",
            MediaType::Image,
            "[image]",
            1000,
            None,
        )
        .unwrap();

        let text_only = db.list_entries(10, Some(MediaType::Text)).unwrap();
        assert_eq!(text_only.len(), 1);
        assert_eq!(text_only[0].preview, "text entry");

        let image_only = db.list_entries(10, Some(MediaType::Image)).unwrap();
        assert_eq!(image_only.len(), 1);
    }
}
