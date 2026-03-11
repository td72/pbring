use pbring::crypto::EncryptionKey;
use pbring::db::Database;
use pbring::types::MediaType;

fn test_key() -> EncryptionKey {
    EncryptionKey::from_bytes([42u8; 32])
}

#[test]
fn full_flow_insert_list_decrypt() {
    let db = Database::open_in_memory().unwrap();
    let key = test_key();

    let plaintext = b"Hello from pbring test!";
    let (ciphertext, nonce) = key.encrypt(plaintext).unwrap();
    let timestamp = "2026-03-11T12:00:00+00:00";

    let id = db
        .insert_entry(
            timestamp,
            &ciphertext,
            &nonce,
            MediaType::Text,
            "Hello from pbring test!",
            plaintext.len() as i64,
            Some("com.apple.Terminal"),
        )
        .unwrap();

    // list
    let entries = db.list_entries(100, None).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].id, id);
    assert_eq!(entries[0].media_type, MediaType::Text);
    assert_eq!(entries[0].preview, "Hello from pbring test!");

    // decrypt
    let entry = db.get_entry(id).unwrap();
    let decrypted = key.decrypt(&entry.content, &entry.nonce).unwrap();
    assert_eq!(&decrypted[..], plaintext);
}

#[test]
fn full_flow_multiple_entries_ordering() {
    let db = Database::open_in_memory().unwrap();
    let key = test_key();

    let texts = ["First entry", "Second entry", "Third entry"];
    for (i, text) in texts.iter().enumerate() {
        let (ct, nonce) = key.encrypt(text.as_bytes()).unwrap();
        db.insert_entry(
            &format!("2026-03-11T12:00:0{i}+00:00"),
            &ct,
            &nonce,
            MediaType::Text,
            text,
            text.len() as i64,
            None,
        )
        .unwrap();
    }

    let entries = db.list_entries(100, None).unwrap();
    assert_eq!(entries.len(), 3);
    // newest first
    assert_eq!(entries[0].preview, "Third entry");
    assert_eq!(entries[1].preview, "Second entry");
    assert_eq!(entries[2].preview, "First entry");
}

#[test]
fn full_flow_delete() {
    let db = Database::open_in_memory().unwrap();
    let key = test_key();

    let (ct, nonce) = key.encrypt(b"to be deleted").unwrap();
    let id = db
        .insert_entry(
            "2026-03-11T12:00:00+00:00",
            &ct,
            &nonce,
            MediaType::Text,
            "to be deleted",
            13,
            None,
        )
        .unwrap();

    assert!(db.delete_entry(id).unwrap());
    assert_eq!(db.entry_count().unwrap(), 0);

    // deleting again returns false
    assert!(!db.delete_entry(id).unwrap());
}

#[test]
fn full_flow_clear() {
    let db = Database::open_in_memory().unwrap();
    let key = test_key();

    for i in 0..5 {
        let (ct, nonce) = key.encrypt(format!("entry {i}").as_bytes()).unwrap();
        db.insert_entry(
            &format!("2026-03-11T12:00:0{i}+00:00"),
            &ct,
            &nonce,
            MediaType::Text,
            &format!("entry {i}"),
            7,
            None,
        )
        .unwrap();
    }

    assert_eq!(db.entry_count().unwrap(), 5);
    db.clear().unwrap();
    assert_eq!(db.entry_count().unwrap(), 0);
    assert!(db.list_entries(100, None).unwrap().is_empty());
}

#[test]
fn full_flow_wipe_db_file() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.db");

    {
        let db = Database::open(&db_path).unwrap();
        let key = test_key();
        let (ct, nonce) = key.encrypt(b"secret data").unwrap();
        db.insert_entry(
            "2026-03-11T12:00:00+00:00",
            &ct,
            &nonce,
            MediaType::Text,
            "secret data",
            11,
            None,
        )
        .unwrap();
    }

    assert!(db_path.exists());

    // Simulate wipe: clear, zero-fill, delete
    {
        let db = Database::open(&db_path).unwrap();
        db.clear().unwrap();
    }
    let size = std::fs::metadata(&db_path).unwrap().len() as usize;
    std::fs::write(&db_path, vec![0u8; size]).unwrap();
    std::fs::remove_file(&db_path).unwrap();

    assert!(!db_path.exists());
}

#[test]
fn full_flow_max_entries_enforcement() {
    let db = Database::open_in_memory().unwrap();
    let key = test_key();

    for i in 0..10 {
        let (ct, nonce) = key.encrypt(format!("entry {i}").as_bytes()).unwrap();
        db.insert_entry(
            &format!("2026-03-11T12:00:{i:02}+00:00"),
            &ct,
            &nonce,
            MediaType::Text,
            &format!("entry {i}"),
            7,
            None,
        )
        .unwrap();
    }

    assert_eq!(db.entry_count().unwrap(), 10);
    db.delete_oldest_beyond(5).unwrap();
    assert_eq!(db.entry_count().unwrap(), 5);

    // Only newest 5 remain
    let entries = db.list_entries(100, None).unwrap();
    assert_eq!(entries[0].preview, "entry 9");
    assert_eq!(entries[4].preview, "entry 5");
}

#[test]
fn full_flow_type_filter() {
    let db = Database::open_in_memory().unwrap();
    let key = test_key();

    let items: &[(&str, MediaType)] = &[
        ("text content", MediaType::Text),
        ("[image PNG 1000 bytes]", MediaType::Image),
        ("[file /tmp/test.txt]", MediaType::File),
        ("another text", MediaType::Text),
    ];

    for (i, (preview, media_type)) in items.iter().enumerate() {
        let (ct, nonce) = key.encrypt(preview.as_bytes()).unwrap();
        db.insert_entry(
            &format!("2026-03-11T12:00:{i:02}+00:00"),
            &ct,
            &nonce,
            *media_type,
            preview,
            preview.len() as i64,
            None,
        )
        .unwrap();
    }

    assert_eq!(db.list_entries(100, Some(MediaType::Text)).unwrap().len(), 2);
    assert_eq!(db.list_entries(100, Some(MediaType::Image)).unwrap().len(), 1);
    assert_eq!(db.list_entries(100, Some(MediaType::File)).unwrap().len(), 1);
    assert_eq!(db.list_entries(100, Some(MediaType::Other)).unwrap().len(), 0);
}

#[test]
fn full_flow_limit() {
    let db = Database::open_in_memory().unwrap();
    let key = test_key();

    for i in 0..10 {
        let (ct, nonce) = key.encrypt(format!("e{i}").as_bytes()).unwrap();
        db.insert_entry(
            &format!("2026-03-11T12:00:{i:02}+00:00"),
            &ct,
            &nonce,
            MediaType::Text,
            &format!("e{i}"),
            2,
            None,
        )
        .unwrap();
    }

    assert_eq!(db.list_entries(3, None).unwrap().len(), 3);
    assert_eq!(db.list_entries(100, None).unwrap().len(), 10);
}

#[test]
fn decrypt_nonexistent_entry() {
    let db = Database::open_in_memory().unwrap();
    let result = db.get_entry(999);
    assert!(result.is_err());
}

#[test]
fn encrypt_decrypt_binary_data() {
    let key = test_key();
    let binary: Vec<u8> = (0..=255).collect();

    let (ct, nonce) = key.encrypt(&binary).unwrap();
    let decrypted = key.decrypt(&ct, &nonce).unwrap();
    assert_eq!(&decrypted[..], &binary[..]);
}
