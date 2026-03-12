# CLAUDE.md

## Concept

pbring is a **headless, encrypted clipboard history daemon for macOS**.
Like `cliphist` (Linux Wayland), but for macOS. No UI — pure CLI, composable with any picker via pipes.

- Two binaries: `pbringd` (daemon) and `pbring` (CLI)
- AES-256-GCM encryption per entry, key stored in macOS Keychain
- Automatic filtering of passwords via NSPasteboard markers
- objc2 for direct NSPasteboard access (not arboard)

## Build & Test

```bash
cargo build              # dev build
cargo test               # all tests (unit + integration + CLI)
cargo clippy             # lint
cargo fmt                # format
```

## Branch Workflow

Always create a feature branch before making changes. Never commit directly to `main`.
When starting work on an issue, always pull the latest `main` first, then create the branch from it.

```bash
git checkout main && git pull
git checkout -b feat/<feature-name>
```

## Conventions

### Commit Messages

Use gitmoji prefix: `✨` new feature, `🐛` bug fix, `🩹` minor fix, `♻️` refactor, `🔧` config, `📝` docs, etc.

### Issue / Pull Request

When creating an issue or PR, first present the title and body in Japanese for user review. After approval, translate to English and create via `gh` command.

Always assign appropriate labels when creating issues.

### Copilot Review

After creating a PR or pushing changes (except when pushing fixes for Copilot review comments), request a Copilot review.

After the review completes, use `/review-copilot-comments` to check and address the review comments.

## Key Architecture

```
src/
├── bin/
│   ├── pbring.rs          # CLI (clap): list, get, copy, delete, clear, wipe
│   └── pbringd.rs         # Daemon: poll → filter → encrypt → store
├── lib.rs                 # Module re-exports
├── config.rs              # TOML config (~/.config/pbring/config.toml)
├── db.rs                  # SQLite CRUD + migrations
├── crypto.rs              # AES-256-GCM + Keychain (via `security` CLI)
├── pasteboard.rs          # objc2 NSPasteboard wrapper + marker filtering
├── types.rs               # Entry, MediaType, DecryptedEntry
└── error.rs               # PbringError enum
```

## Security Notes

- Passwords are never recorded (ConcealedType, 1Password markers filtered)
- Decrypted data uses `Zeroizing<Vec<u8>>` — wiped on drop
- Encryption key uses `Zeroizing<[u8; 32]>`
- PID file uses flock for exclusive locking

## External Dependencies

- macOS 14+ required (objc2 NSPasteboard API)
- macOS Keychain for encryption key storage
- All external crates must be added via `cargo add`
