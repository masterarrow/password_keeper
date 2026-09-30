# Password Keeper

A secure, minimalist CLI password manager written in Rust, featuring **per-record cryptographic isolation**. Designed for developers who prefer clean terminal interfaces, zero telemetry, and complete control over their offline data.

## Features

* **Per-Record Cryptographic Isolation:** Unlike traditional managers that encrypt the whole vault with one key, `password_keeper` derives a unique encryption key (using Argon2id) and unique salt for *every single record*. This exponentially increases the cost of offline brute-force attacks.
* **Shoulder-Surfing Protection:** Passwords are masked by default and only decrypted in memory when explicitly requested.
* **Auto-Clearing Clipboard:** Passwords copied to the clipboard are safely erased after 60 seconds via detached background tasks.
* **Memory Safety:** Sensitive data in RAM is protected using the `secrecy` and `zeroize` crates to prevent leaks in memory dumps.
* **Minimalist TUI:** Built with `comfy-table` and `console` for a fast, no-nonsense "tea-kettle" UX.

## Installation & Build

Ensure you have Rust installed. The database is initialized automatically on the first run.

### Build from source
To build the optimized release version:
```bash
make release
```

The compiled binary will be available at ./target/release/password_keeper.

## Run

```bash
password_keeper
```

## Docker

If you want to use docker, build and run docker container:

```bash
./run -b
```

## Development & Makefile

`make build` - Build the debug version.
`make release` - Build the optimized release version.
`make run` - Run the application directly (cargo run).
`make clean` - Clean cargo build artifacts (safe for your database).
`make db-reset `- DANGER: Deletes the local SQLite database and re-runs migrations (for testing only).

## License

MIT

### Makefile

```makefile
.PHONY: build release run test clean db-reset

build:
	cargo build

release:
	cargo build --release

run:
	cargo run

test:
	cargo test

clean:
	cargo clean

db-reset:
	rm -f ./app.db ./app.db-wal ./app.db-shm
	sqlx database setup
```
