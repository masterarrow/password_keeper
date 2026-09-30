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
