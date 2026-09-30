FROM rust:1-slim

RUN cargo install cargo-watch

WORKDIR /app
