-- Add migration script here
CREATE TABLE IF NOT EXISTS auth (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL
);
