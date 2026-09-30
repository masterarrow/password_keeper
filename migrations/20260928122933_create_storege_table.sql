-- Add migration script here
CREATE TABLE IF NOT EXISTS storage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    username TEXT NOT NULL,
    password TEXT NOT NULL
);
