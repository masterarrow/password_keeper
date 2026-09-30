use crate::DB;
use secrecy::SecretBox;

#[derive(Clone)]
pub struct Config {
    pub db: DB,
    pub master_password: SecretBox<str>,
}

impl Config {
    pub fn new(db: DB, master_password: SecretBox<str>) -> Self {
        Self { db, master_password }
    }
}
