use sqlx::{FromRow, Pool, Sqlite, SqlitePool, sqlite::{SqliteConnectOptions, SqliteJournalMode, SqliteSynchronous}};

pub type DBResult<T> = Result<T, sqlx::Error>;

#[derive(FromRow, Clone)]
pub struct Record {
    pub id: i64,
    pub title: String,
    pub description: String,
    pub username: String,
    pub password: String,
}

impl Record {
    pub fn new() -> Self {
        Self {
            id: 0,
            title: String::new(),
            description: String::new(),
            username: String::new(),
            password: String::new(),
        }
    }
}

#[derive(Clone)]
pub struct DB {
    pub db: Pool<Sqlite>
}

impl DB {
    /**
     * Init database
     *
     * Args:
     *
     *     db (Pool<Sqlite>): Database
     *
     * Returns:
     *
     *     DB
     */
    pub async fn new() -> Self {
        let options = SqliteConnectOptions::new()
            .filename("app.db")
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal);

        let pool = SqlitePool::connect_with(options).await.expect("Could not connect to the database");

        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("Could not run database migrations");

        Self { db: pool }
    }

    /**
     * Get all records
     *
     * Args:
     *
     *     limit (int): Limit
     *     offset (int): Offset
     *     search (Option<String>): Search query
     *
     * Returns:
     *
     *     DBResult<Vec<Record>> Records
     */
    pub async fn all(&self, limit: i64, offset: i64, search: &Option<String>) -> DBResult<Vec<Record>> {
        let todos = sqlx::query_as!(
            Record,
            "SELECT id, title, description, username, password FROM storage WHERE title LIKE ? OR description LIKE ? OR username LIKE ? LIMIT ? OFFSET ?",
            format!("%{}%", search.as_deref().unwrap_or("")),
            format!("%{}%", search.as_deref().unwrap_or("")),
            format!("%{}%", search.as_deref().unwrap_or("")),
            limit,
            offset
        )
            .fetch_all(&self.db)
            .await?;

        Ok(todos)
    }

    /**
     * Get record count
     *
     * Returns:
     *
     *     DBResult<i64> Record count
     */
    pub async fn count_records(&self) -> DBResult<i64> {
        let result = sqlx::query!(
            "SELECT COUNT(*) as count FROM storage;"
        )
            .fetch_one(&self.db)
            .await?;

        Ok(result.count)
    }

    /**
     * Get record by id
     *
     * Args:
     *
     *     id (int): Record id
     *
     * Returns:
     *
     *     DBResult<Option<Record>> Record
     */
    pub async fn get_by_id(&self, id: i64) -> DBResult<Option<Record>> {
        sqlx::query_as!(Record, "SELECT * FROM storage WHERE id = ?", id)
            .fetch_optional(&self.db)
            .await
    }

    /**
     * Create a new record
     *
     * Args:
     *
     *     record (Record): Record
     *
     * Returns:
     *
     *     DBResult<i64> Record id
     */
    pub async fn create(&self, record: &Record) -> DBResult<i64> {
        let result = sqlx::query!(
            "INSERT INTO storage (title, description, username, password) VALUES (?, ?, ?, ?);",
            record.title,
            record.description,
            record.username,
            record.password,
        )
            .execute(&self.db)
            .await?;

        let is_inserted = result.rows_affected() > 0;

        if !is_inserted {
            return Err(sqlx::Error::RowNotFound);
        }

        Ok(result.last_insert_rowid() as i64)
    }

    /**
     * Update a record
     *
     * Args:
     *
     *     record (Record): Record
     *
     * Returns:
     *
     *     DBResult<bool> Is updated
     */
    pub async fn update(&self, record: &Record) -> DBResult<bool> {
        let result = sqlx::query!(
            "UPDATE storage SET title = ?, description = ?, username = ?, password = ? WHERE id = ?;",
            record.title,
            record.description,
            record.username,
            record.password,
            record.id
        )
            .execute(&self.db)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    /**
     * Delete a record
     *
     * Args:
     *
     *     id (int): Record id
     *
     * Returns:
     *
     *     DBResult<bool> Is deleted
     */
    pub async fn remove(&self, id: i64) -> DBResult<bool> {
        let result = sqlx::query!(
            "DELETE FROM storage WHERE id = ?;",
            id
        )
            .execute(&self.db)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    /**
     * Get master password
     *
     * Returns:
     *
     *     DBResult<Option<String>> Master password
     */
    pub async fn get_master_password(&self) -> DBResult<Option<String>> {
        let record = sqlx::query!(
            "SELECT key FROM auth WHERE id = 1;"
        )
            .fetch_optional(&self.db)
            .await?;

        Ok(record.map(|r| r.key))
    }

    /**
     * Update master password
     *
     * Args:
     *
     *     password (str): New master password
     *
     * Returns:
     *
     *     DBResult<bool> Is updated
     */
    pub async fn update_master_password(&self, password: &str) -> DBResult<bool> {
        let result = sqlx::query!(
            "INSERT INTO auth (id, key) VALUES (1, ?) ON CONFLICT(id) DO UPDATE SET key = excluded.key;",
            password
        )
            .execute(&self.db)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    /**
     * Check if this is the first run
     *
     * Returns:
     *
     *     DBResult<bool> Is first run
     */
    pub async fn is_first_run(&self) -> DBResult<bool> {
        let record = sqlx::query!(
            "SELECT COUNT(*) as count FROM auth;"
        )
            .fetch_one(&self.db)
            .await?;

        Ok(record.count == 0)
    }
}
