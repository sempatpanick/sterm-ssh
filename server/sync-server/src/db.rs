use std::path::Path;

use core_crypto::kdf::KdfParams;
use core_vault::models::EncryptedItemEnvelope;
use rusqlite::{params, Connection, OptionalExtension};

pub struct AccountRow {
    pub id: String,
    pub email: String,
    pub auth_hash: String,
    pub kdf_salt_b64: String,
    pub kdf_params: KdfParams,
    pub wrapped_dek_b64: String,
}

pub struct SyncDb {
    conn: Connection,
}

impl SyncDb {
    pub fn open(path: &Path) -> rusqlite::Result<Self> {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let conn = Connection::open(path)?;
        let db = Self { conn };
        db.migrate()?;
        Ok(db)
    }

    pub fn open_in_memory() -> rusqlite::Result<Self> {
        let conn = Connection::open_in_memory()?;
        let db = Self { conn };
        db.migrate()?;
        Ok(db)
    }

    fn migrate(&self) -> rusqlite::Result<()> {
        self.conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            CREATE TABLE IF NOT EXISTS accounts (
                id TEXT PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                auth_hash TEXT NOT NULL,
                kdf_salt_b64 TEXT NOT NULL,
                kdf_params_json TEXT NOT NULL,
                wrapped_dek_b64 TEXT NOT NULL,
                seq_counter INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sync_items (
                account_id TEXT NOT NULL,
                item_id TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                ciphertext_b64 TEXT NOT NULL,
                nonce_b64 TEXT NOT NULL,
                schema_version INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                deleted_at INTEGER,
                server_seq INTEGER NOT NULL,
                PRIMARY KEY (account_id, item_id)
            );

            CREATE INDEX IF NOT EXISTS idx_sync_items_seq
                ON sync_items(account_id, server_seq);
            ",
        )
    }

    #[expect(clippy::too_many_arguments, reason = "maps 1:1 to accounts table INSERT columns")]
    pub fn create_account(
        &self,
        id: &str,
        email: &str,
        auth_hash: &str,
        kdf_salt_b64: &str,
        kdf_params: &KdfParams,
        wrapped_dek_b64: &str,
        created_at: i64,
    ) -> rusqlite::Result<()> {
        let params_json = serde_json::to_string(kdf_params).unwrap();
        self.conn.execute(
            "INSERT INTO accounts
                (id, email, auth_hash, kdf_salt_b64, kdf_params_json, wrapped_dek_b64, seq_counter, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7)",
            params![id, email, auth_hash, kdf_salt_b64, params_json, wrapped_dek_b64, created_at],
        )?;
        Ok(())
    }

    pub fn find_account_by_email(&self, email: &str) -> rusqlite::Result<Option<AccountRow>> {
        self.conn
            .query_row(
                "SELECT id, email, auth_hash, kdf_salt_b64, kdf_params_json, wrapped_dek_b64
                 FROM accounts WHERE email = ?1",
                params![email],
                |row| {
                    let params_json: String = row.get(4)?;
                    let kdf_params: KdfParams =
                        serde_json::from_str(&params_json).unwrap_or_default();
                    Ok(AccountRow {
                        id: row.get(0)?,
                        email: row.get(1)?,
                        auth_hash: row.get(2)?,
                        kdf_salt_b64: row.get(3)?,
                        kdf_params,
                        wrapped_dek_b64: row.get(5)?,
                    })
                },
            )
            .optional()
    }

    pub fn find_account_by_id(&self, id: &str) -> rusqlite::Result<Option<(AccountRow, i64)>> {
        self.conn
            .query_row(
                "SELECT id, email, auth_hash, kdf_salt_b64, kdf_params_json, wrapped_dek_b64, created_at
                 FROM accounts WHERE id = ?1",
                params![id],
                |row| {
                    let params_json: String = row.get(4)?;
                    let kdf_params: KdfParams =
                        serde_json::from_str(&params_json).unwrap_or_default();
                    let created_at: i64 = row.get(6)?;
                    Ok((
                        AccountRow {
                            id: row.get(0)?,
                            email: row.get(1)?,
                            auth_hash: row.get(2)?,
                            kdf_salt_b64: row.get(3)?,
                            kdf_params,
                            wrapped_dek_b64: row.get(5)?,
                        },
                        created_at,
                    ))
                },
            )
            .optional()
    }

    pub fn count_active_items(&self, account_id: &str) -> rusqlite::Result<i64> {
        self.conn.query_row(
            "SELECT COUNT(*) FROM sync_items WHERE account_id = ?1 AND deleted_at IS NULL",
            params![account_id],
            |r| r.get(0),
        )
    }

    pub fn update_account_credentials(
        &self,
        account_id: &str,
        new_auth_hash: &str,
        new_kdf_salt_b64: &str,
        new_kdf_params: &KdfParams,
        new_wrapped_dek_b64: &str,
    ) -> rusqlite::Result<()> {
        let params_json = serde_json::to_string(new_kdf_params).unwrap();
        self.conn.execute(
            "UPDATE accounts
             SET auth_hash = ?2, kdf_salt_b64 = ?3, kdf_params_json = ?4, wrapped_dek_b64 = ?5
             WHERE id = ?1",
            params![
                account_id,
                new_auth_hash,
                new_kdf_salt_b64,
                params_json,
                new_wrapped_dek_b64
            ],
        )?;
        Ok(())
    }

    pub fn delete_account(&mut self, account_id: &str) -> rusqlite::Result<()> {
        let tx = self.conn.transaction()?;
        tx.execute(
            "DELETE FROM sync_items WHERE account_id = ?1",
            params![account_id],
        )?;
        tx.execute("DELETE FROM accounts WHERE id = ?1", params![account_id])?;
        tx.commit()
    }

    pub fn push_items(
        &mut self,
        account_id: &str,
        items: &[EncryptedItemEnvelope],
    ) -> rusqlite::Result<(Vec<(String, i64)>, i64)> {
        let tx = self.conn.transaction()?;
        let mut seq: i64 = tx.query_row(
            "SELECT seq_counter FROM accounts WHERE id = ?1",
            params![account_id],
            |r| r.get(0),
        )?;

        let mut acks = Vec::with_capacity(items.len());
        for item in items {
            seq += 1;
            tx.execute(
                "INSERT INTO sync_items
                    (account_id, item_id, entity_type, ciphertext_b64, nonce_b64, schema_version, updated_at, deleted_at, server_seq)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                 ON CONFLICT(account_id, item_id) DO UPDATE SET
                    entity_type = excluded.entity_type,
                    ciphertext_b64 = excluded.ciphertext_b64,
                    nonce_b64 = excluded.nonce_b64,
                    schema_version = excluded.schema_version,
                    updated_at = excluded.updated_at,
                    deleted_at = excluded.deleted_at,
                    server_seq = excluded.server_seq",
                params![
                    account_id,
                    &item.id,
                    &item.entity_type,
                    &item.ciphertext_b64,
                    &item.nonce_b64,
                    item.schema_version,
                    item.updated_at,
                    item.deleted_at,
                    seq,
                ],
            )?;
            acks.push((item.id.clone(), seq));
        }

        tx.execute(
            "UPDATE accounts SET seq_counter = ?2 WHERE id = ?1",
            params![account_id, seq],
        )?;
        tx.commit()?;
        Ok((acks, seq))
    }

    pub fn pull_changes(
        &self,
        account_id: &str,
        since: i64,
    ) -> rusqlite::Result<(Vec<EncryptedItemEnvelope>, i64)> {
        let latest_seq: i64 = self.conn.query_row(
            "SELECT seq_counter FROM accounts WHERE id = ?1",
            params![account_id],
            |r| r.get(0),
        )?;

        let mut stmt = self.conn.prepare(
            "SELECT item_id, entity_type, ciphertext_b64, nonce_b64, schema_version, updated_at, deleted_at, server_seq
             FROM sync_items
             WHERE account_id = ?1 AND server_seq > ?2
             ORDER BY server_seq ASC",
        )?;

        let rows = stmt.query_map(params![account_id, since], |row| {
            Ok(EncryptedItemEnvelope {
                id: row.get(0)?,
                entity_type: row.get(1)?,
                ciphertext_b64: row.get(2)?,
                nonce_b64: row.get(3)?,
                schema_version: row.get(4)?,
                updated_at: row.get(5)?,
                deleted_at: row.get(6)?,
                sync_revision: row.get(7)?,
            })
        })?;

        let mut items = Vec::new();
        for r in rows {
            items.push(r?);
        }
        Ok((items, latest_seq))
    }

    #[cfg(test)]
    pub fn debug_dump_ciphertexts(&self) -> rusqlite::Result<String> {
        let mut stmt = self
            .conn
            .prepare("SELECT entity_type, ciphertext_b64, nonce_b64 FROM sync_items")?;
        let mut buf = String::new();
        let rows = stmt.query_map([], |r| {
            Ok(format!(
                "{}:{}:{}\n",
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?
            ))
        })?;
        for row in rows {
            buf.push_str(&row?);
        }
        Ok(buf)
    }
}
