use argon2::{Algorithm, Argon2, Params, Version};
use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use secrecy::{ExposeSecret, SecretBox, SecretString};

pub type EResult<T> = Result<T, Box<dyn std::error::Error>>;

/**
 * Encrypt row password
 *
 * Args:
 *
 *     password (SecretBox<str>): Row password to encrypt
 *     master_password (SecretBox<str>): Master password
 *
 * Returns:
 *
 *     EResult<String>: Encrypted row password
 */
pub async fn encrypt_row_password(password: &SecretBox<str>, master_password: &SecretBox<str>) -> EResult<String> {
    // Generate a random salt
    let mut salt = [0u8; 16];
    rand::fill(&mut salt);

    // Derive a 32-byte key using Argon2id
    let mut derived_key = vec![0u8; 32];
    let params = Params::new(19456, 2, 1, Some(32))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon2.hash_password_into(master_password.expose_secret().as_bytes(), &salt, &mut derived_key)?;

    // Initialize AES-256-GCM
    let cipher = Aes256Gcm::new_from_slice(&derived_key)?;

    // Generate a unique 96-bit nonce
    let mut nonce_bytes = [0u8; 12];
    rand::fill(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);

    // Encrypt the password
    let cipher_vec = cipher
        .encrypt(&nonce, password.expose_secret().as_bytes())
        .map_err(|e| format!("Encryption failed: {}", e))?;

    // Concatenate the cipher text and nonce
    let encoded_salt = BASE64.encode(salt);
    let encoded_nonce = BASE64.encode(nonce_bytes);
    let encoded_ciphertext = BASE64.encode(cipher_vec);

    Ok([encoded_salt, encoded_nonce, encoded_ciphertext].join("."))
}

/**
 * Decrypt row password
 *
 * Args:
 *
 *     password (str): Encrypted row password
 *     master_password (SecretBox<str>): Master password
 *
 * Returns:
 *
 *     EResult<SecretBox<str>>: Decrypted row password
 */
pub async fn decrypt_row_password(password: &str, master_password: &SecretBox<str>) -> EResult<SecretBox<str>> {
    // Split the input into cipher text and nonce
    let parts: Vec<&str> = password.split('.').collect();
    if parts.len() != 3 {
        return Err("Invalid input".into());
    }

    let salt = BASE64.decode(parts[0])?;
    let nonce_bytes = BASE64.decode(parts[1])?;
    let ciphertext = BASE64.decode(parts[2])?;

    if nonce_bytes.len() != 12 {
        return Err("Invalid nonce length".into());
    }
    let nonce = Nonce::try_from(nonce_bytes.as_slice())
        .map_err(|_| "Invalid nonce length")?;

    // Derive the key using Argon2id
    let mut derived_key = [0u8; 32];
    let params = Params::new(19456, 2, 1, Some(32))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon2.hash_password_into(master_password.expose_secret().as_bytes(), &salt, &mut derived_key)?;

    // Initialize AES-256-GCM
    let cipher = Aes256Gcm::new_from_slice(&derived_key)?;

    // Decrypt the password
    let decrypted_bytes = cipher.decrypt(&nonce, ciphertext.as_ref())
        .map_err(|e| format!("Decryption failed: {}", e))?;

    let decrypted_password = SecretString::from(String::from_utf8(decrypted_bytes)?);

    Ok(decrypted_password)
}

/**
 * Hash master password to store it in the database
 *
 * Args:
 *
 *     password (SecretBox<str>): Master password
 *
 * Returns:
 *
 *     EResult<String>: Hashed master password
 */
pub fn hash_master_password(password: &SecretBox<str>) -> EResult<String> {
    let mut salt = [0u8; 16];
    rand::fill(&mut salt);

    let mut hash = [0u8; 32];
    let params = Params::new(19456, 2, 1, Some(32))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon2.hash_password_into(password.expose_secret().as_bytes(), &salt, &mut hash)?;

    let encoded_salt = BASE64.encode(salt);
    let encoded_hash = BASE64.encode(hash);

    Ok(format!("{}.{}", encoded_salt, encoded_hash))
}

/**
 * Verify master password
 *
 * Args:
 *
 *     password (SecretBox<str>): Master password
 *     stored_data (str): Hashed master password
 *
 * Returns:
 *
 *     EResult<bool>: Is verified
 */
pub fn verify_master_password(password: &SecretBox<str>, stored_data: &str) -> EResult<bool> {
    let parts: Vec<&str> = stored_data.split('.').collect();
    if parts.len() != 2 {
        return Err("Invalid master password format".into());
    }

    let salt = BASE64.decode(parts[0])?;
    let expected_hash = BASE64.decode(parts[1])?;

    let mut actual_hash = [0u8; 32];
    let params = Params::new(19456, 2, 1, Some(32))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon2.hash_password_into(password.expose_secret().as_bytes(), &salt, &mut actual_hash)?;

    // Сравнение хешей за константное время для защиты от тайминг-атак (Timing Attacks)
    if actual_hash.len() != expected_hash.len() {
        return Ok(false);
    }

    let diff = actual_hash.iter()
        .zip(expected_hash.iter())
        .fold(0, |acc, (a, b)| acc | (a ^ b));

    Ok(diff == 0)
}
