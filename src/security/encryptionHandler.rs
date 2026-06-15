use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use colored::*;
use rand::RngCore;
use std::io::{Error, ErrorKind, Write};
use std::process::Command;

// GenerateConfigEncryptionKey function
pub fn GenerateConfigEncryptionKey() -> Result<(), Error> {
    let mut key = [0u8; 32];

    rand::thread_rng().fill_bytes(&mut key[..]);

    let mut file =
        std::fs::File::create(&*crate::GLOBAL_ENCRYPTION_KEY_FILE_LOCATION).map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!(
                    "{0} {1:?}",
                    "Generate Config Encryption Key Error (file creation) | GenerateConfigEncryptionKey | e:std::io::Error:  ".red(),
                    e
                ),
            )
        })?;

    file.write_all(&key).map_err(|e| {
        Error::new(
            ErrorKind::Other,
            format!(
                "{0} {1:?}",
                "Generate Config Encryption Key Error (file writting) | GenerateConfigEncryptionKey | e:std::io::Error:  ".red(),
                e
            ),
        )
    })?;

    Ok(())
}

// ConfigEncryptionKeyHash function
pub fn ConfigEncryptionKeyHash() -> Result<String, ()> {
    // Running command and returning output
    let COMMAND_OUTPUT = Command::new("sha256sum")
        .arg(&*crate::GLOBAL_ENCRYPTION_KEY_FILE_LOCATION)
        .output()
        .map_err(|e| {
            println!(
                "{0} {1:?}",
                "Config Encryption Key Hash Error | ConfigEncryptionKeyHash | e:std::io::Error:  ".red(),
                e
            );
            return ();
        })
        .unwrap()
        .stdout;
    let COMMAND_OUTPUT = String::from_utf8(COMMAND_OUTPUT).unwrap();
    let HASH_OUTPUT: String = match COMMAND_OUTPUT.split_whitespace().next() {
        Some(HASH) => String::from(HASH),
        _ => "None".to_string(),
    };

    // Error
    if HASH_OUTPUT == "None" {
        return Err(());
    }

    // Return
    Ok(HASH_OUTPUT)
}

// Encrypt data function
pub fn EncryptData(DATA: &[u8], KEY: &[u8]) -> Result<Vec<u8>, Error> {
    // Verifying key length
    if KEY.len() != 32 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Key length must be 32 bytes",
        ));
    }

    let CIPHER = Aes256Gcm::new_from_slice(KEY).map_err(|e| {
        Error::new(
            ErrorKind::Other,
            format!(
                "{0} {1:?}",
                "Encrypt Data Error (creating cipher) | EncryptData | e:aes_gcm::aead::Error:  ".red(),
                e
            ),
        )
    })?;

    // 96 bytes nonce
    let mut nonceBytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonceBytes[..]);
    let NONCE = Nonce::from_slice(&nonceBytes[..]);

    let CIPHER_TEXT = CIPHER
        .encrypt(NONCE, DATA)
        .map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!(
                    "{0} {1:?}",
                    "Encrypt Data Error (encrypting) | EncryptData | e:aes_gcm::aead::Error:  ".red(),
                    e
                ),
            )
        })?;

    let mut output = Vec::new();
    output.extend_from_slice(&nonceBytes);
    output.extend_from_slice(&CIPHER_TEXT);

    // Ok
    Ok(output)
}

// Decrypt data function
pub fn DecryptData(DATA: &[u8], KEY: &[u8]) -> Result<Vec<u8>, Error> {
    // Verifying data byte length
    if DATA.len() < 12 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Data length must be greater than 12 bytes",
        ));
    }

    let CIPHER = Aes256Gcm::new_from_slice(KEY).map_err(|e| {
        Error::new(
            ErrorKind::Other,
            format!(
                "{0} {1:?}",
                "Decrypt Data Error (creating cipher) | DecryptData | e:aes_gcm::aead::Error:  ".red(),
                e
            ),
        )
    })?;

    let (NONCE_BYTE, CIPHER_TEXT) = DATA.split_at(12);
    let NONCE = Nonce::from_slice(NONCE_BYTE);

    CIPHER.decrypt(NONCE, CIPHER_TEXT).map_err(|e| {
        Error::new(
            ErrorKind::Other,
            format!(
                "{0} {1:?}",
                "Error decrypting data | DecryptData | e:aes_gcm::aead::Error:  ".red(),
                e
            ),
        )
    })
}
