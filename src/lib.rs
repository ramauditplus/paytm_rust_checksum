// src/lib.rs

use aes::Aes128;
use base64::{engine::general_purpose, Engine as _};
use cbc::{
    cipher::{
        block_padding::Pkcs7,
        BlockDecryptMut,
        BlockEncryptMut,
        KeyIvInit,
    },
    Decryptor,
    Encryptor,
};
use rand::{rng, Rng};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;

type Aes128CbcEnc = Encryptor<Aes128>;
type Aes128CbcDec = Decryptor<Aes128>;

const IV: &str = "@@@@&&&&####$$$$";

#[derive(Debug)]
pub enum PaytmChecksumError {
    Crypto(String),
    Utf8(std::string::FromUtf8Error),
    Base64(base64::DecodeError),
    InvalidKeyLength,
}

impl fmt::Display for PaytmChecksumError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Crypto(err) => write!(f, "Crypto error: {}", err),
            Self::Utf8(err) => write!(f, "UTF8 error: {}", err),
            Self::Base64(err) => write!(f, "Base64 error: {}", err),
            Self::InvalidKeyLength => {
                write!(f, "Merchant key must be exactly 16 bytes")
            }
        }
    }
}

impl std::error::Error for PaytmChecksumError {}

impl From<std::string::FromUtf8Error> for PaytmChecksumError {
    fn from(value: std::string::FromUtf8Error) -> Self {
        Self::Utf8(value)
    }
}

impl From<base64::DecodeError> for PaytmChecksumError {
    fn from(value: base64::DecodeError) -> Self {
        Self::Base64(value)
    }
}

pub struct PaytmChecksum;

impl PaytmChecksum {
    pub fn encrypt(
        input: &str,
        key: &str,
    ) -> Result<String, PaytmChecksumError> {
        Self::validate_key(key)?;

        let cipher = Aes128CbcEnc::new_from_slices(
            key.as_bytes(),
            IV.as_bytes(),
        )
        .map_err(|e| PaytmChecksumError::Crypto(e.to_string()))?;

        let mut buffer = input.as_bytes().to_vec();

        let msg_len = buffer.len();

        buffer.resize(msg_len + 16, 0);

        let encrypted = cipher
            .encrypt_padded_mut::<Pkcs7>(&mut buffer, msg_len)
            .map_err(|e| PaytmChecksumError::Crypto(format!("{:?}", e)))?;

        Ok(general_purpose::STANDARD.encode(encrypted))
    }

    pub fn decrypt(
        encrypted: &str,
        key: &str,
    ) -> Result<String, PaytmChecksumError> {
        Self::validate_key(key)?;

        let cipher = Aes128CbcDec::new_from_slices(
            key.as_bytes(),
            IV.as_bytes(),
        )
        .map_err(|e| PaytmChecksumError::Crypto(e.to_string()))?;

        let mut decoded =
            general_purpose::STANDARD.decode(encrypted)?;

        let decrypted = cipher
            .decrypt_padded_mut::<Pkcs7>(&mut decoded)
            .map_err(|e| PaytmChecksumError::Crypto(format!("{:?}", e)))?;

        Ok(String::from_utf8(decrypted.to_vec())?)
    }

    pub fn generate_signature(
        params: &BTreeMap<String, String>,
        key: &str,
    ) -> Result<String, PaytmChecksumError> {
        let params_string = Self::get_string_by_params(params);

        let salt = Self::generate_random_string(4);

        Self::calculate_checksum(&params_string, key, &salt)
    }

    pub fn generate_signature_by_string(
        params: &str,
        key: &str,
    ) -> Result<String, PaytmChecksumError> {
        let salt = Self::generate_random_string(4);

        Self::calculate_checksum(params, key, &salt)
    }

    pub fn verify_signature(
        params: &BTreeMap<String, String>,
        key: &str,
        checksum: &str,
    ) -> Result<bool, PaytmChecksumError> {
        let mut filtered = params.clone();

        filtered.remove("CHECKSUMHASH");

        let params_string = Self::get_string_by_params(&filtered);

        Self::verify_signature_by_string(
            &params_string,
            key,
            checksum,
        )
    }

    pub fn verify_signature_by_string(
        params: &str,
        key: &str,
        checksum: &str,
    ) -> Result<bool, PaytmChecksumError> {
        let paytm_hash = Self::decrypt(checksum, key)?;

        let salt = &paytm_hash[paytm_hash.len() - 4..];

        Ok(
            paytm_hash
                == Self::calculate_hash(params, salt),
        )
    }

    fn calculate_checksum(
        params: &str,
        key: &str,
        salt: &str,
    ) -> Result<String, PaytmChecksumError> {
        let hash = Self::calculate_hash(params, salt);

        Self::encrypt(&hash, key)
    }

    fn calculate_hash(params: &str, salt: &str) -> String {
        let final_string = format!("{}|{}", params, salt);

        let mut hasher = Sha256::new();

        hasher.update(final_string.as_bytes());

        let hash = format!("{:x}", hasher.finalize());

        format!("{}{}", hash, salt)
    }

    fn get_string_by_params(
        params: &BTreeMap<String, String>,
    ) -> String {
        params
            .values()
            .map(|value| {
                if value.eq_ignore_ascii_case("null") {
                    ""
                } else {
                    value.as_str()
                }
            })
            .collect::<Vec<&str>>()
            .join("|")
    }

    fn generate_random_string(length: usize) -> String {
        let data =
            b"9876543210ZYXWVUTSRQPONMLKJIHGFEDCBAabcdefghijklmnopqrstuvwxyz!@#$&_";

        let mut rng = rng();

        (0..length)
            .map(|_| {
                let index = rng.random_range(0..data.len());

                data[index] as char
            })
            .collect()
    }

    fn validate_key(key: &str) -> Result<(), PaytmChecksumError> {
        if key.as_bytes().len() != 16 {
            return Err(PaytmChecksumError::InvalidKeyLength);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checksum_generation_and_verification() {
        let mut params = BTreeMap::new();

        params.insert("MID".to_string(), "MID123".to_string());
        params.insert(
            "ORDER_ID".to_string(),
            "ORDER0001".to_string(),
        );
        params.insert(
            "TXN_AMOUNT".to_string(),
            "100.00".to_string(),
        );

        let key = "1234567890123456";

        let checksum =
            PaytmChecksum::generate_signature(&params, key)
                .unwrap();
        println!("Generated Checksum: {}", checksum);

        let verified = PaytmChecksum::verify_signature(
            &params,
            key,
            &checksum,
        )
        .unwrap();

        assert!(verified);
    }
}