use async_std::io::Read;
use async_std::prelude::*;
use std::collections::HashMap;

use crate::bks::errors;

#[derive(Debug)]
pub struct BksTrustedCertEntry {
    cert_type: String,
    cert_data: Vec<u8>,
}

impl BksTrustedCertEntry {
    async fn load<T>(reader: &mut T) -> Result<Self, errors::BksError>
    where
        T: Read + Unpin,
    {
        let cert_type = read_utf8(reader).await?;
        let cert_data = read_data(reader).await?;
        Ok(Self {
            cert_type,
            cert_data,
        })
    }
}

#[derive(Debug)]
pub struct BksKeyEntry {
    key_type: u8,
    key_format: String,
    key_algorithm: String,
    key_enc: Vec<u8>,
}

impl BksKeyEntry {
    async fn load<T>(reader: &mut T) -> Result<Self, errors::BksError>
    where
        T: Read + Unpin,
    {
        let key_type = read_u8(reader).await?;
        let key_format = read_utf8(reader).await?;
        let key_algorithm = read_utf8(reader).await?;
        let key_enc = read_data(reader).await?;
        Ok(Self {
            key_type,
            key_format,
            key_algorithm,
            key_enc,
        })
    }
}

#[derive(Debug)]
pub struct BksSecretEntry {
    secret_data: Vec<u8>,
}

impl BksSecretEntry {
    async fn load<T>(reader: &mut T) -> Result<Self, errors::BksError>
    where
        T: Read + Unpin,
    {
        let secret_data = read_data(reader).await?;
        Ok(Self { secret_data })
    }
}

#[derive(Debug)]
pub struct BksSealedEntry {
    sealed_data: Vec<u8>,
}

impl BksSealedEntry {
    async fn load<T>(reader: &mut T) -> Result<Self, errors::BksError>
    where
        T: Read + Unpin,
    {
        let sealed_data = read_data(reader).await?;
        Ok(Self { sealed_data })
    }
}

#[derive(Debug)]
pub enum BksEntryValue {
    CertEntry(BksTrustedCertEntry),
    KeyEntry(BksKeyEntry),
    SecretEntry(BksSecretEntry),
    SealedEntry(BksSealedEntry),
}

#[derive(Debug)]
pub struct BksEntry {
    alias: String,
    timestamp: u64,
    cert_chain: Vec<BksTrustedCertEntry>,
    value: BksEntryValue,
}

#[derive(Debug)]
pub struct BksKeyStore {
    version: u32,
    store_type: String,
    entries: HashMap<String, BksEntry>,
}

async fn read_u64<T>(reader: &mut T) -> Result<u64, errors::BksError>
where
    T: Read + Unpin,
{
    let mut buf = [0; 8];
    reader.read_exact(&mut buf).await?;
    Ok(u64::from_be_bytes(buf))
}

async fn read_u32<T>(reader: &mut T) -> Result<u32, errors::BksError>
where
    T: Read + Unpin,
{
    let mut buf = [0; 4];
    reader.read_exact(&mut buf).await?;
    Ok(u32::from_be_bytes(buf))
}

async fn read_u8<T>(reader: &mut T) -> Result<u8, errors::BksError>
where
    T: Read + Unpin,
{
    let mut buf = [0; 1];
    reader.read_exact(&mut buf).await?;
    Ok(u8::from_be_bytes(buf))
}

async fn read_data<T>(reader: &mut T) -> Result<Vec<u8>, errors::BksError>
where
    T: Read + Unpin,
{
    let mut size_buf = [0; 4];
    reader.read_exact(&mut size_buf).await?;
    let size: usize = u32::from_be_bytes(size_buf).try_into().unwrap();
    let mut buffer = Vec::with_capacity(size);
    unsafe { buffer.set_len(size) }
    reader.read_exact(&mut buffer).await?;
    Ok(buffer)
}

async fn read_utf8<T>(reader: &mut T) -> Result<String, errors::BksError>
where
    T: Read + Unpin,
{
    let mut size_buf = [0; 2];
    reader.read_exact(&mut size_buf).await?;
    let size: usize = u16::from_be_bytes(size_buf).try_into().unwrap();
    // Skip 2 bytes
    let mut buffer = Vec::with_capacity(size);
    unsafe { buffer.set_len(size) }
    reader.read_exact(&mut buffer).await?;
    Ok(String::from_utf8(buffer)?)
}

impl BksEntry {
    async fn load<T>(reader: &mut T, _type: u8) -> Result<BksEntry, errors::BksError>
    where
        T: Read + Unpin,
    {
        let alias = read_utf8(reader).await?;
        let timestamp = read_u64(reader).await?;
        let chain_length = read_u32(reader).await?;
        let mut cert_chain: Vec<BksTrustedCertEntry> = Vec::new();
        for _ in 0..chain_length {
            let entry = BksTrustedCertEntry::load(reader).await?;
            cert_chain.push(entry)
        }
        let value = match _type {
            1 => {
                let cert = BksTrustedCertEntry::load(reader).await?;
                BksEntryValue::CertEntry(cert)
            }
            2 => BksEntryValue::KeyEntry(BksKeyEntry::load(reader).await?),
            3 => BksEntryValue::SecretEntry(BksSecretEntry::load(reader).await?),
            4 => BksEntryValue::SealedEntry(BksSealedEntry::load(reader).await?),
            _ => {
                return Err(errors::BksError::FormatError(errors::BksFormatError::new(
                    "bad entry type".to_string(),
                )))
            }
        };
        Ok(BksEntry {
            alias,
            timestamp,
            cert_chain,
            value,
        })
    }
}

async fn read_bks_entries<T>(reader: &mut T) -> Result<HashMap<String, BksEntry>, errors::BksError>
where
    T: Read + Unpin,
{
    let mut entries = HashMap::<String, BksEntry>::new();
    while let Ok(_type) = read_u8(reader).await {
        if _type == 0 {
            break;
        }

        let entry = BksEntry::load(reader, _type).await?;
        entries.insert(entry.alias.to_string(), entry);
    }
    Ok(entries)
}

impl BksKeyStore {
    pub async fn load<T>(reader: &mut T) -> Result<BksKeyStore, errors::BksError>
    where
        T: Read + Unpin,
    {
        let version = read_u32(reader).await?;
        let store_type = "bks".to_string();
        if version != 1 && version != 2 {
            return Err(errors::BksFormatError::new(
                "Only bks bversion 1 and 2 are supported".to_string(),
            )
            .into());
        }
        let _salt = read_data(reader).await?;
        let _iteration_count = read_u32(reader).await?;
        let entries = read_bks_entries(reader).await?;
        Ok(BksKeyStore {
            version,
            store_type,
            entries,
        })
    }
}
