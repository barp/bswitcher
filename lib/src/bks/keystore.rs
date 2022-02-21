use async_std::io::Read;
use async_std::prelude::*;
use encoding::all::UTF_16BE;
use encoding::{EncoderTrap, Encoding};
use hmac::{Hmac, Mac};
use sha1::{Digest, Sha1};
use std::collections::HashMap;
use std::pin::Pin;
use std::task::Poll;

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

struct HMACReader<'a, T: Read> {
    inner: &'a mut T,
    hmac: Hmac<Sha1>,
}

impl<'a, T: Read + Unpin> Read for HMACReader<'a, T> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let inner = Pin::into_inner(self);
        match T::poll_read(Pin::new(&mut inner.inner), cx, buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => match result {
                Err(e) => Poll::Ready(Err(e)),
                Ok(size) => {
                    inner.hmac.update(&buf[0..size]);
                    Poll::Ready(Ok(size))
                }
            },
        }
    }
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

fn rfc7292_derieve_key<T: Mac>(
    purpose: u8,
    password: String,
    salt: Vec<u8>,
    iteration_count: u32,
    key_size: u32,
) {
    let mut password_bytes = UTF_16BE
        .encode(&password.to_string(), EncoderTrap::Strict)
        .unwrap();
    password_bytes.extend([0, 0].iter());
    let u = T::output_size();
    let v = 512 / 8; // Sha1 block size, need to this for every sha algorithm
}

async fn read_bks_entries_hmac<T>(
    reader: &mut T,
) -> Result<(HashMap<String, BksEntry>, Vec<u8>), errors::BksError>
where
    T: Read + Unpin,
{
    let mut hmac_reader = HMACReader {
        inner: reader,
        hmac: Hmac::new_from_slice(b"test").unwrap(),
    };
    Ok((
        read_bks_entries(&mut hmac_reader).await?,
        hmac_reader.hmac.finalize().into_bytes().to_vec(),
    ))
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
        let (entries, calculated_hmac) = read_bks_entries_hmac(reader).await?;
        let mut store_hmac = vec![0; Sha1::output_size()];
        reader.read_exact(&mut store_hmac).await?;
        println!(
            "calculated: {:?}, stored: {:?}",
            calculated_hmac, store_hmac
        );
        if store_hmac != calculated_hmac {
            return Err(errors::BksError::SignatureError(
                errors::KeystoreSignatureError::new(store_hmac, calculated_hmac),
            ));
        }
        Ok(BksKeyStore {
            version,
            store_type,
            entries,
        })
    }
}
