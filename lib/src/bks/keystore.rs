use async_std::io::Read;
use async_std::prelude::*;
use digest::core_api::BlockSizeUser;
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

fn _adjust(a: &mut Vec<u8>, a_offset: usize, b: &Vec<u8>) {
    let mut x: u32 = (*b.last().unwrap() as u32) + (a[a_offset + b.len() - 1] as u32) + 1;
    a[a_offset + b.len() - 1] = (x & 0xff).try_into().unwrap();
    x >>= 8;

    for i in (0..(b.len() - 2)).rev() {
        x += (b[i] as u32) + (a[a_offset + i] as u32);
        a[a_offset + i] = (x & 0xff).try_into().unwrap();
        x >>= 8;
    }
}

fn rfc7292_derieve_key<T: Digest + BlockSizeUser>(
    purpose: u8,
    password: String,
    salt: Vec<u8>,
    iteration_count: u32,
    key_size: u32,
) -> Vec<u8> {
    let mut password_bytes = UTF_16BE
        .encode(&password.to_string(), EncoderTrap::Strict)
        .unwrap();
    password_bytes.extend([0, 0].iter());
    let u = <T as Digest>::output_size() as u32;
    let v = <T as BlockSizeUser>::block_size();
    let d = vec![purpose; v];
    let s_len = ((salt.len() + v - 1) / v) * v; // round to lower multiplication
    let s: Vec<u8> = (0..s_len).map(|n| salt[n % salt.len()]).collect();
    let p_len = ((password_bytes.len() + v - 1) / v) * v;
    let p: Vec<u8> = (0..p_len)
        .map(|n| password_bytes[n % password_bytes.len()])
        .collect();
    let mut I: Vec<u8> = s.iter().copied().chain(p.iter().copied()).collect();
    let c = (key_size + u - 1) / u;
    let mut derived_key: Vec<u8> = Vec::new();
    for _ in 1..(c + 1) {
        let mut a: Vec<u8> = T::digest(
            d.iter()
                .copied()
                .chain(I.iter().copied())
                .collect::<Vec<u8>>(),
        )
        .to_vec();
        for _ in 1..iteration_count {
            a = T::digest(a).to_vec();
        }

        let b: Vec<u8> = (0..v).map(|n| a[n % a.len()]).collect();

        for j in 0..(I.len() / v) {
            _adjust(&mut I, j * v, &b);
        }

        derived_key.extend(a)
    }

    derived_key.resize(key_size as usize, 0);
    derived_key
}

async fn read_bks_entries_hmac<T>(
    reader: &mut T,
    key: &[u8],
) -> Result<(HashMap<String, BksEntry>, Vec<u8>), errors::BksError>
where
    T: Read + Unpin,
{
    let mut hmac_reader = HMACReader {
        inner: reader,
        hmac: Hmac::<Sha1>::new_from_slice(key).unwrap(),
    };
    Ok((
        read_bks_entries(&mut hmac_reader).await?,
        hmac_reader.hmac.finalize().into_bytes().to_vec(),
    ))
}

impl BksKeyStore {
    pub async fn load<T>(reader: &mut T, password: String) -> Result<BksKeyStore, errors::BksError>
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
        let salt = read_data(reader).await?;
        let iteration_count = read_u32(reader).await?;
        let hmac_digest_size = Sha1::output_size();
        let hmac_key_size = if version != 1 {
            hmac_digest_size * 8
        } else {
            hmac_digest_size
        };
        let hmac_key = rfc7292_derieve_key::<Sha1>(
            3,
            password,
            salt,
            iteration_count,
            (hmac_key_size / 8).try_into().unwrap(),
        );
        let (entries, calculated_hmac) = read_bks_entries_hmac(reader, &hmac_key).await?;
        let mut store_hmac = vec![0; Sha1::output_size()];
        reader.read_exact(&mut store_hmac).await?;
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
