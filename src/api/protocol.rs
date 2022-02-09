use async_std::net::TcpStream;
use async_std::prelude::*;
use std::str;

use crate::api::api::*;

#[derive(Clone, Copy, Debug)]
pub enum MessageType {
    Request = 1,
    Response = 2,
    Notification = 3,
}

impl TryFrom<u8> for MessageType {
    type Error = ();

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            x if x == MessageType::Request as u8 => Ok(MessageType::Request),
            x if x == MessageType::Response as u8 => Ok(MessageType::Response),
            x if x == MessageType::Notification as u8 => Ok(MessageType::Notification),
            _ => Err(()),
        }
    }
}

#[derive(Debug)]
pub struct MessageWrapper {
    message_type: MessageType,
    priority: u8,
    message_id: u32,
    message: String,
}

impl MessageWrapper {
    pub fn new(message_type: MessageType, message_id: u32, message: String) -> MessageWrapper {
        MessageWrapper {
            message_type,
            priority: 0,
            message_id,
            message,
        }
    }
    pub fn serialize(&self) -> Vec<u8> {
        let mut result: Vec<u8> = Vec::<u8>::with_capacity(6 + self.message.len());
        result.push(self.message_type as u8);
        result.push(self.priority);
        result.extend_from_slice(&self.message_id.to_le_bytes());
        result.extend(self.message.as_bytes());
        result
    }

    pub fn deserialize(data: &Vec<u8>) -> Result<MessageWrapper> {
        Ok(MessageWrapper {
            message_type: data[0].try_into().unwrap(),
            priority: data[1],
            message_id: u32::from_le_bytes(data[2..6].try_into().unwrap()),
            message: str::from_utf8(&data[6..])?.to_string(),
        })
    }

    pub fn message(&self) -> &String {
        &self.message
    }
}

pub fn create_prefixed_message(message: &Vec<u8>) -> Vec<u8> {
    let mut result = Vec::<u8>::with_capacity(8 + message.len());
    // Magic code
    result.push(127);
    result.push(54);
    result.push(60);
    result.push(162);

    result.extend_from_slice(&(message.len() as u32).to_le_bytes());
    result.extend(message);

    result
}

pub async fn read_prefixed_message(
    stream: &mut async_native_tls::TlsStream<TcpStream>,
) -> Result<Vec<u8>> {
    let mut _magic = [0; 4];
    stream.read_exact(&mut _magic).await?;

    let mut size = [0; 4];
    stream.read_exact(&mut size).await?;
    let size = u32::from_le_bytes(size);

    let mut buffer = Vec::with_capacity(size.try_into().unwrap());
    stream.take(size.into()).read_to_end(&mut buffer).await?;
    Ok(buffer)
}
