use async_std::net::TcpStream;
use async_std::prelude::*;
use std::str;

use crate::api::*;

#[derive(Clone, Copy, Debug)]
enum MessageType {
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
struct MessageWrapper {
    message_type: MessageType,
    priority: u8,
    message_id: u32,
    message: String,
}

impl MessageWrapper {
    fn new(message_type: MessageType, message_id: u32, message: &str) -> MessageWrapper {
        MessageWrapper {
            message_type,
            priority: 0,
            message_id,
            message: message.to_owned(),
        }
    }
    fn serialize(&self) -> Vec<u8> {
        let mut result: Vec<u8> = Vec::<u8>::with_capacity(6 + self.message.len());
        result.push(self.message_type as u8);
        result.push(self.priority);
        result.extend_from_slice(&self.message_id.to_le_bytes());
        result.extend(self.message.as_bytes());
        result
    }

    fn deserialize(data: &[u8]) -> Result<MessageWrapper> {
        Ok(MessageWrapper {
            message_type: data[0].try_into().unwrap(),
            priority: data[1],
            message_id: u32::from_le_bytes(data[2..6].try_into().unwrap()),
            message: str::from_utf8(&data[6..])?.to_string(),
        })
    }
}

pub struct CuClient {
    stream: async_native_tls::TlsStream<TcpStream>,
    message_id: u32,
}

impl CuClient {
    pub async fn new(ip: &str, port: u32, identity: async_native_tls::Identity) -> Result<Self> {
        let stream = TcpStream::connect(ip.to_string() + ":" + &port.to_string()).await?;
        let stream = async_native_tls::TlsConnector::new()
            .danger_accept_invalid_certs(true)
            .use_sni(true)
            .identity(identity)
            .connect(ip, stream)
            .await
            .unwrap();
        Ok(CuClient {
            stream,
            message_id: 1,
        })
    }

    fn create_prefixed_message(message: &[u8]) -> Vec<u8> {
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

    async fn read_prefixed_message(&mut self) -> Result<Vec<u8>> {
        let mut _magic = [0; 4];
        self.stream.read_exact(&mut _magic).await?;

        let mut size = [0; 4];
        self.stream.read_exact(&mut size).await?;
        let size = u32::from_le_bytes(size);

        let size: usize = size.try_into().unwrap();
        let mut buffer = Vec::with_capacity(size);
        unsafe { buffer.set_len(size) }
        self.stream.read_exact(&mut buffer).await?;
        Ok(buffer)
    }

    pub async fn request(&mut self, request: &str) -> Result<String> {
        let id = self.message_id;
        let message = MessageWrapper::new(MessageType::Request, id, request);
        let message = Self::create_prefixed_message(&message.serialize());
        self.stream.write_all(&message).await?;
        self.message_id += 1;
        let buf = self.read_prefixed_message().await?;
        let response = MessageWrapper::deserialize(&buf).unwrap();
        if response.message_id != id {
            return Err(CombinedError::ApiError(ApiError {
                status: OperationStatus::OK,
                message: response.message,
                is_wrong_message_id: true,
            }));
        }
        Ok(response.message)
    }
}
