#[derive(Clone, Copy)]
pub enum MessageType {
    Request = 1,
    Response = 2,
    Notification = 3,
}

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
