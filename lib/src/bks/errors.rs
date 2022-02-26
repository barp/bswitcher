use hex;
use std::error::Error;
use std::fmt::{self, Display};

#[derive(Debug)]
pub enum BksError {
    IoError(std::io::Error),
    FormatError(BksFormatError),
    Utf8Error(std::string::FromUtf8Error),
    SignatureError(KeystoreSignatureError),
}

impl From<std::io::Error> for BksError {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e)
    }
}

impl From<BksFormatError> for BksError {
    fn from(e: BksFormatError) -> Self {
        Self::FormatError(e)
    }
}

impl From<std::string::FromUtf8Error> for BksError {
    fn from(e: std::string::FromUtf8Error) -> Self {
        Self::Utf8Error(e)
    }
}

impl From<KeystoreSignatureError> for BksError {
    fn from(e: KeystoreSignatureError) -> Self {
        Self::SignatureError(e)
    }
}

#[derive(Debug)]
pub struct BksFormatError {
    cause: String,
}

impl BksFormatError {
    pub fn new(cause: String) -> BksFormatError {
        BksFormatError { cause }
    }
}

impl Display for BksFormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        String::fmt(&self.cause, f)
    }
}

impl Error for BksFormatError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }

    fn description(&self) -> &str {
        "description() is deprecated; use Display"
    }

    fn cause(&self) -> Option<&dyn Error> {
        self.source()
    }
}

#[derive(Debug)]
pub struct KeystoreSignatureError {
    signature: Vec<u8>,
    expected: Vec<u8>,
}

impl Display for KeystoreSignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!(
            "Signature mismatch got: {}, expected: {}. Did you provide wrong password?",
            hex::encode(&self.signature),
            hex::encode(&self.expected)
        ))
    }
}

impl KeystoreSignatureError {
    pub fn new(expected: Vec<u8>, signature: Vec<u8>) -> Self {
        Self {
            expected,
            signature,
        }
    }
}
