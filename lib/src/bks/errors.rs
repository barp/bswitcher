use std::error::Error;
use std::fmt;

pub enum BksError {
    IoError(std::io::Error),
    FormatError(BksFormatError),
    Utf8Error(std::string::FromUtf8Error),
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

#[derive(Debug)]
pub struct BksFormatError {
    cause: String,
}

impl BksFormatError {
    pub fn new(cause: String) -> BksFormatError {
        BksFormatError { cause }
    }
}

impl fmt::Display for BksFormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self, f)
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
