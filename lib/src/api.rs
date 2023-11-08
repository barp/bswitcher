use async_native_tls;
use async_std;
use async_std::fs;
use async_std::net::UdpSocket;
use async_std::prelude::*;
use base64;
use reqwest::tls::Identity;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Debug, Display};
use std::str;
use std::time::{Duration, SystemTime};

use crate::protocol::CuClient;

#[cfg(feature = "python")]
use pyo3::create_exception;
#[cfg(feature = "python")]
use pyo3::exceptions::PyException;
#[cfg(feature = "python")]
use pyo3::prelude::*;

#[derive(Debug)]
pub struct ApiError {
    pub status: OperationStatus,
    pub message: String,
    pub is_wrong_message_id: bool,
}

impl Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.is_wrong_message_id {
            false => f.write_fmt(format_args!(
                "SwitchBee API error returned: {}",
                self.status.to_string()
            )),
            true => f.write_fmt(format_args!("Got bad message id from server")),
        }
    }
}

#[cfg(feature = "python")]
create_exception!(libpybswitch, TlsError, PyException);

#[cfg(feature = "python")]
create_exception!(libpybswitch, IoError, PyException);

#[cfg(feature = "python")]
create_exception!(libpybswitch, HttpsError, PyException);

#[cfg(feature = "python")]
create_exception!(libpybswitch, JSONDecodeError, PyException);

#[cfg(feature = "python")]
create_exception!(libpybswitch, PyApiError, PyException);

#[cfg(feature = "python")]
create_exception!(libpybswitch, Ut8DecodeError, PyException);

#[cfg(feature = "python")]
create_exception!(libpybswitch, Base64DecodeError, PyException);

#[derive(Debug)]
pub enum CombinedError {
    IoError(async_std::io::Error),
    ReqwestError(reqwest::Error),
    AsyncTlsError(async_native_tls::Error),
    SerdeJsonError(serde_json::Error),
    ApiError(ApiError),
    Utf8Error(str::Utf8Error),
    B64DecodeError(base64::DecodeError),
    OpenSSLError(openssl::error::ErrorStack),
}

#[cfg(feature = "python")]
impl From<CombinedError> for PyErr {
    fn from(err: CombinedError) -> Self {
        match err {
            CombinedError::IoError(err) => IoError::new_err(err.to_string()),
            CombinedError::ReqwestError(err) => HttpsError::new_err(err.to_string()),
            CombinedError::AsyncTlsError(err) => TlsError::new_err(err.to_string()),
            CombinedError::SerdeJsonError(err) => JSONDecodeError::new_err(err.to_string()),
            CombinedError::ApiError(err) => PyApiError::new_err(err.to_string()),
            CombinedError::Utf8Error(err) => Ut8DecodeError::new_err(err.to_string()),
            CombinedError::B64DecodeError(err) => Base64DecodeError::new_err(err.to_string()),
            CombinedError::OpenSSLError(err) => TlsError::new_err(err.to_string()),
        }
    }
}

impl From<openssl::error::ErrorStack> for CombinedError {
    fn from(e: openssl::error::ErrorStack) -> Self {
        Self::OpenSSLError(e)
    }
}

impl From<base64::DecodeError> for CombinedError {
    fn from(e: base64::DecodeError) -> Self {
        Self::B64DecodeError(e)
    }
}

impl From<async_std::io::Error> for CombinedError {
    fn from(e: async_std::io::Error) -> Self {
        Self::IoError(e)
    }
}

impl From<reqwest::Error> for CombinedError {
    fn from(e: reqwest::Error) -> Self {
        Self::ReqwestError(e)
    }
}

impl From<serde_json::Error> for CombinedError {
    fn from(e: serde_json::Error) -> Self {
        Self::SerdeJsonError(e)
    }
}

impl From<async_native_tls::Error> for CombinedError {
    fn from(e: async_native_tls::Error) -> Self {
        Self::AsyncTlsError(e)
    }
}

impl From<str::Utf8Error> for CombinedError {
    fn from(e: str::Utf8Error) -> Self {
        Self::Utf8Error(e)
    }
}

pub type Result<T> = std::result::Result<T, CombinedError>;

#[derive(Debug, Deserialize, Clone)]
pub struct UnitItem {
    pub name: String,
    #[serde(rename = "unitId")]
    pub unit_id: i32,
    pub value: i32,
    #[serde(rename = "type")]
    pub unit_type: i32,
}

#[derive(Debug, Deserialize)]
pub struct Zone {
    pub id: i32,
    pub name: String,
    pub items: Vec<UnitItem>,
}

#[derive(Debug, Deserialize)]
pub struct Place {
    pub zones: Vec<Zone>,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case, dead_code)]
#[cfg_attr(feature = "python", pyclass)]
pub struct CuData {
    #[serde(default)]
    pub CUIP: String,
    CUVersion: String,
    #[serde(default)]
    NoUsers: bool,
    #[serde(default)]
    apVer: i32,
    #[serde(default)]
    autoHolidayMode: bool,
    #[serde(default)]
    holiday: bool,
    ip: String,
    #[serde(default)]
    lat: f64,
    #[serde(default)]
    lon: f64,
    mac: String,
    name: String,
    #[serde(default)]
    pin: i32,
    #[serde(default)]
    pnpe: bool,
    port: i32,
    #[serde(default)]
    time: i64,
    timeStr: String,
    timeZone: i32,
    timeZoneName: String,
    pub place: Option<Place>,
}

#[cfg(feature = "python")]
#[pymethods]
impl CuData {
    #[getter(CUIP)]
    fn py_cuip(&self) -> String {
        self.CUIP.to_string()
    }

    pub fn __repr__(&self) -> PyResult<String> {
        Ok(format!("CuData<CUIP: {}>", self.CUIP))
    }
}

#[derive(Debug, Serialize)]
pub struct UnitItemOperation {
    #[serde(rename = "newState")]
    pub new_state: i32,
    #[serde(rename = "type")]
    pub unit_type: i32,
    #[serde(rename = "unitId")]
    pub unit_id: i32,
}

#[derive(Serialize)]
#[cfg_attr(feature = "python", pyclass)]
pub struct RegisterDeviceParams {
    // Device model
    pub device: String,
    // Generated public key x509
    #[serde(rename = "deviceCertificate")]
    pub device_certificate: String,
    pub email: String,
    // password generated when adding a managing device in the application menu
    pub key: String,
    // Admin name
    pub name: String,
    pub password: String,
    // seems to be unused
    pub pin: String,
}

#[cfg(feature = "python")]
#[pymethods]
impl RegisterDeviceParams {
    #[setter(device)]
    fn py_device_set(&mut self, device: String) -> () {
        self.device = device
    }
    #[getter(device)]
    fn py_device(&self) -> String {
        self.device.to_owned()
    }
    #[setter(device_certificate)]
    fn py_device_certificate_set(&mut self, cert: String) -> () {
        self.device_certificate = cert
    }
    #[getter(device_certificate)]
    fn py_device_certificate(&self) -> String {
        self.device_certificate.to_owned()
    }

    #[setter(email)]
    fn py_email_set(&mut self, email: String) -> () {
        self.email = email
    }
    #[getter(email)]
    fn py_email(&self) -> String {
        self.email.to_owned()
    }
    #[setter(key)]
    fn py_key_set(&mut self, key: String) -> () {
        self.key = key
    }
    #[getter(key)]
    fn py_key(&self) -> String {
        self.key.to_owned()
    }
    #[setter(name)]
    fn py_name_set(&mut self, name: String) -> () {
        self.name = name
    }
    #[getter(name)]
    fn py_name(&self) -> String {
        self.name.to_owned()
    }
    #[setter(password)]
    fn py_password_set(&mut self, password: String) -> () {
        self.password = password
    }
    #[getter(password)]
    fn py_password(&self) -> String {
        self.password.to_owned()
    }
    #[setter(pin)]
    fn py_pin_set(&mut self, pin: String) -> () {
        self.pin = pin
    }
    #[getter(password)]
    fn py_pin(&self) -> String {
        self.pin.to_owned()
    }
}

#[derive(Deserialize, PartialEq, Debug)]
pub enum OperationStatus {
    OK,
    ERROR,
    KeyError,
    EmailError,
    PermissionError,
    UserNotFound,
    DeviceNotFound,
    FileNotFound,
    LastAdminError,
    NameError,
    Busy,
    Full,
    Empty,
    SignalError,
    Timeout,
    Cancelled,
}

impl fmt::Display for OperationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Debug::fmt(self, f)
    }
}

#[derive(Deserialize, Debug)]
#[cfg_attr(feature = "python", pyclass)]
pub struct CuStatus {
    pub status: OperationStatus,
}

#[derive(Deserialize, Debug)]
#[cfg_attr(feature = "python", pyclass)]
pub struct RegisterDeviceResponse {
    #[serde(flatten)]
    pub status: CuStatus,
}

#[cfg(feature = "python")]
#[pymethods]
impl RegisterDeviceResponse {
    fn py_status(&self) -> String {
        self.status.status.to_string()
    }
}

async fn collect_responses(socket: UdpSocket, exit_on_first: bool) -> Result<Vec<CuData>> {
    let mut buf: [u8; 10000] = [0; 10000];

    let mut results: Vec<CuData> = Vec::new();

    let timeout = SystemTime::now()
        .checked_add(Duration::from_secs(5))
        .unwrap();

    loop {
        let current_dur = match timeout.duration_since(SystemTime::now()) {
            Ok(val) => val,
            Err(_) => break,
        };
        let (data_size, ip) = match socket.recv_from(&mut buf).timeout(current_dur).await {
            Ok(result) => result,
            Err(_) => break,
        }?;
        let str_data = str::from_utf8(&buf[0..data_size]).unwrap();
        let mut cudata: CuData = serde_json::from_str(str_data).unwrap();
        cudata.CUIP = ip.ip().to_string();
        results.push(cudata);
        if exit_on_first {
            break;
        }
    }

    Ok(results)
}

pub async fn discover_central_units(exit_on_first: bool) -> Result<Vec<CuData>> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.set_broadcast(true)?;
    socket
        .send_to("FIND".as_bytes(), "255.255.255.255:8872".to_string())
        .await?;
    Ok(collect_responses(socket, exit_on_first).await?)
}

pub async fn get_guest_identity() -> Result<Identity> {
    let contents = include_bytes!("key");
    Ok(reqwest::Identity::from_pkcs12_der(contents, "1234")?)
}

// Client used for device registration, requires the guest certificate
pub async fn get_default_https_client() -> Result<reqwest::Client> {
    Ok(Client::builder()
        // .add_root_certificate(cert)
        .danger_accept_invalid_certs(true)
        .identity(get_guest_identity().await?)
        .build()?)
}

pub async fn get_device_identity(path: &str) -> Result<async_native_tls::Identity> {
    let contents = fs::read(path).await?;
    Ok(async_native_tls::Identity::from_pkcs12(&contents, "1234")?)
}

pub async fn register_device(
    client: &reqwest::Client,
    ip: &str,
    params: &RegisterDeviceParams,
) -> Result<RegisterDeviceResponse> {
    let req_text = "REGD".to_string() + &serde_json::to_string(params)?;
    let req = match client
        .post("https://".to_owned() + ip + ":8443/commands")
        .body(req_text)
        .send()
        .await
    {
        Ok(val) => val,
        Err(e) => {
            println!("Failed to send request {}\n", e);
            return Err(CombinedError::ReqwestError(e));
        }
    };
    let resp_text = req.text().await?;
    let resp: RegisterDeviceResponse = serde_json::from_str(&resp_text)?;
    if resp.status.status != OperationStatus::OK {
        return Err(CombinedError::ApiError(ApiError {
            message: resp_text,
            status: resp.status.status,
            is_wrong_message_id: false,
        }));
    }
    Ok(resp)
}

impl CuClient {
    pub async fn get_all(&mut self) -> Result<CuData> {
        let resp = self.request("GETA").await?;
        Ok(serde_json::from_str::<CuData>(&resp)?)
    }
    pub async fn unit_operation(&mut self, op: &UnitItemOperation) -> Result<CuStatus> {
        let resp = self
            .request(&("UNOP".to_string() + &serde_json::to_string(op)?.to_owned()))
            .await?;
        let resp: CuStatus = serde_json::from_str(&resp)?;
        if resp.status != OperationStatus::OK {
            return Err(CombinedError::ApiError(ApiError {
                message: resp.status.to_string(),
                status: resp.status,
                is_wrong_message_id: false,
            }));
        }
        Ok(resp)
    }
}
