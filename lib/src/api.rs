use async_native_tls;
use async_std;
use async_std::fs;
use async_std::net::UdpSocket;
use async_std::prelude::*;
use reqwest::tls::Identity;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::str;
use std::time::{Duration, SystemTime};

use crate::protocol::CuClient;

#[derive(Debug)]
pub struct ApiError {
    pub status: OperationStatus,
}

#[derive(Debug)]
pub enum CombinedError {
    IoError(async_std::io::Error),
    ReqwestError(reqwest::Error),
    AsyncTlsError(async_native_tls::Error),
    SerdeJsonError(serde_json::Error),
    ApiError(ApiError),
    Utf8Error(str::Utf8Error),
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

#[derive(Debug, Deserialize)]
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
#[allow(non_snake_case, dead_code)]
pub struct RegisterDeviceParams {
    // Device model
    pub device: String,
    // Generated public key x509
    pub deviceCertificate: String,
    pub email: String,
    // password
    pub key: String,
    // Admin name
    pub name: String,
    pub password: String,
    // seems to be unused
    pub pin: String,
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

#[derive(Deserialize, Debug)]
pub struct CuStatus {
    pub status: OperationStatus,
}

#[derive(Deserialize, Debug)]
pub struct RegisterDeviceResponse {
    #[serde(flatten)]
    pub status: CuStatus,
}

async fn collect_responses(socket: UdpSocket, exit_on_first: bool) -> Result<Vec<CuData>> {
    let mut buf: [u8; 100000] = [0; 100000];

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

async fn get_guest_identity() -> Result<Identity> {
    let contents = fs::read("./id.pfx").await?;
    Ok(reqwest::Identity::from_pkcs12_der(&contents, "1234")?)
}

// Client used for device registration, requires the guest certificate
pub async fn get_default_https_client() -> Result<reqwest::Client> {
    let identity = get_guest_identity().await?;
    Ok(Client::builder()
        // .add_root_certificate(cert)
        .danger_accept_invalid_certs(true)
        .identity(identity)
        .build()?)
}

pub async fn get_device_identity(path: &str) -> Result<async_native_tls::Identity> {
    let contents = fs::read(path).await?;
    Ok(async_native_tls::Identity::from_pkcs12(&contents, "1234")?)
}

pub async fn register_device(
    client: &reqwest::Client,
    ip: &String,
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
    let resp = req.text().await?;
    let resp: RegisterDeviceResponse = serde_json::from_str(&resp)?;
    if resp.status.status != OperationStatus::OK {
        return Err(CombinedError::ApiError(ApiError {
            status: resp.status.status,
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
                status: resp.status,
            }));
        }
        Ok(resp)
    }
}
