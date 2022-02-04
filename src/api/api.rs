use async_std;
use async_std::fs;
use async_std::net::{SocketAddr, UdpSocket};
use async_std::prelude::*;
use reqwest::tls::{Certificate, Identity};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::str;
use std::time::{Duration, SystemTime};

#[derive(Debug)]
pub enum CombinedError {
    IoError(async_std::io::Error),
    ReqwestError(reqwest::Error),
    SerdeJsonError(serde_json::Error),
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

type Result<T> = std::result::Result<T, CombinedError>;

#[derive(Debug, Deserialize)]
#[allow(non_snake_case, dead_code)]
pub struct CuData {
    #[serde(default)]
    CUIP: String,
    CUVersion: String,
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
    pin: String,
    #[serde(default)]
    pnpe: bool,
    port: i32,
    #[serde(default)]
    time: i64,
    timeStr: String,
    timeZone: i32,
    timeZoneName: String,
    // @Expose
    // public EnabledFeatures features;
    // @Expose
    // public SwitchBeePlace place;
    // @Expose
    // public RemoteConnectionType rct;
    // @Expose
    // public Role role;
    // private HashMap<Integer, TimerItem> timersMap;
    // private Vector<UnitItem> unitItems;
    // private HashMap<Integer, UnitItem> unitsMap;
}

#[derive(Serialize, Deserialize)]
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

async fn collect_responses(socket: UdpSocket) -> Result<Vec<CuData>> {
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
        println!("ip: {}", ip);
        let str_data = str::from_utf8(&buf[0..data_size]).unwrap();
        let mut cudata: CuData = serde_json::from_str(str_data).unwrap();
        cudata.CUIP = ip.ip().to_string();
        println!("CUDATA: {:?}", cudata);
        results.push(cudata);
    }

    Ok(results)
}

pub async fn discover_central_units() -> Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.set_broadcast(true)?;
    socket
        .send_to("FIND".as_bytes(), "255.255.255.255:8872".to_string())
        .await?;
    collect_responses(socket).await?;
    Ok(())
}

async fn get_identity() -> Result<Identity> {
    let contents = fs::read("./id.pfx").await?;
    Ok(reqwest::Identity::from_pkcs12_der(&contents, "1234")?)
}

pub async fn get_default_https_client() -> Result<reqwest::Client> {
    let identity = get_identity().await?;
    Ok(Client::builder()
        // .add_root_certificate(cert)
        .danger_accept_invalid_certs(true)
        .identity(identity)
        .build()?)
}

pub async fn register_device(
    client: &reqwest::Client,
    ip: &String,
    params: &RegisterDeviceParams,
) -> Result<()> {
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
    println!("resp: {}", resp);
    Ok(())
}
