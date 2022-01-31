use async_std;
use async_std::net::UdpSocket;
use async_std::prelude::*;
use serde::Deserialize;
use std::str;
use std::time::{Duration, SystemTime};

#[derive(Deserialize)]
#[allow(non_snake_case, dead_code)]
struct CuData {
    CUIP: String,
    CUVersion: String,
    NoUsers: bool,
    apVer: i32,
    autoHolidayMode: bool,
    holiday: bool,
    ip: String,
    lat: f64,
    lon: f64,
    mac: String,
    name: String,
    pin: String,
    pnpe: bool,
    port: i32,
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

async fn collect_responses(socket: UdpSocket) -> std::io::Result<Vec<CuData>> {
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
        let ret = match socket.recv_from(&mut buf).timeout(current_dur).await {
            Ok(result) => result,
            Err(_) => break,
        }?;
        println!("data_size: {}, ip: {}", ret.0, ret.1);
        println!("data:");
        let str_data = str::from_utf8(&buf[0..ret.0]).unwrap();
        println!("{}", str_data);
        results.push(serde_json::from_str(str_data).unwrap());
    }

    Ok(results)
}

async fn discover_central_units() -> std::io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.set_broadcast(true)?;
    socket
        .send_to("find".as_bytes(), "255.255.255.255:8872".to_string())
        .await?;
    collect_responses(socket).await?;
    Ok(())
}

#[async_std::main]
async fn main() {
    discover_central_units().await.unwrap();
}
