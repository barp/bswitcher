use async_std;
use async_std::net::UdpSocket;
use async_std::prelude::*;
use std::str;
use std::time::{Duration, SystemTime};

struct CuData {}

async fn collect_responses(socket: UdpSocket) -> std::io::Result<CuData> {
    let mut buf: [u8; 100000] = [0; 100000];

    let timeout = SystemTime::now()
        .checked_add(Duration::from_secs(5))
        .unwrap();

    loop {
        let now = SystemTime::now();
        if now.ge(&timeout) {
            break;
        }
        let ret = match socket
            .recv_from(&mut buf)
            .timeout(timeout.duration_since(SystemTime::now()).unwrap())
            .await
        {
            Ok(result) => result,
            Err(_) => break,
        }?;
        println!("data_size: {}, ip: {}", ret.0, ret.1);
        println!("data:");
        println!("{}", str::from_utf8(&buf[0..ret.0]).unwrap());
    }

    Ok(CuData {})
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
