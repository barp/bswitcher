use async_std::fs;
use base64;
use clap::{Parser, Subcommand};

use bswitch::api::*;
use bswitch::keygen::*;
use bswitch::protocol::*;

#[derive(Parser)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Discover,
    Register {
        #[clap(long)]
        ip: Option<String>,
        email: String,
        password: String,
    },
    SendCommand {
        #[clap(long)]
        ip: Option<String>,
        certificate_path: String,
        message: String,
    },
    GetAllUnits {
        #[clap(long)]
        ip: Option<String>,
        certificate_path: String,
    },
    TurnOn {
        #[clap(long)]
        ip: Option<String>,
        certificate_path: String,
        #[clap(name = "type")]
        unit_type: i32,
        unit_id: i32,
    },
    TurnOff {
        #[clap(long)]
        ip: Option<String>,
        certificate_path: String,
        #[clap(name = "type")]
        unit_type: i32,
        unit_id: i32,
    },
}

async fn get_cu_ip(ip: &Option<String>) -> Result<String> {
    Ok(match ip {
        Some(p) => p.to_string(),
        None => {
            let cu = discover_central_units(true).await?;
            if cu.len() < 1 {
                panic!("no central unit found")
            }
            cu[0].CUIP.to_owned()
        }
    })
}

#[async_std::main]
async fn main() {
    let cli = Cli::parse();
    match &cli.command {
        Commands::Discover => {
            let cus = discover_central_units(false).await.unwrap();
            println!("{:?}", cus)
        }
        Commands::Register {
            ip,
            email,
            password,
        } => {
            let real_ip = get_cu_ip(ip).await.unwrap();
            let (pk, cert) = generate_keypair("barp12@gmail.com");
            let params = RegisterDeviceParams {
                name: email.to_string(),
                email: email.to_string(),
                key: password.to_string(),
                password: "".to_string(),
                pin: "".to_string(),
                device: "android_REL_HA".to_string(),
                deviceCertificate: base64::encode_config(cert.to_der().unwrap(), base64::URL_SAFE),
            };
            let client = get_default_https_client().await.unwrap();
            let resp = register_device(&client, &real_ip, &params).await.unwrap();
            println!("resp: {:?}", resp);
            println!("saving private key in device.key");
            let pkcs12cert = openssl::pkcs12::Pkcs12::builder()
                .build("1234", "device cert", &pk, &cert)
                .unwrap();
            fs::write("./device.key", pkcs12cert.to_der().unwrap())
                .await
                .unwrap();
        }
        Commands::SendCommand {
            ip,
            certificate_path,
            message,
        } => {
            let ip = get_cu_ip(ip).await.unwrap();
            let identity = get_device_identity(certificate_path).await.unwrap();
            let mut client = CuClient::new(&ip, 23789, identity).await.unwrap();
            let resp = client.request(message).await.unwrap();
            println!("{}", resp);
        }
        Commands::GetAllUnits {
            ip,
            certificate_path,
        } => {
            let ip = get_cu_ip(ip).await.unwrap();
            let identity = get_device_identity(certificate_path).await.unwrap();
            let mut client = CuClient::new(&ip, 23789, identity).await.unwrap();
            let resp = client.get_all().await.unwrap();
            for zone in &resp.place.as_ref().unwrap().zones {
                for item in &zone.items {
                    println!("{:?}", item)
                }
            }
        }
        Commands::TurnOn {
            ip,
            certificate_path,
            unit_type,
            unit_id,
        } => {
            let ip = get_cu_ip(ip).await.unwrap();
            let identity = get_device_identity(certificate_path).await.unwrap();
            let mut client = CuClient::new(&ip, 23789, identity).await.unwrap();
            let resp = client
                .unit_operation(&UnitItemOperation {
                    unit_id: *unit_id,
                    unit_type: *unit_type,
                    new_state: 100,
                })
                .await
                .unwrap();
            println!("{:?}", resp)
        }
        Commands::TurnOff {
            ip,
            certificate_path,
            unit_type,
            unit_id,
        } => {
            let ip = get_cu_ip(ip).await.unwrap();
            let identity = get_device_identity(certificate_path).await.unwrap();
            let mut client = CuClient::new(&ip, 23789, identity).await.unwrap();
            let resp = client
                .unit_operation(&UnitItemOperation {
                    unit_id: *unit_id,
                    unit_type: *unit_type,
                    new_state: 0,
                })
                .await
                .unwrap();
            println!("{:?}", resp)
        }
    }
}
