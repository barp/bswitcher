use clap::{Parser, Subcommand};

mod api;

use crate::api::api::*;
use crate::api::keygen::*;

#[derive(Parser)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Discover,
    Register,
}

#[async_std::main]
async fn main() {
    let cli = Cli::parse();
    match &cli.command {
        Commands::Discover => discover_central_units().await.unwrap(),
        Commands::Register => {
            let (pk, cert) = generate_keypair("barp12@gmail.com");
            print!(
                "{}",
                String::from_utf8(pk.private_key_to_pem_pkcs8().unwrap()).unwrap()
            );
            println!("{}", String::from_utf8(cert.to_pem().unwrap()).unwrap());
        }
    }
    // let x = get_default_https_client()
    //     .await
    //     .unwrap()
    //     .post("http://asdas.com")
    //     .send()
    //     .await
    //     .unwrap()
    //     .text()
    //     .await
    //     .unwrap();
    // println!("{}", x)
    // discover_central_units().await.unwrap();
}
