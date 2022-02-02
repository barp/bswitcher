use clap::{Parser, Subcommand};

mod api;

use crate::api::*;

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
            let x = get_default_https_client()
                .await
                .unwrap()
                .post("https://asdas.com")
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap();
            println!("{}", x)
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
