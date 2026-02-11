mod compute_server;
use crate::compute_server::Server;

use anyhow::Result;
use clap::Parser;
use log::{error, info};
use rusqlite::Connection;
use tokio::net::TcpListener;
/// Search for a pattern in a file and display the lines that contain it.

#[derive(Parser)]
struct Cli {
    bind: String,
    authority_addr: String,
    db_path: std::path::PathBuf,
    #[clap(long, short, action)]
    populate_db: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let args = Cli::parse();

    if !args.db_path.exists() {
        return Err(anyhow::anyhow!(
            "The path {} does not exist.",
            args.db_path.display()
        ));
    }

    let ct_connection = Connection::open(args.db_path).unwrap();

    let socket = match TcpListener::bind(&args.bind).await {
        Ok(listener) => {
            info!("Successfuly started server");
            listener
        }
        Err(e) => panic!("Unable to bind {} : {}", &args.bind, e),
    };

    let mut server = Server::new(socket, ct_connection, args.authority_addr);
    server.run().await?;
    Ok(())
}
