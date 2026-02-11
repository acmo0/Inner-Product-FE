mod instance_server;
use crate::instance_server::Server;

use anyhow::Result;
use log::info;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let to_bind = std::env::args()
        .nth(1)
        .expect("Please provide an address:port to bind");

    let socket = match TcpListener::bind(&to_bind).await {
        Ok(listener) => {
            info!("Successfuly started server");
            listener
        }
        Err(e) => panic!("Unable to bind {} : {}", &to_bind, e),
    };

    let mut server = Server::new(socket);
    server.run().await?;
    Ok(())
}
