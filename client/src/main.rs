use anyhow::Result;
use anyhow::anyhow;
use clap::Parser;
use log::{debug, info};
use messages::FHVector;
use nilsimsa::Nilsimsa;
use std::fs::File;
use std::io::BufReader;
use std::io::Read;
use tokio::net::TcpStream;

mod client;
use client::Client;

/// Arguments of the program
#[derive(Parser)]
struct Cli {
    compute_addr: String,
    file: std::path::PathBuf,
    #[clap(long, action, default_value = "true", conflicts_with = "sdhash")]
    nilsimsa: bool,
    #[clap(long, action, conflicts_with = "nilsimsa")]
    sdhash: bool,
}

// 2^24 bytes
const BUF_SIZE: usize = 1usize << 24;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let args = Cli::parse();

    info!("Computing fuzzy hash for {}", &args.file.display());

    // Read the file and hash it
    let f = File::open(&args.file)?;
    let mut reader = BufReader::new(f);
    let hash: FHVector<u8>;

    if args.nilsimsa {
        debug!("Hashing using nilsimsa");
        let mut hasher = Nilsimsa::new();
        let mut buffer = vec![0; BUF_SIZE];

        loop {
            let c = reader.read(&mut buffer)?;
            if c == 0 {
                break;
            }
            hasher.update(str::from_utf8(&buffer[..c])?);
        }
        let computed_fh: [u8; 32] = hex::decode(hasher.digest())?
            .try_into()
            .expect("Unable to compute fuzzy hash.");
        println!("{:?}", computed_fh);
        hash = FHVector::from(computed_fh);
    } else if args.sdhash {
        return Err(anyhow!("Not implemented"));
    } else {
        return Err(anyhow!("Please select a fuzzy hash algorithm"));
    }

    debug!("Computed hash : {:?}", hash);

    // Connect to the compute server
    let stream = TcpStream::connect(&args.compute_addr).await?;

    // Init a new client
    let mut client = Client::new(stream, hash);
    let max_similarity_score = client.start().await?;

    println!("Max similarity score is {:?}", max_similarity_score);
    Ok(())
}
