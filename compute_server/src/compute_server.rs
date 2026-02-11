use anyhow::{Error, Result, anyhow};
use fe::traits::FEInstance;
use fe::{Instance, PublicKey, SecretKey};
use log::{error, info};
use tokio::io::AsyncReadExt;
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
};

use futures::StreamExt;
use futures::sink::SinkExt;
use fuzzy_hashes::{FHVector, NILSIMSA_VECTOR_SIZE_BITS, NILSIMSA_VECTOR_SIZE_BYTES};
use messages::{GenerateInstanceRequest, GenerateInstanceResponse, HashComparisonRequest};
use rusqlite::Connection;
use rusqlite::named_params;
use std::mem;
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};

#[derive(Debug)]
pub struct Server {
    listener: TcpListener,
    db_connection: Connection,
    authority_addr: String,
}

const FH_SQL_QUERY: &str = "SELECT fh FROM fuzzy_hashes WHERE type == :hash_type";

impl Server {
    pub fn new(listener: TcpListener, db_connection: Connection, authority_addr: String) -> Self {
        Self {
            listener,
            db_connection,
            authority_addr,
        }
    }

    fn get_nilsimsa_hashes(&self) -> Result<Vec<FHVector<u8>>> {
        let mut nilsimsa_statement = self.db_connection.prepare(FH_SQL_QUERY)?;

        let vectors = nilsimsa_statement
            .query_map(named_params! {":hash_type": "nilsimsa"}, |row| {
                let r: [u8; 32] = row.get("fh").expect("Malformed database");
                Ok(FHVector::from(r))
            })?
            .map(|vector| vector.expect("Malformed fuzzy hash in database"))
            .collect();

        Ok(vectors)
    }

    async fn retrieve_secret_keys<const N: usize>(
        &self,
        vectors: &[FHVector<u8>],
    ) -> Result<GenerateInstanceResponse<N>> {
        let mut authority_stream = TcpStream::connect(&self.authority_addr).await?;
        info!("Connection opened with authority");

        let mut writer = FramedWrite::new(&mut authority_stream, LengthDelimitedCodec::new());
        let serialized = postcard::to_stdvec(vectors)?;
        writer.send(serialized.into()).await.unwrap();
        info!("Sended vectors to authority");

        let mut reader = FramedRead::new(&mut authority_stream, LengthDelimitedCodec::new());
        let frame = reader.next().await.unwrap().unwrap();

        let resp: GenerateInstanceResponse<N> = postcard::from_bytes(&frame)?;

        Ok(resp)
    }

    pub async fn run(&mut self) -> Result<()> {
        loop {
            let mut s = match self.accept_conn().await {
                Ok(stream) => stream,
                Err(e) => {
                    error!("{}", e);
                    panic!("Cannot accept connection");
                }
            };

            /*            info!("Loading client request");
                        let mut reader = FramedRead::new(&mut s, LengthDelimitedCodec::new());
                        let frame = reader.next().await.unwrap().unwrap();

                        let requested_hash_type: HashComparisonRequest =
                            postcard::from_bytes(&frame).expect("Failed to understand client request");
            */
            let requested_hash_type = HashComparisonRequest::NILSIMSA;
            info!("Loading {:?} fuzzy hashes", requested_hash_type);

            let hashes = match requested_hash_type {
                HashComparisonRequest::NILSIMSA => match self.get_nilsimsa_hashes() {
                    Err(error) => return Err(error),
                    Ok(v) => v,
                },
            };

            info!("Loaded {} fuzzy hashes", hashes.len());
            info!("Query authority server for secret keys");
            let keys = match requested_hash_type {
                HashComparisonRequest::NILSIMSA => {
                    let mut batches = vec![];
                    for hashes_batch in hashes.chunks(NILSIMSA_VECTOR_SIZE_BITS - 1) {
                        let compressed_response = self
                            .retrieve_secret_keys::<NILSIMSA_VECTOR_SIZE_BITS>(hashes_batch)
                            .await?;
                        match compressed_response.decompress() {
                            Ok(decompressed) => batches.push(decompressed),
                            _ => return Err(anyhow!("Unable to retrieve vectors from authority")),
                        }
                    }
                    batches
                }
            };

            info!("Received pk/sk from authority");

            tokio::spawn(async move {
                let mut client_handler = ClientHandler {
                    stream: s,
                    keys: keys,
                };

                match client_handler.handle_client().await {
                    Ok(_) => {}
                    Err(error) => {
                        error!("Error while handling client")
                    }
                }
            });
        }
    }

    async fn accept_conn(&mut self) -> Result<TcpStream> {
        loop {
            match self.listener.accept().await {
                Ok((sock, _)) => return Ok(sock),
                Err(e) => return Err(Error::from(e)),
            }
        }
    }
}

struct ClientHandler<const N: usize> {
    stream: TcpStream,
    keys: Vec<(PublicKey<N>, Vec<SecretKey<N>>)>,
}

impl<const N: usize> ClientHandler<N> {
    pub async fn handle_client(&mut self) -> Result<()> {
        info!("Handling client");
        Ok(())
    }
}
