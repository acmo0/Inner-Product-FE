use rayon::prelude::*;
use anyhow::{Error, Result, anyhow};
use fe::{GroupElement, PublicKey, SecretKey, traits::FESecretKey, RANDOM_PADDING_LEN};
use log::{debug, error, info};
use tokio::net::{TcpListener, TcpStream};

use futures::SinkExt;
use futures::StreamExt;
use fuzzy_hashes::{FHVector, NILSIMSA_VECTOR_SIZE_BITS};
use messages::{
    EncryptionRequest, EncryptionResponse, GenerateInstanceResponse, HashComparisonRequest,
};
use rusqlite::Connection;
use rusqlite::named_params;
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};

use comparator::Comparator;

#[derive(Debug)]
pub struct Server {
    listener: TcpListener,
    db_connection: Connection,
    authority_addr: String,
}

const VECTOR_SIZE: usize = NILSIMSA_VECTOR_SIZE_BITS + RANDOM_PADDING_LEN;
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

            info!("Loading client request");
            let mut reader = FramedRead::new(&mut s, LengthDelimitedCodec::new());
            let frame = reader.next().await.unwrap().unwrap();

            let requested_hash_type: HashComparisonRequest =
                postcard::from_bytes(&frame).expect("Failed to understand client request");

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
                    for hashes_batch in hashes.chunks(RANDOM_PADDING_LEN) {
                        let compressed_response = self
                            .retrieve_secret_keys::<VECTOR_SIZE>(hashes_batch)
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
                    hash_type: requested_hash_type,
                    keys,
                };

                match client_handler.handle_client().await {
                    Ok(_) => {}
                    Err(error) => {
                        error!("Error while handling client : {}", error)
                    }
                }
            });
        }
    }

    async fn accept_conn(&mut self) -> Result<TcpStream> {
        match self.listener.accept().await {
            Ok((sock, _)) => Ok(sock),
            Err(e) => Err(Error::from(e)),
        }
    }
}

struct ClientHandler<const N: usize> {
    stream: TcpStream,
    hash_type: HashComparisonRequest,
    keys: Vec<(PublicKey<N>, Vec<SecretKey<N>>)>,
}

impl ClientHandler<VECTOR_SIZE> {
    /// The protocol is using framed content, encoded by prefixing the length of the payload
    /// This reads an entire frame and returns what the readed frame.
    async fn read_frame(&mut self) -> Result<Vec<u8>> {
        let mut reader = FramedRead::new(&mut self.stream, LengthDelimitedCodec::new());
        let frame = reader.next().await.unwrap().unwrap().to_vec();
        Ok(frame)
    }

    /// The protocol is using framed content, encoded by prefixing the length of the payload
    /// This write an entire frame made of the given bytes.
    async fn write_frame(&mut self, bytes: Vec<u8>) -> Result<()> {
        let mut writer = FramedWrite::new(&mut self.stream, LengthDelimitedCodec::new());
        writer.send(bytes.into()).await?;
        Ok(())
    }

    pub async fn handle_client(&mut self) -> Result<()> {
        // Split between read and write
        let (mut rx, mut tx) = self.stream.split();

        // Init framed read/write
        let mut writer = FramedWrite::new(&mut tx, LengthDelimitedCodec::new());
        let mut reader = FramedRead::new(&mut rx, LengthDelimitedCodec::new());

        let mut scores: Vec<GroupElement> = vec![];

        for (pk, sks) in &self.keys {
            let message = match self.hash_type {
                HashComparisonRequest::NILSIMSA => {
                    EncryptionRequest::<VECTOR_SIZE, GroupElement> {
                        pk: Some(pk.clone()),
                        similarity_scores: Some(scores.clone()),
                    }
                }
            };

            debug!("Sending PK to client");
            writer.send(postcard::to_stdvec(&message)?.into()).await?;

            let encrypted_vector = match self.hash_type {
                HashComparisonRequest::NILSIMSA => {
                    postcard::from_bytes::<EncryptionResponse<VECTOR_SIZE>>(
                        reader.next().await.unwrap().unwrap().to_vec().as_slice(),
                    )?
                }
            };

            let ct = match encrypted_vector {
                EncryptionResponse::<_>::EncryptedVector(ct) => ct,
                EncryptionResponse::<_>::EndOfComparison => break,
            };

            scores = sks.par_iter().map(|sk| sk.partial_decrypt(ct)).collect();
        }

        // Send to client the "end of the db"
        let message = match self.hash_type {
            HashComparisonRequest::NILSIMSA => {
                EncryptionRequest::<RANDOM_PADDING_LEN, GroupElement> {
                    pk: None,
                    similarity_scores: Some(scores),
                }
            }
        };
        writer.send(postcard::to_stdvec(&message)?.into()).await?;

        info!("Handling client");
        Ok(())
    }
}
