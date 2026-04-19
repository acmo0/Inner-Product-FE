use std::time::Duration;

use anyhow::{Error, Result};
use cpu_time::ProcessTime;
use futures::SinkExt;
use futures::StreamExt;
use log::{debug, error, info};
use rand::seq::SliceRandom;
use rand::{
    SeedableRng,
    rngs::{StdRng, SysRng},
};
use rayon::prelude::*;
use rusqlite::Connection;
use rusqlite::named_params;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};

use fe::{
    CompressedGroupElement, CompressedSecretKey, GroupElement, PublicKey, RANDOM_PADDING_LEN,
    SecretKey, traits::FESecretKey,
};
use messages::{
    EncryptionRequest, EncryptionResponse, FHVector, GenerateInstanceResponse,
    HashComparisonRequest, NILSIMSA_VECTOR_SIZE_BITS,
};

// Stateful server for a single client
#[derive(Debug)]
pub struct Server {
    listener: TcpListener,
    db_connection: Connection,
    authority_addr: String,
}

// SQL query to retrieve fuzzy hashes from a DB
const VECTOR_SIZE: usize = NILSIMSA_VECTOR_SIZE_BITS + RANDOM_PADDING_LEN;
const FH_SQL_QUERY: &str = "SELECT fh FROM fuzzy_hashes WHERE type == :hash_type";

impl Server {
    // Create new server
    pub fn new(listener: TcpListener, db_connection: Connection, authority_addr: String) -> Self {
        Self {
            listener,
            db_connection,
            authority_addr,
        }
    }

    // Retrieve all the fuzzy hashes from the database
    fn get_nilsimsa_hashes(&self) -> Result<Vec<FHVector<u8>>> {
        let mut nilsimsa_statement = self.db_connection.prepare(FH_SQL_QUERY)?;

        let mut vectors: Vec<_> = nilsimsa_statement
            .query_map(named_params! {":hash_type": "nilsimsa"}, |row| {
                let r: [u8; 32] = row.get("fh").expect("Malformed database");
                Ok(FHVector::from(r))
            })?
            .map(|vector| vector.expect("Malformed fuzzy hash in database"))
            .collect();

        // Shuffle the vectors
        let mut rng = StdRng::try_from_rng(&mut SysRng).unwrap();
        vectors.shuffle(&mut rng);

        Ok(vectors)
    }

    // Ask the authority for a secret key to each fuzzy hash
    async fn retrieve_secret_keys<const N: usize>(
        &self,
        vectors: &[FHVector<u8>],
    ) -> Result<GenerateInstanceResponse<N>> {
        // Connect to authority
        let mut authority_stream = TcpStream::connect(&self.authority_addr).await?;
        info!("Connection opened with authority");

        // Send the fuzzy hashes
        let mut codec = LengthDelimitedCodec::new();
        codec.set_max_frame_length(usize::MAX);

        let mut writer = FramedWrite::new(&mut authority_stream, codec.clone());
        let serialized = postcard::to_stdvec(vectors)?;
        writer.send(serialized.into()).await.unwrap();
        info!("Sended vectors to authority");

        // Retrieve the server key from the authority
        let mut reader = FramedRead::new(&mut authority_stream, codec);
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

            // Loading fuzzy hashes from db
            info!("Loading {:?} fuzzy hashes", requested_hash_type);
            let hashes = match requested_hash_type {
                HashComparisonRequest::NILSIMSA => match self.get_nilsimsa_hashes() {
                    Err(error) => return Err(error),
                    Ok(v) => v,
                },
            };

            // Ask the authority for the secret keys
            info!("Loaded {} fuzzy hashes", hashes.len());
            info!("Query authority server for secret keys");

            let start = ProcessTime::now();

            let keys = match requested_hash_type {
                HashComparisonRequest::NILSIMSA => {
                    self.retrieve_secret_keys::<VECTOR_SIZE>(&hashes).await?.0
                }
            };

            let cpu_time: Duration = start.elapsed();
            info!("CPU Time for querying secret keys {:?}", cpu_time);

            info!("Received pk/sk from authority");
            // Spawn a handler for that client
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

/*
    Single client handling
*/
struct ClientHandler<const N: usize> {
    stream: TcpStream,
    hash_type: HashComparisonRequest,
    keys: Vec<(PublicKey<N>, Vec<CompressedSecretKey>)>,
}

impl ClientHandler<VECTOR_SIZE> {
    pub async fn handle_client(&mut self) -> Result<()> {
        // Split between read and write
        let (mut rx, mut tx) = self.stream.split();

        // Init framed read/write
        let mut writer = FramedWrite::new(&mut tx, LengthDelimitedCodec::new());
        let mut reader = FramedRead::new(&mut rx, LengthDelimitedCodec::new());

        // Store the partial decryption for each batch
        let mut scores: Vec<GroupElement> = vec![];

        let start = ProcessTime::now();

        for (pk, sks) in &self.keys {
            // Send the right message to the client depending on the
            // request that was made.
            let message = match self.hash_type {
                HashComparisonRequest::NILSIMSA => {
                    EncryptionRequest::<VECTOR_SIZE, CompressedGroupElement> {
                        pk: Some(pk.into()),
                        similarity_scores: Some(scores.iter().map(|p| p.compress()).collect()),
                    }
                }
            };

            // Sending the public key to the client
            debug!("Sending PK to client");
            writer.send(postcard::to_stdvec(&message)?.into()).await?;

            // Retrieve the encryption sent by the client
            let encrypted_vector = match self.hash_type {
                HashComparisonRequest::NILSIMSA => {
                    postcard::from_bytes::<EncryptionResponse<VECTOR_SIZE>>(
                        reader.next().await.unwrap().unwrap().to_vec().as_slice(),
                    )?
                }
            };

            // Check if the client send an encryption or a EndOfComparison request
            let ct = match encrypted_vector {
                EncryptionResponse::<_>::EncryptedVector(ct) => ct,
                EncryptionResponse::<_>::EndOfComparison => break,
            };

            // Naive parallelization of the partial decryptions
            scores = sks
                .par_iter()
                .map(|sk: &CompressedSecretKey| {
                    let sk_decompressed: SecretKey<VECTOR_SIZE> = sk.try_into().unwrap();
                    sk_decompressed.partial_decrypt(&ct)
                })
                .collect();
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

        let cpu_time: Duration = start.elapsed();
        info!("CPU Time to handle client {:?}", cpu_time);
        info!("Handling client");
        Ok(())
    }
}
