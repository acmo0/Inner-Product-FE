use std::collections::HashSet;
use std::fs;

use anyhow::{Error, Result, anyhow};
use fe::{GroupElement, PublicKey, SecretKey, CompressedSecretKey, traits::FESecretKey, RANDOM_PADDING_LEN};
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
    cache_path: std::path::PathBuf,
    cache: Vec<u8>,
}

const VECTOR_SIZE: usize = NILSIMSA_VECTOR_SIZE_BITS + RANDOM_PADDING_LEN;
const FH_SQL_QUERY: &str = "SELECT fh FROM fuzzy_hashes WHERE type == :hash_type";
const PK_SQL_QUERY: &str = "SELECT * FROM public_keys WHERE type == :hash_type";
const SK_SQL_QUERY: &str = "SELECT * from secret_keys WHERE type == :hash_type AND pk_id == :pk_id";

impl Server {
    pub fn new(listener: TcpListener, db_connection: Connection, authority_addr: String, cache_path: std::path::PathBuf) -> Self {
        Self {
            listener,
            db_connection,
            authority_addr,
            cache_path,
            cache: vec![],
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

    fn from_cache(&self) -> Result<Vec<(PublicKey<VECTOR_SIZE>, Vec<CompressedSecretKey>, Vec<FHVector<u8>>)>> {
        if self.cache.is_empty() {
            Ok(vec![])
        } else {
            match postcard::from_bytes::<Vec<(PublicKey<VECTOR_SIZE>, Vec<CompressedSecretKey>, Vec<FHVector<u8>>)>>(&self.cache) {
                Ok(c) => Ok(c),
                _ => Ok(vec![]),
            }
        }
    }

    fn to_cache(&mut self, cache: Vec<(PublicKey<VECTOR_SIZE>, Vec<CompressedSecretKey>, Vec<FHVector<u8>>)>) {
        self.cache = postcard::to_stdvec(&cache).unwrap();
    }

    fn get_cache(&self) -> Vec<u8> {
        self.cache.clone()
    }

/*    fn get_nilsimsa_public_keys(&self) -> Result<Vec<(u32, PublicKey<VECTOR_SIZE>)>> {
        let mut pk_statement = self.db_connection.prepare(PK_SQL_QUERY)?;

        let pks = pk_statement
            .query_map(named_params! {":hash_type": "nilsimsa"}, |row| {
                let pk_id: u32 = row.get("pk_id").expect("Malformed database");
                let pk_blob: Vec<u8> = row.get("pk").expect("Malformed database");

                let pk: PublicKey<VECTOR_SIZE> = postcard::from_bytes(&pk_blob).expect("Malformed database");
                Ok((pk_id, pk))
            })?
            .map(|e| e.expect("Malformed public key in database"))
            .collect();

        Ok(pks)
    }

    fn get_nilsimsa_secret_key(&self, pk_id: u32) -> Result<Vec<SecretKey<VECTOR_SIZE>>> {
        let mut sk_statement = self.db_connection.prepare(SK_SQL_QUERY)?;

        let sks = sk_statement
            .query_map(named_params! {":hash_type": "nilsimsa", "pk_id": pk_id}, |row| {
                let sk_blob: Vec<u8> = row.get("sk")
            })
    }*/

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
        self.cache = {
            if fs::exists(&self.cache_path)? {
                fs::read(&self.cache_path)?
            } else {
                vec![]
            }
        };

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
            let mut hashes: HashSet<FHVector<u8>> = match requested_hash_type {
                HashComparisonRequest::NILSIMSA => match self.get_nilsimsa_hashes() {
                    Err(error) => return Err(error),
                    Ok(v) => HashSet::from_iter(v),
                },
            };

            info!("Loaded {} fuzzy hashes", hashes.len());
            info!("Loading cache");
            let mut cache = self.from_cache()?;

            let cached_hashes: HashSet<FHVector<u8>> = HashSet::from_iter(cache.iter().flat_map(|(_,_,fhs)| fhs.clone()));
            let diff: HashSet<FHVector<u8>> = (&hashes - &cached_hashes);

            let remaining_hashes: Vec<_> = diff.into_iter().collect();

            info!("Query authority server for additionnal secret keys");
            let (mut keys, fhs) = match requested_hash_type {
                HashComparisonRequest::NILSIMSA => {
                    let mut batches = (vec![], vec![]);

                    for hashes_batch in remaining_hashes.chunks(RANDOM_PADDING_LEN) {
                        let compressed_response = self
                            .retrieve_secret_keys::<VECTOR_SIZE>(hashes_batch)
                            .await?;
                        match compressed_response.decompress() {
                            Ok(decompressed) => {
                                batches.0.push(decompressed);
                                batches.1.push(hashes_batch);
                            },
                            _ => return Err(anyhow!("Unable to retrieve vectors from authority")),
                        }
                    }
                    batches
                }
            };
            info!("Received pk/sk from authority");
            
            for ((pk, sks), fhs2) in keys.into_iter().zip(fhs) {
                cache.push((
                    pk,
                    sks.iter().map(|sk: &SecretKey<VECTOR_SIZE>| {
                    let compressed: CompressedSecretKey = sk.into();
                    compressed
                    }).collect(),
                    fhs2.to_vec()));
            }

            keys = cache.iter().cloned().map(|(pk, sks, _)| {
                let sks_decompressed = sks.iter().map(|sk| {let decompressed: SecretKey<VECTOR_SIZE> = sk.try_into().unwrap(); decompressed }).collect();
                (pk, sks_decompressed)
            }).collect();

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

            self.to_cache(cache);
            debug!("Writing to cache file");
            fs::write(&self.cache_path, &self.cache)?;
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

            scores = sks.iter().map(|sk| sk.partial_decrypt(ct)).collect();
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
