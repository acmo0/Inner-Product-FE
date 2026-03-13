use anyhow::Result;
use fe::curve25519_dalek::traits::Identity;
use fe::traits::FEPubKey;
use fe::{CipherText, GroupElement, LogTable, RANDOM_PADDING_LEN, Scalar};
use futures::SinkExt;
use futures::StreamExt;
use fuzzy_hashes::{FHVector, NILSIMSA_VECTOR_SIZE_BITS};
use log::{debug, info};
use messages::{EncryptionRequest, EncryptionResponse, HashComparisonRequest};
use std::array;
use tokio::net::TcpStream;
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};

use rand::{
    SeedableRng,
    rngs::{StdRng, SysRng},
};

pub struct Client {
    stream: TcpStream,
    fuzzy_hash: FHVector<u8>,
}

const VECTOR_SIZE: usize = RANDOM_PADDING_LEN + NILSIMSA_VECTOR_SIZE_BITS;

impl Client {
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

    /// Create a new client
    pub fn new(stream: TcpStream, fuzzy_hash: FHVector<u8>) -> Self {
        Self { stream, fuzzy_hash }
    }
    pub async fn start(&mut self) -> Result<i16> {
        info!("Started connection with server");

        let message = match self.fuzzy_hash {
            FHVector::NilsimsaVector(_) => HashComparisonRequest::NILSIMSA,
        };

        // Init similarity score
        let mut score = i16::MIN;
        // Init the vector to compute the fuzzy hash comparison
        let vector = match self.fuzzy_hash {
            FHVector::NilsimsaVector(_) => {
                self.fuzzy_hash.to_bits::<NILSIMSA_VECTOR_SIZE_BITS>()?
            }
        };
        // Init the RNG to perform encryption
        let mut rng = StdRng::try_from_rng(&mut SysRng).unwrap();
        let mut log_table = LogTable::new();
        let mut randoms: [Scalar; RANDOM_PADDING_LEN] = array::from_fn(|_i| Scalar::ZERO);
        let mut g: GroupElement = GroupElement::identity();

        // Compute the vector to compare fuzzy hashes
        info!("Sending request to server");
        self.write_frame(postcard::to_stdvec(&message)?).await?;

        loop {
            let encryption_rq = match self.fuzzy_hash {
                FHVector::NilsimsaVector(_) => postcard::from_bytes::<
                    EncryptionRequest<VECTOR_SIZE, GroupElement>,
                >(&self.read_frame().await?)?,
            };

            debug!("Received a public key from the server");

            // Update similarity score if any
            if let Some(scores) = encryption_rq.similarity_scores {
                for (i, s) in scores.into_iter().enumerate() {
                    let log_s = match log_table.get(&(s - randoms[i] * g).compress()) {
                        Some(i) => *i,
                        None => u16::MIN,
                    };
                    let similarity_score: i16 =
                        128 - (((NILSIMSA_VECTOR_SIZE_BITS >> 1) as i16) - (log_s as i16));
                    if similarity_score > score {
                        score = similarity_score;
                    }
                }
            }

            // Retrieve the pk if any
            let pk = match encryption_rq.pk {
                Some(pk) => pk,
                // None means no more vectors to compare to on the server side
                None => return Ok(score),
            };

            info!("Encrypting vector...");
            g = pk.get_gen();

            let encrypted_vector: CipherText<VECTOR_SIZE>;
            (encrypted_vector, randoms) = pk.encrypt_random_pad(&mut rng, vector);

            info!("Sending ct to server");
            let encryption_response = EncryptionResponse::EncryptedVector(encrypted_vector);
            self.write_frame(postcard::to_stdvec(&encryption_response)?)
                .await?;

            info!("Generating log table...");
            log_table = fe::generate_table(g, 256);
        }

        Ok(i16::MIN)
    }
}
