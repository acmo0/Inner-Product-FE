use futures::SinkExt;
use futures::StreamExt;
use std::array;
use std::time::Duration;

use anyhow::Result;
use log::{debug, info};
use rand::{
    SeedableRng,
    rngs::{StdRng, SysRng},
};
use tokio::net::TcpStream;
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};

use cpu_time::ProcessTime;
use fe::curve25519_dalek::traits::Identity;
use fe::traits::FEPubKey;
use fe::{
    CipherText, CompressedGroupElement, GroupElement, LogTable, PublicKey, RANDOM_PADDING_LEN,
    Scalar,
};
use messages::{
    EncryptionRequest, EncryptionResponse, FHVector, HashComparisonRequest,
    NILSIMSA_VECTOR_SIZE_BITS,
};

/// Structure for having a stateful client.
pub struct Client {
    stream: TcpStream,
    fuzzy_hash: FHVector<u8>,
}

/// A vector size is defined by the length of a nilsimsa hash
/// plus the random padding appended at the end.
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
        let vector: [u8; NILSIMSA_VECTOR_SIZE_BITS] = match self.fuzzy_hash {
            FHVector::NilsimsaVector(_) => self
                .fuzzy_hash
                .to_bits::<NILSIMSA_VECTOR_SIZE_BITS>()?
                .try_into()
                .unwrap(),
        };

        // Init the RNG to perform encryption
        let mut rng = StdRng::try_from_rng(&mut SysRng).unwrap();

        // Init the lookup table for discrete log
        let mut log_table = LogTable::new();
        let mut randoms: [Scalar; RANDOM_PADDING_LEN] = array::from_fn(|_i| Scalar::ZERO);
        let mut g: GroupElement = GroupElement::identity();

        info!("Sending request to server");

        // Measure CPU time
        let start = ProcessTime::now();

        self.write_frame(postcard::to_stdvec(&message)?).await?;

        loop {
            // Retrieve the response from the server
            let encryption_rq = match self.fuzzy_hash {
                FHVector::NilsimsaVector(_) => postcard::from_bytes::<
                    EncryptionRequest<VECTOR_SIZE, CompressedGroupElement>,
                >(&self.read_frame().await?)?,
            };

            debug!("Parsed a response from the server");

            // Update similarity score if any
            if let Some(scores) = encryption_rq.similarity_scores {
                // For every score given by the server, undo the one time pad
                // and retrieve the log value from the lookup table
                for (i, s) in scores
                    .into_iter()
                    .map(|p| {
                        p.decompress()
                            .expect("Unable to understad the server response")
                    })
                    .enumerate()
                {
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
            let pk: PublicKey<VECTOR_SIZE> = match &encryption_rq.pk {
                Some(pk) => pk.try_into().unwrap(),
                // None means no more vectors to compare to on the server side
                None => {
                    let cpu_time: Duration = start.elapsed();
                    info!("CPU Time : {:?}", cpu_time);
                    return Ok(score);
                }
            };

            info!("Encrypting vector...");
            g = pk.get_gen();

            let encrypted_vector: CipherText<VECTOR_SIZE>;
            (encrypted_vector, randoms) = pk.encrypt_random_pad(&mut rng, vector);

            info!("Sending ct to server");
            let encryption_response = EncryptionResponse::EncryptedVector(encrypted_vector);
            self.write_frame(postcard::to_stdvec(&encryption_response)?)
                .await?;

            // Generating the next log table while the
            // server is computing partial decryption
            info!("Generating log table...");
            log_table = fe::generate_table(g, 256);
        }
    }
}
