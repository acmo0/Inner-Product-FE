use anyhow::{Error, Result, anyhow};
use core::array;
use fe::traits::FEInstance;
use fe::{Instance, PublicKey, SecretKey};
use futures::sink::SinkExt;
use fuzzy_hashes::{FHVector, NILSIMSA_VECTOR_SIZE_BITS};
use log::{error, info};
use messages::{GenerateInstanceRequest, GenerateInstanceResponse};
use std::mem;
use tokio::net::{TcpListener, TcpStream};
use tokio_stream::StreamExt;
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};

#[derive(Debug)]
pub struct Server {
    listener: TcpListener,
}

// Max number of vectors that a single instance can encrypt
// if the request contains more (or at least as much) than this
// the request is simply ignored.
const SERVER_MAX_LEN: usize = NILSIMSA_VECTOR_SIZE_BITS;

impl Server {
    pub fn new(listener: TcpListener) -> Self {
        Self { listener }
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

            // Create a dedicated thread for any incomming client
            tokio::spawn(async move {
                // Init a client handler
                let mut client_handler = ClientHandler { stream: s };
                // Start handling it
                match client_handler.handle_client().await {
                    Ok(_) => {
                        info!("Closing connection with client")
                    }
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

// Struct to handle a client
struct ClientHandler {
    stream: TcpStream,
}

impl ClientHandler {
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

    /// Main function, this contains the handling flow of a request
    async fn handle_client(&mut self) -> Result<()> {
        info!("Handling new client");

        // Read the incomming request and deserialize it to retrieve the GenerateInstanceRequest
        let frame = self.read_frame().await?;
        let incomming_vectors: GenerateInstanceRequest<u8> = match postcard::from_bytes(&frame) {
            Ok(v) => v,
            Err(error) => {
                error!("Unable to understand client payload");
                return Err(error.into());
            }
        };
        info!("Received {} vectors from client", incomming_vectors.len());

        // Ensure that incomming vectors are homogeneous in their length, type
        // and that the number of request vectors are less that the maximum allowed
        // number of vectors per instance.
        match check_incomming_vectors(&incomming_vectors) {
            Ok(_) => {}
            Err(error) => {
                error!("Error : {}", error);
                return Err(error);
            }
        }

        // Once the vectors are "accepted", then generate an instance and derive a public key
        // and compute all the secrets keys for the requested vectors
        info!("Generate parameters");
        match incomming_vectors[0] {
            FHVector::<_>::NilsimsaVector(_) => {
                let response = generate_parameters_nilsimsa(incomming_vectors);
                info!("Encoding response");
                self.write_frame(postcard::to_stdvec(&response)?).await?;
                info!("Sended public key/secret keys to client")
            }
        }
        Ok(())
    }
}

/// Helper function, this function ensures that the vectors are all the same length, the same type
/// and that it as at least one vector (and no more than the maximum number of vectors allowed )
fn check_incomming_vectors(incomming_vectors: &GenerateInstanceRequest<u8>) -> Result<()> {
    match incomming_vectors.len() {
        0 => return Err(anyhow!("Received empty message, abort")),
        SERVER_MAX_LEN => return Err(anyhow!("Received too much vectors, abort")),
        _ => {}
    }

    let all_same_kind = incomming_vectors
        .iter()
        .all(|vector| mem::discriminant(vector) == mem::discriminant(&incomming_vectors[0]));

    if !all_same_kind {
        return Err(anyhow!("Received heterogeneous vectors, abort"));
    }

    Ok(())
}

/// Generate the instance, the public key and all the secret keys given 
/// a "checked" request from a compute server.
fn generate_parameters_nilsimsa(
    requested_vectors: GenerateInstanceRequest<u8>,
) -> GenerateInstanceResponse<NILSIMSA_VECTOR_SIZE_BITS> {
    let instance = Instance::setup();
    let pk: PublicKey<NILSIMSA_VECTOR_SIZE_BITS> = instance.public_key::<u8>();
    let sk_vec: Vec<SecretKey<NILSIMSA_VECTOR_SIZE_BITS>> = requested_vectors
        .iter()
        .map(|vector| {
            match vector {
                FHVector::<_>::NilsimsaVector(v_bytes) => {
                    let v: [u8; NILSIMSA_VECTOR_SIZE_BITS] =
                        array::from_fn(|i| 1 & (v_bytes[i / 8] >> (7 - (i % 8))));
                    return instance.secret_key(v);
                }
            };
        })
        .collect();

    GenerateInstanceResponse::from((pk, sk_vec))
}
