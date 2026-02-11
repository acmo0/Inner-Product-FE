use anyhow::{Error, Result, anyhow};
use fe::traits::FEInstance;
use fe::{Instance, PublicKey, SecretKey};
use log::{error, info};
use tokio::io::AsyncReadExt;
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
};
use tokio_stream::StreamExt;
use futures::sink::SinkExt;
use fuzzy_hashes::{FHVector, NILSIMSA_VECTOR_SIZE};
use messages::{GenerateInstanceRequest, GenerateInstanceResponse};
use std::mem;

use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};

#[derive(Debug)]
pub struct Server {
    listener: TcpListener,
}

const SERVER_MAX_LEN: usize = NILSIMSA_VECTOR_SIZE;

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

            tokio::spawn(async move {
                let mut client_handler = ClientHandler{
                    stream: s
                };
                match client_handler.handle_client().await {
                    Ok(_) => {info!("Closing connection with client")}
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

struct ClientHandler {
    stream: TcpStream
}

impl ClientHandler {
    async fn read_frame(&mut self) -> Result<Vec<u8>> {
        let mut reader = FramedRead::new(&mut self.stream, LengthDelimitedCodec::new());
        let frame = reader.next().await.unwrap().unwrap().to_vec();
        Ok(frame)
    }

    async fn write_frame(&mut self, bytes: Vec<u8>) -> Result<()> {
        let mut writer = FramedWrite::new(&mut self.stream, LengthDelimitedCodec::new());
        writer.send(bytes.into()).await?;
        Ok(())
    }

    async fn handle_client(&mut self) -> Result<()> {
        info!("Handling client");
        
        let frame = self.read_frame().await?;

        let mut incomming_vectors: GenerateInstanceRequest<u8> = match postcard::from_bytes(&frame) {
            Ok(v) => v,
            Err(error) => {
                error!("Unable to understand client payload");
                return Err(error.into());
            }
        };

        info!("Received {} vectors from client", incomming_vectors.len());
        /*let incomming_vectors: GenerateInstanceRequest<u8> =
            postcard::from_bytes(&buf).expect("Failed to understand client request");
    */
        match check_incomming_vectors(&incomming_vectors) {
            Ok(_) => {}
            Err(error) => return Err(error),
        }

        match incomming_vectors[0] {
            FHVector::<_>::NilsimsaVector(_) => {
                let response = generate_parameters_nilsimsa(incomming_vectors);
                self.write_frame(postcard::to_stdvec(&response)?).await?;
                info!("Sended public key/secret keys to client")
            }
        }
        Ok(())
    }
}

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

fn generate_parameters_nilsimsa(
    requested_vectors: GenerateInstanceRequest<u8>,
) -> GenerateInstanceResponse<NILSIMSA_VECTOR_SIZE> {
    let instance = Instance::setup();
    let pk: PublicKey<NILSIMSA_VECTOR_SIZE> = instance.public_key::<u8>();
    let sk_vec: Vec<SecretKey<NILSIMSA_VECTOR_SIZE>> = requested_vectors
        .iter()
        .map(|vector| {
            match vector {
                FHVector::<_>::NilsimsaVector(v) => return instance.secret_key(*v),
            };
        })
        .collect();

    GenerateInstanceResponse(pk, sk_vec)
}