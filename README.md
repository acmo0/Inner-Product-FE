# Fuzzy Hashes Comparison over the encrypted domain

## Structure
### Libs
- [benches](./benches) : benchmark for the functionnal encryption implementation
- [comparator](./comparator) : crate to implement comparison function for a fuzzy hash over the encrypted domain
- [fe](./fe) : functionnal encryption for vectors (over EC and FF)
- [fuzzy_hashes](./fuzzy_hashes) : implementation and constants related to fuzzy hashes themself
- [messages](./messages) : messages exchanged between the actors
### Bins
- [compute-server](./compute-server) : code of the compute server
- [instance-server](./instance-server) : code of the instance server

## Doc
```
git clone https://github.com/acmo0/Inner-Product-FE.git
cd Inner-Product-FE
cargo doc --open --no-deps
```

## Test
> This will take a while to test (few minutes using elliptic-curve feature of the crate fe, few tens of munites for the finite-field feature of the crate fe)
```
# Test ec implementation
cargo test --release
# Test finite field implementation
cd fe
cargo test --no-default-features -F finite-field --release
```

## Build
```sh
RUSTFALGS="-C target-cpu=native" cargo build --release
```

## Run
> Note : please follow the build step before

Note that only the request to the authority from the compute server to generate a fresh instance with associated public key and secret keys for requested vectors is implemented.

```sh
# First populate a db made of random nilsimsa fuzzy hashes
# By default : 10_000 fuzzy hashes
python3 populate.py

# Launch the authority server
RUST_LOG=info ./target/release/instance-server 127.0.0.1:1234 

# In another tty launch the compute server
RUST_LOG=info ./target/release/compute-server 127.0.0.1:1337 127.0.0.1:1234 test_db.db 

# In another tty, init a connection with the compute server
# Note : this is only to trigger the exchanges between the compute and instance servers
nc 127.0.0.1 1337
# Then you should see in the logs the instance-server and
# compute server exchange hashes and secret keys
```

## Benchmarking

| Implementation | Base crate       | Encryption time | Decryption time |
|----------------|------------------|-----------------|-----------------|
| DH group n°15  | Bigint(1)          | 8.82 s          | 0.271 s         |
| DH group n°15  | Malachite        | 7.06 s          | 0.043 s         |
| Ristretto255(2)   | Curve25519-dalek | 0.03 s          | 0.005 s         |

> Notes :  (1) Because it was less efficient than malachite I droped it to reduce implementation time  (2)elliptic curve operations are done in constant-time to avoid some side-channel attack

