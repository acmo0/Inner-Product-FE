# Fuzzy Hashes Comparison over the encrypted domain

## Structure
### Libs
- [benches](./benches) : benchmark for the functionnal encryption implementation
- [fe](./fe) : result-hiding functional encryption for vectors
- [messages](./messages) : messages exchanged between the actors
### Bins
- [client](./client) : code of the client
- [compute-server](./compute-server) : code of the compute server
- [instance-server](./instance-server) : code of the instance server

## Doc
```
git clone https://github.com/acmo0/Inner-Product-FE.git
cd Inner-Product-FE
cargo +nightly doc --open --no-deps
```

## Test
> This will take a while to test (few minutes)
```
# Test ec implementation
cargo test --release
# Test finite field implementation
cd fe
cargo test --no-default-features -F finite-field --release
```

## Build
```sh
RUSTFLAGS="-C target-cpu=native" cargo +nightly build --release
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
RUST_LOG=info ./target/release/client 127.0.0.1:1337 /path/to/a/file/to/hash
```
