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

## Benchmarking

| Implementation | Base crate       | Encryption time | Decryption time |
|----------------|------------------|-----------------|-----------------|
| DH group n°15  | Bigint(1)          | 8.82 s          | 0.271 s         |
| DH group n°15  | Malachite        | 7.06 s          | 0.043 s         |
| Ristretto255(2)   | Curve25519-dalek | 0.03 s          | 0.005 s         |

> Notes :  (1) Because it was less efficient than malachite I droped it to reduce implementation time  (2)elliptic curve operations are done in constant-time to avoid some side-channel attack

