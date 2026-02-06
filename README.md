# Inner Product Functionnal Encryption

This repository aims to provide multiple implementation of the first scheme depicted in the paper [Fully Secure Functional Encryption for Inner Products, from Standard Assumptions](https://eprint.iacr.org/2015/608).

Since the scheme is defined for any prime-order cyclic group, a version over the Diffie-Hellman group n°15 from [RFC 3526](https://datatracker.ietf.org/doc/html/rfc3526). This has been implemented using both [Bigint crate](https://crates.io/crates/num-bigint) (in [`num-znz-fe`](./num-znz-fe)) and [Malachite crate](https://crates.io/crates/malachite) (in [`malachite-znz-fe`](./malachite-znz-fe)).
Another version based on the Ristretto255 elliptic curve is also implemented in [`ristretto-znz-fe`](./ristretto-znz-fe), which **is way faster**.

## Benchmarking

| Implementation | Base crate       | Encryption time | Decryption time |
|----------------|------------------|-----------------|-----------------|
| DH group n°15  | Bigint(1)          | 8.82 s          | 0.271 s         |
| DH group n°15  | Malachite        | 7.06 s          | 0.043 s         |
| Ristretto255(2)   | Curve25519-dalek | 0.03 s          | 0.005 s         |

> Notes :  (1) Because it was less efficient than malachite I droped it to reduce implementation time  (2)elliptic curve operations are done in constant-time to avoid some side-channel attack

