#!/bin/bash

set -euo pipefail
IFS=$'\n\t'

function write_len {
	sed -i "s/= .*;/= ${1};/g" fe/src/consts.rs
}


for len in 16 32 64 128 256 512 1024 2048; do
	write_len $len
	cargo clean
	RUSTFLAGS="-C target-cpu=native" cargo +nightly build --release
	read -n 1 -p "Continue ?"
done
