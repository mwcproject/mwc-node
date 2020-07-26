#!/bin/sh

cargo clean
export OPENSSL_LIB_DIR=/usr/lib/x86_64-linux-gnu/
export OPENSSL_INCLUDE_DIR=/usr/include/openssl/
export OPENSSL_STATIC=yes

cargo build --release

