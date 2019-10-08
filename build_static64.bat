cargo clean

set OPENSSL_LIB_DIR="C:\Program Files\OpenSSL-Win64@1.1/lib/"
set OPENSSL_INCLUDE_DIR="C:\Program Files\OpenSSL-Win64@1.1/include"
set OPENSSL_STATIC="yes"
set LIBCLANG_PATH="C:\Program Files\LLVM\bin\libclang.dll"

cargo build --release
