cargo clean

set OPENSSL_LIB_DIR="C:\Program Files (x86)\OpenSSL-Win32@1.1/lib/"
set OPENSSL_INCLUDE_DIR="C:\Program Files (x86)\OpenSSL-Win32@1.1/include"
set OPENSSL_STATIC="yes"
set LIBCLANG_PATH="C:\Program Files (x86)\LLVM\bin\libclang.dll"

cargo +stable-i686-pc-windows-msvc build --release
