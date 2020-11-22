cargo clean

set OPENSSL_LIB_DIR=C:\Program Files\OpenSSL-Win64\lib\
set OPENSSL_INCLUDE_DIR=C:\Program Files\OpenSSL-Win64\include
set OPENSSL_STATIC=yes
set LIBCLANG_PATH=C:\Program Files\LLVM\bin\libclang.dll

call .ci\win64_cargo.bat build --release
