cargo build --release --all
cp target/release/libbls_signatures.h /usr/local/include/
cp target/release/libbls_signatures.a /usr/local/lib/
cp target/release/libbls_signatures.pc /usr/local/lib/pkgconfig/
