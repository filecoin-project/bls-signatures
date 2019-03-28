#!/usr/bin/env bash

TAR_PATH=/tmp/release
TAR_FILE=/tmp/release.tar.gz

mkdir -p $TAR_PATH
mkdir -p $TAR_PATH/bin
mkdir -p $TAR_PATH/include
mkdir -p $TAR_PATH/lib/pkgconfig
mkdir -p $TAR_PATH/misc

cp target/release/libbls_signatures.h $TAR_PATH/include/
cp target/release/libbls_signatures_ffi.a $TAR_PATH/lib/libbls_signatures.a
cp target/release/libbls_signatures.pc $TAR_PATH/lib/pkgconfig

pushd $TAR_PATH

tar -czf $TAR_FILE ./*

popd
