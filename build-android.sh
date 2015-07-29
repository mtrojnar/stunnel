#!/bin/sh
set -ev
VERSION=5.00
DST=stunnel-$VERSION-android

# to build Zlib:
# export CHOST=arm-linux-androideabi
# ./configure --static --prefix=/opt/androideabi/sysroot
# make
# make install

# to build OpenSSL:
# export CC=arm-linux-androideabi-gcc
# ./Configure linux-armv4 threads no-shared zlib no-dso --openssldir=/opt/androideabi/sysroot
# make
# make install

mkdir -p bin/android
cd bin/android
../../configure --build=i686-pc-linux-gnu --host=arm-linux-androideabi --prefix=/data/local --with-ssl=/opt/androideabi/sysroot
make clean
make
cd ../..
mkdir $DST
cp bin/android/src/stunnel /opt/androideabi/sysroot/bin/openssl $DST
# arm-linux-androideabi-strip $DST/stunnel $DST/openssl
arm-linux-androideabi-strip $DST/openssl
zip -r $DST.zip $DST
rm -rf $DST
sha256sum $DST.zip
mv $DST.zip ../dist/
