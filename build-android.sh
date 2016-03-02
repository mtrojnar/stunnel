#!/bin/sh
set -ev
VERSION=5.31
DST=stunnel-$VERSION-android

# to build Zlib:
# CHOST=arm-linux-androideabi ./configure --static --prefix=/opt/androideabi/sysroot
# make install

# to build OpenSSL:
# ./Configure threads no-shared zlib no-dso --cross-compile-prefix=arm-linux-androideabi- --openssldir=/opt/androideabi/sysroot linux-armv4
# make install

test -f Makefile && make distclean
mkdir -p bin/android
cd bin/android
../../configure --with-sysroot --build=i686-pc-linux-gnu --host=arm-linux-androideabi --prefix=/data/local
make clean
make
cd ../..
mkdir $DST
cp bin/android/src/stunnel $DST
# arm-linux-androideabi-strip $DST/stunnel $DST/openssl
# cp /opt/androideabi/sysroot/bin/openssl $DST
# arm-linux-androideabi-strip $DST/openssl
zip -r $DST.zip $DST
rm -rf $DST
# sha256sum $DST.zip
# mv $DST.zip ../dist/
