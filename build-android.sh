#!/bin/sh
set -ev
VERSION=4.50
DST=stunnel-$VERSION-android
./configure --build=i686-pc-linux-gnu --host=arm-linux-androideabi \
    --with-ssl=/opt/androideabi/sysroot --prefix=/data/local
make clean
make
mkdir $DST
cp src/stunnel /opt/androideabi/sysroot/bin/openssl $DST
arm-linux-androideabi-strip $DST/stunnel $DST/openssl
zip -r $DST.zip $DST
rm -rf $DST
sha256sum $DST.zip
mv $DST.zip ../dist/
