#!/bin/sh
set -ev
VERSION=5.59
DST=stunnel-$VERSION-android

# download Android NDK r21e: https://developer.android.com/ndk/downloads
# build arm-linux-androideabi toolchain
# ./build/tools/make-standalone-toolchain.sh --toolchain=arm-linux-androideabi
# cd /toochains/dir 
# tar xfv /tmp/ndk-root/arm-linux-androideabi.tar.bz2
# export PATH=/toolchains/dir/arm-linux-androideabi/bin:${PATH}
# export ANDROID_NDK_HOME=/toolchains/dir/arm-linux-androideabi

# to build Zlib:
# CHOST=arm-linux-androideabi ./configure --static --prefix=/opt/androideabi/sysroot
# make install

# to build OpenSSL:
# ./Configure threads no-shared zlib --cross-compile-prefix=arm-linux-androideabi- --openssldir=/opt/androideabi/sysroot anrdroid-arm
# make install

test -f Makefile && make distclean
mkdir -p bin/android
cd bin/android
../../configure --with-sysroot --host=arm-linux-androideabi --prefix=/data/local
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
