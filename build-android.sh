#!/bin/sh
set -ev
VERSION=5.56
DST=stunnel-$VERSION-android

# install Android NDK on Arch Linux:
# aurman -S android-ndk-14b

# install Android NDK on Debian:
# sudo apt install google-android-ndk-installer

# build OpenSSL:
# export ANDROID_NDK=/usr/lib/android-ndk
# export PATH=$ANDROID_NDK/toolchains/arm-linux-androideabi-4.9/prebuilt/linux-x86_64/bin:$PATH
# ./Configure no-shared --prefix=/opt/openssl-android --openssldir=/data/local/tmp/ssl android-arm -D__ANDROID_API__=14
# make
# sudo PATH=$ANDROID_NDK/toolchains/arm-linux-androideabi-4.9/prebuilt/linux-x86_64/bin:$PATH make install

# Debian does not deploy /etc/profile.d/android-ndk.sh
test -d "$ANDROID_NDK" || ANDROID_NDK=/usr/lib/android-ndk

ANDROID_SYSROOT=$ANDROID_NDK/platforms/android-14/arch-arm
export CPPFLAGS="--sysroot=$ANDROID_SYSROOT"
export CFLAGS="--sysroot=$ANDROID_SYSROOT"
export PATH="$ANDROID_NDK/toolchains/arm-linux-androideabi-4.9/prebuilt/linux-x86_64/bin:$PATH"
test -f Makefile && make distclean
mkdir -p bin/android
cd bin/android
../../configure --with-ssl=/opt/openssl-android --prefix=/data/local/tmp \
    --build=x86_64-pc-linux-gnu --host=arm-linux-androideabi
make clean
make V=1
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
