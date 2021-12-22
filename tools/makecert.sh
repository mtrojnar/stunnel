#!/bin/sh

if test -n "$1"; then
    CONF="$1/openssl.cnf"
else
    CONF="openssl.cnf"
fi

if test -n "$2"; then
    OPENSSL="$2/bin/openssl"
    export LD_LIBRARY_PATH="$2/lib:$2/lib64"
else
    OPENSSL=openssl
fi

$OPENSSL version

if test -n "$3"; then
    RAND="$3"
else
    RAND="/dev/urandom"
fi

dd if="$RAND" of=stunnel.rnd bs=256 count=1
$OPENSSL req -new -x509 -days 1461 -rand stunnel.rnd -config $CONF \
    -out stunnel.pem -keyout stunnel.pem
rm -f stunnel.rnd

echo
echo "Certificate details:"
$OPENSSL x509 -subject -dates -fingerprint -noout -in stunnel.pem
echo
