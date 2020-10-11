#!/bin/sh

ddays=1461

result_path=$(pwd)
cd $(dirname "$0")
script_path=$(pwd)
cd "${result_path}"

mkdir "tmp/"

# create new psk secrets
gen_psk () {
  tr -c -d 'A-Za-z0-9' </dev/urandom 2>> "maketestcert.log" | head -c 50 > tmp/psk.txt
  if [ -s tmp/psk.txt ]
    then
      printf "test$1:" > tmp/psk$1.txt
      cat tmp/psk.txt >> tmp/psk$1.txt 2>> "maketestcert.log"
      printf "\n" >> tmp/psk$1.txt
    fi
  rm -f tmp/psk.txt
}

export LC_ALL=C
gen_psk 1
cat tmp/psk1.txt > tmp/secrets.txt 2>> "maketestcert.log"
gen_psk 2
cat tmp/psk2.txt >> tmp/secrets.txt 2>> "maketestcert.log"
gen_psk 2

# OpenSSL settings
TEMP_LD_LIBRARY_PATH=$LD_LIBRARY_PATH
LD_LIBRARY_PATH=""
OPENSSL=openssl
CONF="${script_path}/openssltest.cnf"

mkdir "demoCA/"
touch "demoCA/index.txt"
touch "demoCA/index.txt.attr"
echo 1000 > "demoCA/serial"

# generate a self-signed certificate
$OPENSSL req -config $CONF -new -x509 -days $ddays -keyout tmp/stunnel.pem -out tmp/stunnel.pem \
    -subj "/C=PL/ST=Mazovia Province/L=Warsaw/O=Stunnel Developers/OU=Provisional CA/CN=localhost/emailAddress=stunnel@example.com" \
    1>&2 2>> "maketestcert.log"

# generate root CA certificate
$OPENSSL genrsa -out demoCA/CA.key 1>&2 2>> "maketestcert.log"
$OPENSSL req -config $CONF -new -x509 -days $ddays -key demoCA/CA.key -out tmp/CACert.pem \
    -subj "/C=PL/O=Stunnel Developers/OU=Root CA/CN=CA/emailAddress=CA@example.com" \
    1>&2 2>> "maketestcert.log"

# generate a certificate to revoke
$OPENSSL genrsa -out demoCA/revoked.key 1>&2 2>> "maketestcert.log"
$OPENSSL req -config $CONF -new -key demoCA/revoked.key -out demoCA/revoked.csr \
    -subj "/C=PL/O=Stunnel Developers/OU=revoked/CN=revoked/emailAddress=revoked@example.com" \
    1>&2 2>> "maketestcert.log"

$OPENSSL ca -config $CONF -batch -days $ddays -in demoCA/revoked.csr -out demoCA/revoked.cer 1>&2 2>> "maketestcert.log"

$OPENSSL x509 -in demoCA/revoked.cer -out tmp/revoked_cert.pem 1>&2 2>> "maketestcert.log"
cat demoCA/revoked.key >> tmp/revoked_cert.pem 2>> "maketestcert.log"

# revoke above certificate and generate CRL file
$OPENSSL ca -config $CONF -revoke demoCA/1000.pem 1>&2 2>> "maketestcert.log"
$OPENSSL ca -config $CONF -gencrl -crldays $ddays -out tmp/CACertCRL.pem 1>&2 2>> "maketestcert.log"

# generate a client certificate
$OPENSSL genrsa -out demoCA/client.key 1>&2 2>> "maketestcert.log"
$OPENSSL req -config $CONF -new -key demoCA/client.key -out demoCA/client.csr \
    -subj "/C=PL/O=Stunnel Developers/OU=client/CN=client/emailAddress=client@example.com" \
    1>&2 2>> "maketestcert.log"

$OPENSSL ca -config $CONF -batch -days $ddays -in demoCA/client.csr -out demoCA/client.cer 1>&2 2>> "maketestcert.log"

$OPENSSL x509 -in demoCA/client.cer -out tmp/client_cert.pem 1>&2 2>> "maketestcert.log"
cat tmp/client_cert.pem > tmp/PeerCerts.pem 2>> "maketestcert.log"
cat demoCA/client.key >> tmp/client_cert.pem 2>> "maketestcert.log"

# generate a server certificate
$OPENSSL genrsa -out demoCA/server.key 1>&2 2>> "maketestcert.log"
$OPENSSL req -config $CONF -new -key demoCA/server.key -out demoCA/server.csr \
    -subj "/C=PL/O=Stunnel Developers/OU=server/CN=server/emailAddress=server@example.com" \
    1>&2 2>> "maketestcert.log"

$OPENSSL ca -config $CONF -batch -days $ddays -in demoCA/server.csr -out demoCA/server.cer 1>&2 2>> "maketestcert.log"

$OPENSSL x509 -in demoCA/server.cer -out tmp/server_cert.pem 1>&2 2>> "maketestcert.log"
cat tmp/server_cert.pem >> tmp/PeerCerts.pem 2>> "maketestcert.log"
cat demoCA/server.key >> tmp/server_cert.pem 2>> "maketestcert.log"

# create a PKCS#12 file with a server certificate
$OPENSSL pkcs12 -export -certpbe pbeWithSHA1And3-KeyTripleDES-CBC -in tmp/server_cert.pem -out tmp/server_cert.p12 -passout pass: 1>&2 2>> "maketestcert.log"

# copy new files
if [ -s tmp/stunnel.pem ] && [ -s tmp/CACert.pem ] && [ -s tmp/CACertCRL.pem ] && \
   [ -s tmp/revoked_cert.pem ] && [ -s tmp/client_cert.pem ] &&  [ -s tmp/server_cert.pem ] && \
   [ -s tmp/PeerCerts.pem ] && [ -s tmp/server_cert.p12 ] && \
   [ -s tmp/psk1.txt ] && [ -s tmp/psk2.txt ] && [ -s tmp/secrets.txt ]
  then
    cp tmp/* ./
    printf "%s\n" "keys & certificates successfully generated"
    printf "%s\n" "./maketestcert.sh finished"
    rm -f "maketestcert.log"
  else
    printf "%s\n" "./maketestcert.sh failed"
    printf "%s\n" "error logs ${result_path}/maketestcert.log"
  fi

# remove the working directory
rm -rf "demoCA/"
rm -rf "tmp/"

# restore settings
LD_LIBRARY_PATH=$TEMP_LD_LIBRARY_PATH
