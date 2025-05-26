# How to run mini OCSP servers:
# openssl ocsp -index tests/certs/index.txt -port 19253 -rsigner tests/certs/inter_ocsp.pem -CA tests/certs/CACert.pem
# openssl ocsp -index tests/certs/index.txt -port 19254 -rsigner tests/certs/leaf_ocsp.pem -CA tests/certs/intermediateCA.pem

#!/bin/sh

result_path=$(pwd)
cd $(dirname "$0")
script_path=$(pwd)
cd "${result_path}"
export LC_ALL=C

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


################################################################################
# OpenSSL settings
################################################################################
TEMP_LD_LIBRARY_PATH=$LD_LIBRARY_PATH
if [ -z "$OPENSSL_PATH" ]; then
    export LD_LIBRARY_PATH=""
    OPENSSL="openssl"
else
    LIB_PATH="$OPENSSL_PATH/lib64"
    [ -d "$LIB_PATH" ] || LIB_PATH="$OPENSSL_PATH/lib"
    [ -d "$LIB_PATH" ] || { echo "Error: No lib or lib64 found in $OPENSSL_PATH."; exit 1; }

    export LD_LIBRARY_PATH="$LIB_PATH:$LD_LIBRARY_PATH"
    OPENSSL="$OPENSSL_PATH/bin/openssl"
fi

date > "maketestcert.log"
mkdir "tmp/" 2>> "maketestcert.log" 1>&2
mkdir "CA/" 2>> "maketestcert.log" 1>&2
touch "CA/index.txt"
echo -n "unique_subject = no" > "CA/index.txt.attr"
"$OPENSSL" rand -hex 16 > "CA/serial"
echo 1001 > "CA/crlnumber"
"$OPENSSL" version 2>> "maketestcert.log" 1>&2


################################################################################
# Create new psk secrets
################################################################################
gen_psk 1
cat tmp/psk1.txt > tmp/secrets.txt 2>> "maketestcert.log"
gen_psk 2
cat tmp/psk2.txt >> tmp/secrets.txt 2>> "maketestcert.log"
gen_psk 2


################################################################################
# self-signed certificate
################################################################################
CONF="${script_path}/openssl_root.cnf"
"$OPENSSL" req -config $CONF -new -x509 -keyout tmp/stunnel.pem -out tmp/stunnel.pem \
    -subj "/C=PL/ST=Mazovia Province/L=Warsaw/O=Stunnel Developers/OU=Provisional CA/CN=localhost/emailAddress=stunnel@example.com" \
    2>> "maketestcert.log" 1>&2


################################################################################
# Root CA certificate
################################################################################
"$OPENSSL" genrsa -out CA/CA.key 2048 \
    2>> "maketestcert.log" 1>&2
"$OPENSSL" req -config $CONF -new -x509 -days 3600 -key CA/CA.key -out tmp/CACert.pem \
    -subj "/C=PL/O=Stunnel Developers/OU=Root CA/CN=CA/emailAddress=CA@example.com" \
    2>> "maketestcert.log" 1>&2


################################################################################
# Intermediate CA certificate
################################################################################
CONF="${script_path}/openssl_intermediate.cnf"
"$OPENSSL" genrsa -out CA/intermediateCA.key 2048 \
    2>> "maketestcert.log" 1>&2
"$OPENSSL" req -config "$CONF" -new -key CA/intermediateCA.key -out CA/intermediateCA.csr \
    -subj "/C=PL/O=Stunnel Developers/OU=Intermediate CA/CN=Intermediate CA" \
    2>> "maketestcert.log" 1>&2

CONF="${script_path}/openssl_root.cnf"
"$OPENSSL" ca -config "$CONF" -batch -in CA/intermediateCA.csr -out CA/intermediateCA.cer \
    2>> "maketestcert.log" 1>&2
"$OPENSSL" x509 -in CA/intermediateCA.cer -out tmp/intermediateCA.pem \
    2>> "maketestcert.log" 1>&2


################################################################################
# Revoked certificate chain
################################################################################
CONF="${script_path}/openssl_intermediate.cnf"
"$OPENSSL" genrsa -out CA/revoked.key 2048 \
    2>> "maketestcert.log" 1>&2
"$OPENSSL" req -config $CONF -new -key CA/revoked.key -out CA/revoked.csr \
    -subj "/C=PL/O=Stunnel Developers/OU=revoked/CN=revoked/emailAddress=revoked@example.com" \
    2>> "maketestcert.log" 1>&2
"$OPENSSL" ca -config $CONF -batch -in CA/revoked.csr -out CA/revoked.cer \
    2>> "maketestcert.log" 1>&2
"$OPENSSL" x509 -in CA/revoked.cer -out tmp/revoked_cert.pem \
    2>> "maketestcert.log" 1>&2
cat CA/revoked.key >> tmp/revoked_cert.pem 2>> "maketestcert.log"
cat tmp/intermediateCA.pem >> tmp/revoked_cert.pem 2>> "maketestcert.log"

# revoke above certificate and generate CRL file
"$OPENSSL" ca -config $CONF -revoke CA/revoked.cer \
    2>> "maketestcert.log" 1>&2
"$OPENSSL" ca -config $CONF -gencrl -crldays 1461 -out tmp/CACertCRL.pem \
    2>> "maketestcert.log" 1>&2


################################################################################
# Server certificate chain
################################################################################
"$OPENSSL" genrsa -out CA/server.key 2048 \
    2>> "maketestcert.log" 1>&2
"$OPENSSL" req -config $CONF -new -key CA/server.key -out CA/server.csr \
    -subj "/C=PL/O=Stunnel Developers/OU=server/CN=server/emailAddress=server@example.com" \
    2>> "maketestcert.log" 1>&2
"$OPENSSL" ca -config $CONF -batch -in CA/server.csr -out CA/server.cer \
    2>> "maketestcert.log" 1>&2
"$OPENSSL" x509 -in CA/server.cer -out tmp/server_cert.pem \
    2>> "maketestcert.log" 1>&2
cat tmp/server_cert.pem >> tmp/PeerCerts.pem 2>> "maketestcert.log"
cat CA/server.key >> tmp/server_cert.pem 2>> "maketestcert.log"
cat tmp/intermediateCA.pem >> tmp/server_cert.pem 2>> "maketestcert.log"

# create a PKCS#12 file with a server certificate chain using AES-256-CBC
# and PBMAC1 (RFC 9579, supported in OpenSSL 3.4.0+);
# PBMAC1 is FIPS-compliant, whereas SHA1 + 3DES is not
"$OPENSSL" pkcs12 -export --certpbe AES-256-CBC -keypbe AES-256-CBC \
    -macalg SHA256 -pbmac1_pbkdf2 \
    -in tmp/server_cert.pem -out tmp/server_cert.p12 -passout pass: \
     2>> "maketestcert.log" 1>&2
# if the operation fails, retry with SHA1 + 3DES for compatibility
if ! test -s tmp/server_cert.p12; then
    "$OPENSSL" pkcs12 -export -certpbe pbeWithSHA1And3-KeyTripleDES-CBC \
        -in tmp/server_cert.pem -out tmp/server_cert.p12 -passout pass: \
        2>> "maketestcert.log" 1>&2
fi
"$OPENSSL" pkcs12 -in tmp/server_cert.p12 -noout -info -passin pass: \
    2>> "maketestcert.log" 1>&2


################################################################################
# Client certificate chain
################################################################################
"$OPENSSL" genrsa -out CA/client.key 2048 \
    2>> "maketestcert.log" 1>&2
"$OPENSSL" req -config $CONF -new -key CA/client.key -out CA/client.csr \
    -subj "/C=PL/O=Stunnel Developers/OU=client/CN=client/emailAddress=client@example.com" \
    2>> "maketestcert.log" 1>&2
"$OPENSSL" ca -config $CONF -batch -in CA/client.csr -out CA/client.cer \
    2>> "maketestcert.log" 1>&2
"$OPENSSL" x509 -in CA/client.cer -out tmp/client_cert.pem \
    2>> "maketestcert.log" 1>&2
cat tmp/client_cert.pem > tmp/PeerCerts.pem 2>> "maketestcert.log"
cat CA/client.key >> tmp/client_cert.pem 2>> "maketestcert.log"
cat tmp/intermediateCA.pem >> tmp/client_cert.pem 2>> "maketestcert.log"


################################################################################
# OCSP certificates with XKU_OCSP_SIGN
# openssl ocsp -port 19253 -index index.txt -rsigner inter_ocsp.pem -CA CACert.pem -nmin 1
# openssl ocsp -port 19254 -index index.txt -rsigner leaf_ocsp.pem -CA intermediateCA.pem -nmin 1
################################################################################
CONF="${script_path}/openssl_root.cnf"
"$OPENSSL" genrsa -out CA/inter_ocsp.key \
    2>> "maketestcert.log" 1>&2
"$OPENSSL" req -config $CONF -new -key CA/inter_ocsp.key -out CA/inter_ocsp.csr \
    -extensions v3_OCSP \
    -subj "/C=PL/O=Stunnel Developers/OU=Intermediate OCSP/CN=inter_ocsp/emailAddress=inter_ocsp@example.com" \
    2>> "maketestcert.log" 1>&2
"$OPENSSL" ca -config $CONF -batch -in CA/inter_ocsp.csr -out CA/inter_ocsp.cer \
    -extensions v3_OCSP \
    2>> "maketestcert.log" 1>&2
"$OPENSSL" x509 -in CA/inter_ocsp.cer -out tmp/inter_ocsp.pem \
    2>> "maketestcert.log" 1>&2
cat CA/inter_ocsp.key >> tmp/inter_ocsp.pem 2>> "maketestcert.log"

CONF="${script_path}/openssl_intermediate.cnf"
"$OPENSSL" genrsa -out CA/leaf_ocsp.key \
    2>> "maketestcert.log" 1>&2
"$OPENSSL" req -config $CONF -new -key CA/leaf_ocsp.key -out CA/leaf_ocsp.csr \
    -extensions v3_OCSP \
    -subj "/C=PL/O=Stunnel Developers/OU=Leaf OCSP/CN=leaf_ocsp/emailAddress=leaf_ocsp@example.com" \
    2>> "maketestcert.log" 1>&2
"$OPENSSL" ca -config $CONF -batch -in CA/leaf_ocsp.csr -out CA/leaf_ocsp.cer \
    -extensions v3_OCSP \
    2>> "maketestcert.log" 1>&2
"$OPENSSL" x509 -in CA/leaf_ocsp.cer -out tmp/leaf_ocsp.pem \
    2>> "maketestcert.log" 1>&2
cat CA/leaf_ocsp.key >> tmp/leaf_ocsp.pem 2>> "maketestcert.log"


################################################################################
# OCSP certificates without XKU_OCSP_SIGN
# Don't include any certificates in the OCSP response
# openssl ocsp -port 19253 -index index.txt -rsigner CA_ocsp.pem -CA CACert.pem -nmin 1 -resp_no_certs
# openssl ocsp -port 19254 -index index.txt -rsigner interCA_ocsp.pem -CA intermediateCA.pem -nmin 1 -resp_no_certs
################################################################################
cat tmp/CACert.pem >> tmp/CA_ocsp.pem  2>> "makecerts.log"
cat CA/CA.key >> tmp/CA_ocsp.pem  2>> "makecerts.log"
cat tmp/intermediateCA.pem  >> tmp/interCA_ocsp.pem  2>> "makecerts.log"
cat CA/intermediateCA.key >> tmp/interCA_ocsp.pem  2>> "makecerts.log"


################################################################################
# Copy new files
################################################################################
if test -s tmp/CACert.pem -a -s tmp/CACertCRL.pem \
    -a -s tmp/intermediateCA.pem \
    -a -s tmp/stunnel.pem -a -s tmp/revoked_cert.pem \
    -a -s tmp/client_cert.pem -a -s tmp/server_cert.pem \
    -a -s tmp/server_cert.p12 \
    -a -s tmp/inter_ocsp.pem -a -s tmp/leaf_ocsp.pem \
    -a -s tmp/CA_ocsp.pem -a -s tmp/interCA_ocsp.pem \
    -a -s tmp/PeerCerts.pem -a -s tmp/secrets.txt \
    -a -s tmp/psk1.txt -a -s tmp/psk2.txt \
    -a -s CA/index.txt
  then
    cp tmp/* ../certs
    cp CA/index.txt ../certs
    printf "%s\n" "keys & certificates successfully generated"
    printf "%s\n" "./maketestcert.sh finished"
    rm -f "maketestcert.log"
  else
    printf "%s\n" "./maketestcert.sh failed"
    printf "%s\n" "error logs ${result_path}/maketestcert.log"
  fi


################################################################################
# Remove the working directory
################################################################################
rm -rf "CA/"
rm -rf "tmp/"

# restore settings
LD_LIBRARY_PATH=$TEMP_LD_LIBRARY_PATH
