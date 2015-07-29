#!/bin/bash

echo "Content-type: application/x-x509-ca-cert"
echo
cat /var/lib/httpds/cgi-bin/cacert.pem
