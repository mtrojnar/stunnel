#!/bin/bash

REMOTE_HOST="www.mirt.net:443"
echo "client script connecting $REMOTE_HOST"
/usr/local/bin/stunnel -fd 10 \
    11<&0 <<EOT 10<&0 0<&11 11<&-
client=yes
connect=$REMOTE_HOST
EOT
echo "client script finished"

