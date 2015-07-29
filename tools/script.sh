#!/bin/bash

echo "client script started"
/usr/local/sbin/stunnel -fd 10 \
    11<&0 <<EOT 10<&0 0<&11 11<&-
client=yes
connect=www.mirt.net:443
EOT
echo "client script finished"

