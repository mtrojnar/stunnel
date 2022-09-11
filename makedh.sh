#!/bin/sh

cat <<EOT
/* dhparam.c: initial DH parameters for stunnel */
#include "prototypes.h"
#ifndef OPENSSL_NO_DH
#define DN_new DH_new
DH *get_dh2048(void) {
    static unsigned char dhp_2048[] = {
EOT

openssl dhparam 2048 |
    openssl asn1parse |
    sed -n '2p' |
    sed 's/.*://' |
    xxd -r -p |
    xxd -i |
    sed 's/^/      /'

cat <<EOT
    };
    static unsigned char dhg_2048[] = {
        0x02
    };
    DH *dh = DH_new();
    BIGNUM *p, *g;

    if (dh == NULL)
        return NULL;
    p = BN_bin2bn(dhp_2048, sizeof(dhp_2048), NULL);
    g = BN_bin2bn(dhg_2048, sizeof(dhg_2048), NULL);
    if (p == NULL || g == NULL
            || !DH_set0_pqg(dh, p, NULL, g)) {
        DH_free(dh);
        BN_free(p);
        BN_free(g);
        return NULL;
    }
    return dh;
}
#endif /* OPENSSL_NO_DH */
/* built for $1 */
EOT
