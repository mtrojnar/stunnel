/* dhparam.c: initial DH parameters for stunnel */
#include "prototypes.h"
#ifndef OPENSSL_NO_DH
#define DN_new DH_new
DH *get_dh2048(void) {
    static unsigned char dhp_2048[] = {
        0xeb, 0x81, 0x74, 0xe2, 0x58, 0x37, 0x8a, 0x6d, 0x69, 0x9a, 0xcf, 0x9c,
        0xae, 0xd5, 0xc0, 0x80, 0xf9, 0x1b, 0xf8, 0x6e, 0xbf, 0x2f, 0x41, 0x0c,
        0xba, 0x30, 0x29, 0x60, 0x8f, 0x2c, 0xa8, 0x6a, 0x09, 0xb3, 0xd3, 0x65,
        0xba, 0x65, 0x78, 0xf8, 0x78, 0x30, 0x00, 0xa2, 0xc9, 0xff, 0x92, 0x37,
        0xbb, 0x31, 0x3a, 0x18, 0xd3, 0x8d, 0xf7, 0x54, 0xc0, 0x96, 0xfb, 0xd7,
        0x38, 0xb3, 0x5e, 0xe1, 0xdf, 0x2b, 0xca, 0xbf, 0xa5, 0xce, 0x5d, 0x64,
        0xb4, 0xaa, 0xf0, 0x5a, 0x95, 0xdb, 0xc6, 0x27, 0x28, 0x72, 0xcc, 0x3e,
        0xaf, 0x37, 0xb8, 0x43, 0x07, 0x5b, 0xf8, 0x11, 0x07, 0xb0, 0xd1, 0xb3,
        0x83, 0x69, 0x89, 0x35, 0xa3, 0xb0, 0x04, 0xf4, 0x20, 0x55, 0x7f, 0xd4,
        0xb3, 0xac, 0x5e, 0x91, 0x1d, 0x18, 0x44, 0x83, 0x0b, 0xef, 0x1a, 0xa5,
        0x8c, 0xf9, 0x5a, 0xd3, 0x58, 0x09, 0x4b, 0x07, 0x18, 0x85, 0x6f, 0x32,
        0xe8, 0xc9, 0x2c, 0xa9, 0x99, 0x91, 0xb4, 0x3b, 0x84, 0x2e, 0xb9, 0x27,
        0xd7, 0xe9, 0x3f, 0xe2, 0xa6, 0xb4, 0xfc, 0x9b, 0x1b, 0x07, 0xa9, 0x2f,
        0xc3, 0xc9, 0x4b, 0xc4, 0x77, 0x46, 0x55, 0x75, 0x45, 0x4e, 0xd1, 0x73,
        0xb8, 0x9b, 0x15, 0xd4, 0xb6, 0x49, 0x98, 0x1a, 0x0d, 0xd8, 0x1f, 0x6a,
        0xea, 0x3f, 0xe4, 0x63, 0x01, 0x85, 0x53, 0x40, 0xb1, 0xad, 0xe0, 0x1b,
        0x29, 0x1f, 0x5f, 0xe4, 0x0b, 0x41, 0x7f, 0x9a, 0x5c, 0x8e, 0xa5, 0x6d,
        0xc8, 0xc4, 0xd3, 0x58, 0x81, 0x06, 0x2d, 0x35, 0xac, 0x5e, 0xc4, 0xd9,
        0x65, 0x4b, 0xe7, 0x6b, 0x9d, 0x89, 0x48, 0x6b, 0x04, 0x5f, 0x98, 0xca,
        0xf2, 0x82, 0xc5, 0xdb, 0x38, 0xa3, 0x89, 0x46, 0x7f, 0x08, 0x41, 0x21,
        0xd2, 0x48, 0x03, 0xea, 0x07, 0xb5, 0x1e, 0x9a, 0xf8, 0xca, 0x85, 0xa9,
        0x90, 0xbd, 0x10, 0x7f
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
/* built for stunnel 5.72 */
