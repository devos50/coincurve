typedef struct {
    uint64_t d[4];
} secp256k1_scalar;

void secp256k1_scalar_chacha20(
    secp256k1_scalar *r1,
    secp256k1_scalar *r2,
    const unsigned char *seed,
    uint64_t idx
);