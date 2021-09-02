void secp256k1_scalar_chacha20(
    secp256k1_scalar *r1,
    secp256k1_scalar *r2,
    const unsigned char *seed,
    uint64_t idx
);

void secp256k1_scalar_clear(
    secp256k1_scalar *r
);

void secp256k1_scalar_set_b32(
    secp256k1_scalar *r,
    const unsigned char *bin,
    int *overflow
);

int secp256k1_scalar_add(
    secp256k1_scalar *r,
    const secp256k1_scalar *a,
    const secp256k1_scalar *b
);

void secp256k1_scalar_mul(
    secp256k1_scalar *r,
    const secp256k1_scalar *a,
    const secp256k1_scalar *b
);