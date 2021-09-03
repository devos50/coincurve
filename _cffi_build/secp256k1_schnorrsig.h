typedef int (*secp256k1_nonce_function_hardened)(
    unsigned char *nonce32,
    const unsigned char *msg32,
    const unsigned char *key32,
    const unsigned char *xonly_pk32,
    const unsigned char *algo16,
    void *data
);

int secp256k1_schnorrsig_sign(
    const secp256k1_context* ctx,
    unsigned char *sig64,
    const unsigned char *msg32,
    const secp256k1_keypair *keypair,
    secp256k1_nonce_function_hardened noncefp,
    void *ndata
);

int secp256k1_schnorrsig_verify(
    const secp256k1_context* ctx,
    const unsigned char *sig64,
    const unsigned char *msg32,
    const secp256k1_xonly_pubkey *pubkey
);

void secp256k1_schnorrsig_challenge(
    secp256k1_scalar* e,
    const unsigned char *r32,
    const unsigned char *msg32,
    const unsigned char *pubkey32
);