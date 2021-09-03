int secp256k1_xonly_pubkey_from_pubkey(
    const secp256k1_context* ctx,
    secp256k1_xonly_pubkey *xonly_pubkey,
    int *pk_parity,
    const secp256k1_pubkey *pubkey
);

int secp256k1_xonly_pubkey_serialize(
    const secp256k1_context* ctx,
    unsigned char *output32,
    const secp256k1_xonly_pubkey* pubkey
);

int secp256k1_keypair_create(
    const secp256k1_context* ctx,
    secp256k1_keypair *keypair,
    const unsigned char *seckey
);