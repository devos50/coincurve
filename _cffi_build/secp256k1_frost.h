typedef struct {
    size_t threshold;
    size_t my_index;
    size_t n_signers;
    int pk_parity;
    secp256k1_xonly_pubkey combined_pk;
    secp256k1_pubkey coeff_pk;
} secp256k1_frost_keygen_session;

int secp256k1_frost_keygen_init(
    const secp256k1_context *ctx,
    secp256k1_frost_keygen_session *session,
    secp256k1_scalar *privcoeff,
    secp256k1_pubkey *pubcoeff,
    const size_t threshold,
    const size_t n_signers,
    const size_t my_index,
    const unsigned char *seckey
);

int secp256k1_frost_pubkey_combine(
    const secp256k1_context *ctx,
    secp256k1_scratch_space *scratch,
    secp256k1_frost_keygen_session *session,
    const secp256k1_pubkey *pubkeys
);

void secp256k1_frost_generate_shares(
    secp256k1_frost_share *shares,
    secp256k1_scalar *coeff,
    const secp256k1_frost_keygen_session *session
);


void secp256k1_frost_aggregate_shares(
    secp256k1_frost_share *aggregate_share,
    const secp256k1_frost_share *shares,
    const secp256k1_frost_keygen_session *session
);