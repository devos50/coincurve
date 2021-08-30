typedef struct {
    uint64_t magic;
    unsigned char pk_hash[32];
    unsigned char second_pk[32];
    int pk_parity;
    int is_tweaked;
    unsigned char tweak[32];
    int internal_key_parity;
} secp256k1_musig_pre_session;

int secp256k1_musig_pubkey_combine(
    const secp256k1_context* ctx,
    secp256k1_scratch_space *scratch,
    secp256k1_xonly_pubkey *combined_pk,
    secp256k1_musig_pre_session *pre_session,
    const secp256k1_xonly_pubkey * const* pubkeys,
    size_t n_pubkeys
);

int secp256k1_musig_session_init(
    const secp256k1_context* ctx,
    secp256k1_musig_secnonce *secnonce,
    unsigned char *pubnonce66,
    const unsigned char *session_id32,
    const unsigned char *seckey,
    const unsigned char *msg32,
    const secp256k1_xonly_pubkey *combined_pk,
    const unsigned char *extra_input32
);

int secp256k1_musig_process_nonces(
    const secp256k1_context* ctx,
    secp256k1_musig_session_cache *session_cache,
    secp256k1_musig_template *sig_template,
    int *nonce_parity,
    const unsigned char * const* pubnonces,
    size_t n_pubnonces,
    const unsigned char *msg32,
    const secp256k1_xonly_pubkey *combined_pk,
    const secp256k1_musig_pre_session *pre_session,
    const secp256k1_pubkey *adaptor
);

int secp256k1_musig_nonces_combine(
    const secp256k1_context* ctx,
    unsigned char *combined_pubnonce66,
    const unsigned char * const* pubnonces,
    size_t n_pubnonces
);

int secp256k1_musig_partial_sign(
    const secp256k1_context* ctx,
    secp256k1_musig_partial_signature *partial_sig,
    secp256k1_musig_secnonce *secnonce,
    const secp256k1_keypair *keypair,
    const secp256k1_musig_pre_session *pre_session,
    const secp256k1_musig_session_cache *session_cache
);

int secp256k1_musig_partial_sig_verify(
    const secp256k1_context* ctx,
    const secp256k1_musig_partial_signature *partial_sig,
    const unsigned char *pubnonce66,
    const secp256k1_xonly_pubkey *pubkey,
    const secp256k1_musig_pre_session *pre_session,
    const secp256k1_musig_session_cache *session_cache
);