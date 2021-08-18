typedef struct {
    uint64_t magic;
    unsigned char pk_hash[32];
    unsigned char second_pk[32];
    int pk_parity;
    int is_tweaked;
    unsigned char tweak[32];
    int internal_key_parity;
} secp256k1_musig_pre_session;

typedef struct {
    uint64_t magic;
    int round;
    secp256k1_musig_pre_session pre_session;
    secp256k1_xonly_pubkey combined_pk;
    uint32_t n_signers;
    int is_msg_set;
    unsigned char msg[32];
    int has_secret_data;
    unsigned char seckey[32];
    unsigned char secnonce[32];
    secp256k1_xonly_pubkey nonce;
    int partial_nonce_parity;
    unsigned char nonce_commitments_hash[32];
    secp256k1_xonly_pubkey combined_nonce;
    int combined_nonce_parity;
} secp256k1_musig_session;

typedef struct {
    int present;
    secp256k1_xonly_pubkey nonce;
    unsigned char nonce_commitment[32];
} secp256k1_musig_session_signer_data;

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
    secp256k1_musig_session *session,
    secp256k1_musig_session_signer_data *signers,
    unsigned char *nonce_commitment32,
    const unsigned char *session_id32,
    const unsigned char *msg32,
    const secp256k1_xonly_pubkey *combined_pk,
    const secp256k1_musig_pre_session *pre_session,
    size_t n_signers,
    const unsigned char *seckey
);

int secp256k1_musig_session_get_public_nonce(
    const secp256k1_context* ctx,
    secp256k1_musig_session *session,
    secp256k1_musig_session_signer_data *signers,
    unsigned char *nonce32,
    const unsigned char *const *commitments,
    size_t n_commitments,
    const unsigned char *msg32
);

int secp256k1_musig_set_nonce(
    const secp256k1_context* ctx,
    secp256k1_musig_session_signer_data *signer,
    const unsigned char *nonce32
);

int secp256k1_musig_session_combine_nonces(
    const secp256k1_context* ctx,
    secp256k1_musig_session *session,
    const secp256k1_musig_session_signer_data *signers,
    size_t n_signers,
    int *nonce_parity,
    const secp256k1_pubkey *adaptor
);

int secp256k1_musig_partial_sign(
    const secp256k1_context* ctx,
    const secp256k1_musig_session *session,
    secp256k1_musig_partial_signature *partial_sig
);

int secp256k1_musig_partial_sig_verify(
    const secp256k1_context* ctx,
    const secp256k1_musig_session *session,
    const secp256k1_musig_session_signer_data *signer,
    const secp256k1_musig_partial_signature *partial_sig,
    const secp256k1_xonly_pubkey *pubkey
);

int secp256k1_musig_partial_sig_combine(
    const secp256k1_context* ctx,
    const secp256k1_musig_session *session,
    unsigned char *sig64,
    const secp256k1_musig_partial_signature *partial_sigs,
    size_t n_sigs
);