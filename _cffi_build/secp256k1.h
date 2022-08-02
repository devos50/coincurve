typedef struct {
    uint64_t d[4];
} secp256k1_scalar;

typedef struct {
    unsigned char data[96];
} secp256k1_keypair;

typedef struct {
    uint64_t n[4];
} secp256k1_fe_storage;

typedef struct {
    secp256k1_fe_storage x;
    secp256k1_fe_storage y;
} secp256k1_ge_storage;

typedef struct {
    /* For accelerating the computation of a*P + b*G: */
    secp256k1_ge_storage (*pre_g)[];    /* odd multiples of the generator */
    secp256k1_ge_storage (*pre_g_128)[]; /* odd multiples of 2^128*generator */
} secp256k1_ecmult_context;

typedef struct {
    uint64_t n[5];
} secp256k1_fe;

typedef struct {
    secp256k1_fe x;
    secp256k1_fe y;
    int infinity; /* whether this represents the point at infinity */
} secp256k1_ge;

typedef struct {
    secp256k1_fe x; /* actual X: x/z^2 */
    secp256k1_fe y; /* actual Y: y/z^3 */
    secp256k1_fe z;
    int infinity; /* whether this represents the point at infinity */
} secp256k1_gej;

typedef struct {
    secp256k1_ge_storage (*prec)[64][16]; /* prec[j][i] = (PREC_G)^j * i * G + U_i */
    secp256k1_scalar blind;
    secp256k1_gej initial;
} secp256k1_ecmult_gen_context;

typedef struct secp256k1_context_struct secp256k1_context;

typedef struct secp256k1_scratch_space_struct secp256k1_scratch_space;

typedef struct {
    unsigned char data[64];
} secp256k1_pubkey;

typedef struct {
    unsigned char data[64];
} secp256k1_ecdsa_signature;

typedef struct {
    unsigned char data[64];
} secp256k1_xonly_pubkey;

typedef int (*secp256k1_nonce_function)(
    unsigned char *nonce32,
    const unsigned char *msg32,
    const unsigned char *key32,
    const unsigned char *algo16,
    void *data,
    unsigned int attempt
);

typedef struct {
    unsigned char data[64];
} secp256k1_frost_secnonce;

typedef struct {
    unsigned char data[32];
} secp256k1_frost_share;

#define SECP256K1_FLAGS_TYPE_MASK ...
#define SECP256K1_FLAGS_TYPE_CONTEXT ...
#define SECP256K1_FLAGS_TYPE_COMPRESSION ...
#define SECP256K1_FLAGS_BIT_CONTEXT_VERIFY ...
#define SECP256K1_FLAGS_BIT_CONTEXT_SIGN ...
#define SECP256K1_FLAGS_BIT_COMPRESSION ...

#define SECP256K1_CONTEXT_VERIFY ...
#define SECP256K1_CONTEXT_SIGN ...
#define SECP256K1_CONTEXT_NONE ...

#define SECP256K1_EC_COMPRESSED ...
#define SECP256K1_EC_UNCOMPRESSED ...

secp256k1_context* secp256k1_context_create(
    unsigned int flags
);

secp256k1_context* secp256k1_context_clone(
    const secp256k1_context* ctx
);

void secp256k1_context_destroy(
    secp256k1_context* ctx
);

void secp256k1_context_set_illegal_callback(
    secp256k1_context* ctx,
    void (*fun)(const char* message, void* data),
    const void* data
);

void secp256k1_context_set_error_callback(
    secp256k1_context* ctx,
    void (*fun)(const char* message, void* data),
    const void* data
);

int secp256k1_ec_pubkey_parse(
    const secp256k1_context* ctx,
    secp256k1_pubkey* pubkey,
    const unsigned char *input,
    size_t inputlen
);

int secp256k1_ec_pubkey_serialize(
    const secp256k1_context* ctx,
    unsigned char *output,
    size_t *outputlen,
    const secp256k1_pubkey* pubkey,
    unsigned int flags
);

int secp256k1_ecdsa_signature_parse_compact(
    const secp256k1_context* ctx,
    secp256k1_ecdsa_signature* sig,
    const unsigned char *input64
);

int secp256k1_ecdsa_signature_parse_der(
    const secp256k1_context* ctx,
    secp256k1_ecdsa_signature* sig,
    const unsigned char *input,
    size_t inputlen
);

int secp256k1_ecdsa_signature_serialize_der(
    const secp256k1_context* ctx,
    unsigned char *output,
    size_t *outputlen,
    const secp256k1_ecdsa_signature* sig
);

int secp256k1_ecdsa_signature_serialize_compact(
    const secp256k1_context* ctx,
    unsigned char *output64,
    const secp256k1_ecdsa_signature* sig
);

int secp256k1_ecdsa_verify(
    const secp256k1_context* ctx,
    const secp256k1_ecdsa_signature *sig,
    const unsigned char *msg32,
    const secp256k1_pubkey *pubkey
);

int secp256k1_ecdsa_signature_normalize(
    const secp256k1_context* ctx,
    secp256k1_ecdsa_signature *sigout,
    const secp256k1_ecdsa_signature *sigin
);

extern const secp256k1_nonce_function secp256k1_nonce_function_rfc6979;

extern const secp256k1_nonce_function secp256k1_nonce_function_default;

int secp256k1_ecdsa_sign(
    const secp256k1_context* ctx,
    secp256k1_ecdsa_signature *sig,
    const unsigned char *msg32,
    const unsigned char *seckey,
    secp256k1_nonce_function noncefp,
    const void *ndata
);

int secp256k1_ec_seckey_verify(
    const secp256k1_context* ctx,
    const unsigned char *seckey
);

int secp256k1_ec_pubkey_create(
    const secp256k1_context* ctx,
    secp256k1_pubkey *pubkey,
    const unsigned char *seckey
);

int secp256k1_ec_privkey_tweak_add(
    const secp256k1_context* ctx,
    unsigned char *seckey,
    const unsigned char *tweak
);

int secp256k1_ec_pubkey_tweak_add(
    const secp256k1_context* ctx,
    secp256k1_pubkey *pubkey,
    const unsigned char *tweak
);

int secp256k1_ec_privkey_tweak_mul(
    const secp256k1_context* ctx,
    unsigned char *seckey,
    const unsigned char *tweak
);

int secp256k1_ec_pubkey_tweak_mul(
    const secp256k1_context* ctx,
    secp256k1_pubkey *pubkey,
    const unsigned char *tweak
);

int secp256k1_context_randomize(
    secp256k1_context* ctx,
    const unsigned char *seed32
);

int secp256k1_ec_pubkey_combine(
    const secp256k1_context* ctx,
    secp256k1_pubkey *out,
    const secp256k1_pubkey * const * ins,
    size_t n
);