import os
from binascii import hexlify

from coincurve._libsecp256k1 import ffi, lib

from coincurve import GLOBAL_CONTEXT

NUM_PARTICIPANTS = 3
THRESHOLD = 2

context = GLOBAL_CONTEXT
sessions = []
private_coefficients = []
public_coefficients = []
pubkeys = ffi.new("secp256k1_pubkey[%d]" % NUM_PARTICIPANTS)
shares = []
agg_shares = []
participants = []
p_sigs = []
l = ffi.new("secp256k1_scalar *")
s1 = ffi.new("secp256k1_scalar *")
s2 = ffi.new("secp256k1_scalar *")
rj = ffi.new("secp256k1_gej *")
rp = ffi.new("secp256k1_ge *")
keypair = ffi.new("secp256k1_keypair *")
k = ffi.new("secp256k1_frost_secnonce *")
pk1 = ffi.new("unsigned char[33]")
pk2 = ffi.new("unsigned char[33]")
sig = ffi.new("unsigned char[64]")
size = ffi.new("size_t *")
size[0] = 33

# Initialize variables
for ind in range(NUM_PARTICIPANTS):
    session = ffi.new("secp256k1_frost_keygen_session *")
    sessions.append(session)

    coefficients = ffi.new("secp256k1_scalar[%d]" % THRESHOLD)
    private_coefficients.append(coefficients)

    coefficients = ffi.new("secp256k1_pubkey[%d]" % THRESHOLD)
    public_coefficients.append(coefficients)

    my_shares = ffi.new("secp256k1_frost_share[%d]" % NUM_PARTICIPANTS)
    shares.append(my_shares)

    my_agg_share = ffi.new("secp256k1_frost_share *")
    agg_shares.append(my_agg_share)

    p_sig = ffi.new("unsigned char[32]")
    p_sigs.append(p_sig)

# Round 1.1, 1.2, 1.3, and 1.4
for ind in range(NUM_PARTICIPANTS):
    sk = os.urandom(32)
    print("Secret of participant %d: %s" % (ind, hexlify(sk).decode()))
    res = lib.secp256k1_frost_keygen_init(context.ctx,
                                          sessions[ind],
                                          private_coefficients[ind],
                                          public_coefficients[ind],
                                          THRESHOLD,
                                          NUM_PARTICIPANTS,
                                          ind + 1,
                                          sk)

    if res == 0:
        raise Exception("Keygen initialization failed for participant %d" % (ind + 1))

    pubkeys[ind] = sessions[ind].coeff_pk

# Round 2.4
for ind in range(NUM_PARTICIPANTS):
    res = lib.secp256k1_frost_pubkey_combine(context.ctx,
                                             ffi.NULL,
                                             sessions[ind],
                                             pubkeys)
    if res == 0:
        raise Exception("Combining public keys failed for participant %d" % (ind + 1))

# Round 2.1
for ind in range(NUM_PARTICIPANTS):
    lib.secp256k1_frost_generate_shares(shares[ind],
                                        private_coefficients[ind],
                                        sessions[ind])

# Round 2.3
for i in range(NUM_PARTICIPANTS):
    rec_shares = []
    for j in range(NUM_PARTICIPANTS):
        rec_shares.append(shares[j][sessions[i].my_index - 1])

    lib.secp256k1_frost_aggregate_shares(agg_shares[i], rec_shares, sessions[i])

# Reconstruct secret
# ONLY FOR TESTING PURPOSES

for i in range(THRESHOLD):
    participants.append(sessions[i].my_index)

lib.secp256k1_scalar_clear(s2)

for i in range(THRESHOLD):
    lib.secp256k1_frost_lagrange_coefficient(l, participants, THRESHOLD, sessions[i].my_index)
    lib.secp256k1_scalar_set_b32(s1, agg_shares[i].data, ffi.NULL)
    lib.secp256k1_scalar_mul(s1, s1, l)
    lib.secp256k1_scalar_add(s2, s2, s1)

lib.secp256k1_ecmult_gen_with_ctx(context.ctx, rj, s2)
lib.secp256k1_ge_set_gej(rp, rj)
ptr = ffi.new("secp256k1_pubkey *", pubkeys[0])
lib.secp256k1_pubkey_save(ptr, rp)
assert lib.secp256k1_ec_pubkey_serialize(context.ctx, pk1, size, ptr, lib.SECP256K1_EC_COMPRESSED)
ptr = ffi.new("secp256k1_xonly_pubkey *", sessions[0].combined_pk)
assert lib.secp256k1_xonly_pubkey_serialize(context.ctx, pk2, ptr)
assert lib.secp256k1_memcmp_var(ffi.addressof(pk1, 1), pk2, 32) == 0
lib.secp256k1_scalar_clear(s1)

for i in range(NUM_PARTICIPANTS):
    ptr = ffi.new("secp256k1_scalar *", private_coefficients[i][0])
    lib.secp256k1_scalar_add(s1, s1, ptr)

assert lib.secp256k1_scalar_eq(s1, s2)

print("Global secret: %d %d %d %d" % (s1.d[0], s1.d[1], s1.d[2], s1.d[3]))

# Test signing
msg = os.urandom(32)
lib.secp256k1_scalar_get_b32(sk, s1)
assert lib.secp256k1_keypair_create(context.ctx, keypair, sk)
assert lib.secp256k1_schnorrsig_sign(context.ctx, sig, msg, keypair, ffi.NULL, ffi.NULL)
ptr = ffi.new("secp256k1_xonly_pubkey *", sessions[0].combined_pk)
assert lib.secp256k1_schnorrsig_verify(context.ctx, sig, msg, ptr)

print("Schnorr signature with full key: %s" % hexlify(bytes(sig)).decode())

# Generate nonces
the_id = os.urandom(32)

pk_list = []

for i in range(THRESHOLD):
    lib.secp256k1_nonce_function_frost(k, the_id, agg_shares[i].data, msg, pk2, b"FROST/non", 9, ffi.NULL)
    lib.secp256k1_scalar_set_b32(s1, k.data, ffi.NULL)
    lib.secp256k1_ecmult_gen_with_ctx(context.ctx, rj, s1)
    lib.secp256k1_ge_set_gej(rp, rj)
    lib.secp256k1_pubkey_save(ffi.addressof(pubkeys, i), rp)

    print("Nonce pubkey of participant %d: %s" % (i, hexlify(bytes(pubkeys[i].data)).decode()))

sessions[0].n_signers = THRESHOLD
assert lib.secp256k1_frost_pubkey_combine(context.ctx, ffi.NULL, sessions[0], pubkeys)
print("Combined key: %s" % hexlify(bytes(sessions[0].combined_pk.data)).decode())
assert lib.secp256k1_xonly_pubkey_serialize(context.ctx, pk2, ffi.addressof(sessions[0], "combined_pk"))

# Sign
for i in range(THRESHOLD):
    # Compute challenge hash
    lib.secp256k1_schnorrsig_challenge(s2, pk2, msg, ffi.addressof(pk1, 1))
    lib.secp256k1_scalar_set_b32(s1, agg_shares[i].data, ffi.NULL)
    lib.secp256k1_frost_lagrange_coefficient(l, participants, THRESHOLD, sessions[i].my_index)
    lib.secp256k1_scalar_mul(s1, s1, l)
    lib.secp256k1_scalar_mul(s2, s2, s1)
    ptr = ffi.new("secp256k1_xonly_pubkey *", sessions[0].combined_pk)
    assert lib.secp256k1_xonly_pubkey_serialize(context.ctx, pk2, ptr)
    lib.secp256k1_nonce_function_frost(k, the_id, agg_shares[i].data, msg, ffi.addressof(pk1, 1), b"FROST/non", 9, ffi.NULL)
    lib.secp256k1_scalar_set_b32(s1, k.data, ffi.NULL)
    if sessions[0].pk_parity:
        lib.secp256k1_scalar_negate(s1, s1)
    lib.secp256k1_scalar_add(s2, s2, s1)
    lib.secp256k1_scalar_get_b32(p_sigs[i], s2)

    print("Partial signature of participant %d: %s" % (i, hexlify(bytes(p_sigs[i])).decode()))

# Combine sigs
lib.secp256k1_scalar_clear(s1)
for i in range(THRESHOLD):
    lib.secp256k1_scalar_set_b32(s2, p_sigs[i], ffi.NULL)
    lib.secp256k1_scalar_add(s1, s1, s2)

lib.secp256k1_scalar_get_b32(ffi.addressof(sig, 32), s1)
ffi.memmove(ffi.addressof(sig, 0), pk2, 32)

sig_hex = hexlify(bytes(sig)).decode()
print("Resulting Schnorr signature: %s" % sig_hex)

assert lib.secp256k1_schnorrsig_verify(context.ctx, sig, msg, ffi.addressof(sessions[1], "combined_pk"))
print("SCHNORR SIGNATURE VALID")
