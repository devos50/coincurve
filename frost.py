import os

from coincurve._libsecp256k1 import ffi, lib

from coincurve import GLOBAL_CONTEXT

NUM_PARTICIPANTS = 3
THRESHOLD = 2

context = GLOBAL_CONTEXT
sessions = []
private_coefficients = []
public_coefficients = []
pubkeys = []
shares = []
agg_shares = []
participants = []
l = ffi.new("secp256k1_scalar *")
s1 = ffi.new("secp256k1_scalar *")
s2 = ffi.new("secp256k1_scalar *")

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

# Round 1.1, 1.2, 1.3, and 1.4
for ind in range(NUM_PARTICIPANTS):
    sk = os.urandom(256)
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

    pubkeys.append(sessions[ind].coeff_pk)

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

print(context.ctx.ecmut_gen_ctx)