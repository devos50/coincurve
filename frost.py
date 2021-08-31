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

# Initialize variables
for ind in range(NUM_PARTICIPANTS):
    session = ffi.new("secp256k1_frost_keygen_session *")
    sessions.append(session)

    coefficients = ffi.new("secp256k1_scalar[%d]" % THRESHOLD)
    private_coefficients.append(coefficients)

    coefficients = ffi.new("secp256k1_pubkey[%d]" % THRESHOLD)
    public_coefficients.append(coefficients)

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
