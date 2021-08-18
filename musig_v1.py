"""
Python implementation of MuSig v1.
See https://github.com/ElementsProject/secp256k1-zkp/blob/master/src/modules/musig/example.c
"""
import os

from coincurve import GLOBAL_CONTEXT
from coincurve.keys import Keypair
from coincurve._libsecp256k1 import ffi, lib

NUM_SIGNERS = 1000
MSG = b"this_could_be_the_hash_of_a_msg!"

context = GLOBAL_CONTEXT

keypairs = []
for _ in range(NUM_SIGNERS):
    keypairs.append(Keypair())

# Create the xonly_pubkeys
xonly_pubkeys = []
for keypair in keypairs:
    xonly_pubkey = ffi.new('secp256k1_xonly_pubkey *')
    lib.secp256k1_keypair_xonly_pub(context.ctx, xonly_pubkey, ffi.NULL, keypair.keypair)
    xonly_pubkeys.append(xonly_pubkey)

# Create some scratch space
scratch = lib.secp256k1_scratch_space_create(context.ctx, 10000000)

# Combine public keys
combined_key = ffi.new("secp256k1_xonly_pubkey *")
pre_session = ffi.new("secp256k1_musig_pre_session *")
pubkey_ptrs = ffi.new("secp256k1_xonly_pubkey *[]", xonly_pubkeys)
lib.secp256k1_musig_pubkey_combine(context.ctx, scratch, combined_key, pre_session, pubkey_ptrs, NUM_SIGNERS)

# Create and initialize the sessions
sessions = []
session_ids = []
nonce_commitments = []
signer_data_list = []
nonces = []
partial_sigs = ffi.new("secp256k1_musig_partial_signature[%d]" % NUM_SIGNERS)

for ind in range(NUM_SIGNERS):
    signer_data = ffi.new("secp256k1_musig_session_signer_data [%d]" % NUM_SIGNERS)
    signer_data_list.append(signer_data)
    nonces.append(ffi.new("unsigned char[32]"))
    nonce_commitments.append(ffi.new("unsigned char[32]"))

    session_id = os.urandom(32)
    session_ids.append(session_id)
    session = ffi.new("secp256k1_musig_session *")
    sessions.append(session)
    res = lib.secp256k1_musig_session_init(context.ctx,
                                           session,
                                           signer_data_list[ind],
                                           nonce_commitments[ind],
                                           session_id,
                                           MSG,
                                           combined_key,
                                           pre_session,
                                           NUM_SIGNERS,
                                           keypairs[ind].secret)

    if res == 0:
        raise Exception("Session initialization failed!")

# -- Communication round 1: Exchange nonce commitments --

for ind in range(NUM_SIGNERS):
    # Set nonce commitments in the signer data and get the own public nonce
    res = lib.secp256k1_musig_session_get_public_nonce(context.ctx,
                                                       sessions[ind],
                                                       signer_data_list[ind],
                                                       nonces[ind],
                                                       nonce_commitments,
                                                       NUM_SIGNERS,
                                                       ffi.NULL)

    if res == 0:
        raise Exception("Nonce fetching failed!")

# -- Communication round 2: Exchange nonces --

for i in range(NUM_SIGNERS):
    for j in range(NUM_SIGNERS):
        res = lib.secp256k1_musig_set_nonce(context.ctx, ffi.addressof(signer_data_list[i][j]), nonces[j])
        if res == 0:
            raise Exception("Nonce verification failed!")

    # Combine nonces
    res = lib.secp256k1_musig_session_combine_nonces(context.ctx, sessions[i], signer_data_list[i], NUM_SIGNERS, ffi.NULL, ffi.NULL)
    if res == 0:
        raise Exception("Combining nonces failed!")

for i in range(NUM_SIGNERS):
    # Generate partial signature
    res = lib.secp256k1_musig_partial_sign(context.ctx, sessions[i], ffi.addressof(partial_sigs, i))
    if res == 0:
        raise Exception("Generating partial signature failed!")

# -- Communication round 3: Exchange partial signatures --

for i in range(NUM_SIGNERS):
    for j in range(NUM_SIGNERS):
        res = lib.secp256k1_musig_partial_sig_verify(context.ctx, sessions[i], ffi.addressof(signer_data_list[i][j]), ffi.addressof(partial_sigs, j), xonly_pubkeys[j])
        if res == 0:
            raise Exception("Verification of partial signature failed!")

combined_sig = ffi.new("unsigned char[64]")

res = lib.secp256k1_musig_partial_sig_combine(context.ctx, sessions[0], combined_sig, partial_sigs, NUM_SIGNERS)
if res == 0:
    raise Exception("Combining multi-signature failed!")

print(bytes(combined_sig))

# Verify
res = lib.secp256k1_schnorrsig_verify(context.ctx, combined_sig, MSG, 32, combined_key)
if res == 0:
    raise Exception("Verification of Schnorr signature failed!")

print("Everything OK \o/")