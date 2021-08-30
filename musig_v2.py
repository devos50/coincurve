"""
Python implementation of MuSig v2.
See https://github.com/jonasnick/musig-benchmark/blob/master/main.c
"""
import os

from coincurve import GLOBAL_CONTEXT
from coincurve.keys import Keypair
from coincurve._libsecp256k1 import ffi, lib

NUM_SIGNERS = 2
MSG = b"this_could_be_the_hash_of_a_msg!"

context = GLOBAL_CONTEXT

signers = ffi.new("signer_t[%d]" % NUM_SIGNERS)

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
res = lib.secp256k1_musig_pubkey_combine(context.ctx, scratch, combined_key, pre_session, pubkey_ptrs, NUM_SIGNERS)
if res == 0:
    raise Exception("Failed to combine public key!")

# Initialize sessions
secnonces = ffi.new("secp256k1_musig_secnonce[%d]" % NUM_SIGNERS)
pubnonces = [ffi.new("unsigned char[66]")] * NUM_SIGNERS
session_caches = ffi.new("secp256k1_musig_session_cache[%d]" % NUM_SIGNERS)
sig_template = ffi.new("secp256k1_musig_template *")
session_ids = []
partial_sigs = ffi.new("secp256k1_musig_partial_signature[%d]" % NUM_SIGNERS)

for ind in range(NUM_SIGNERS):
    session_ids.append(os.urandom(32))
    res = lib.secp256k1_musig_session_init(context.ctx,
                                           ffi.addressof(secnonces, ind),
                                           pubnonces[ind],
                                           session_ids[ind],
                                           keypairs[ind].secret,
                                           MSG,
                                           combined_key,
                                           ffi.NULL)
    if res == 0:
        raise Exception("Failed to initialize session!")



# -- Communication round 1: Exchange nonces --

combined_pubnonce = ffi.new("unsigned char[66]")
res = lib.secp256k1_musig_nonces_combine(context.ctx,
                                         combined_pubnonce,
                                         pubnonces,
                                         NUM_SIGNERS)
if res == 0:
    raise Exception("Failed to process combine nonces!")

combined_pubnonce_list = [combined_pubnonce]
combined_pubnonce_list_ptr = ffi.new("unsigned char **", combined_pubnonce)

for ind in range(NUM_SIGNERS):
    res = lib.secp256k1_musig_process_nonces(context.ctx,
                                             ffi.addressof(session_caches[ind]),
                                             sig_template,
                                             ffi.NULL,
                                             combined_pubnonce_list_ptr,
                                             1,
                                             MSG,
                                             combined_key,
                                             pre_session,
                                             ffi.NULL
                                             )
    if res == 0:
        raise Exception("Failed to process nonces!")

    res = lib.secp256k1_musig_partial_sign(context.ctx,
                                           ffi.addressof(partial_sigs, ind),
                                           ffi.addressof(secnonces, ind),
                                           keypairs[ind].keypair,
                                           pre_session,
                                           ffi.addressof(session_caches, ind))
    if res == 0:
        raise Exception("Failed to partially sign message!")

# -- Communication round 2: Exchange partial signatures --

for i in range(NUM_SIGNERS):
    for j in range(NUM_SIGNERS):
        res = lib.secp256k1_musig_partial_sig_verify(context.ctx,
                                                     ffi.addressof(partial_sigs, j),
                                                     pubnonces[j],
                                                     xonly_pubkeys[j],
                                                     pre_session,
                                                     ffi.addressof(session_caches, i))
        if res == 0:
            raise Exception("Verification of partial signature failed!")