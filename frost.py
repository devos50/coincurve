import os
from binascii import hexlify

from coincurve._libsecp256k1 import ffi, lib

from coincurve import GLOBAL_CONTEXT

NUM_PARTICIPANTS = 7
THRESHOLD = 3
ACTIVE_SIGNERS = 7
context = GLOBAL_CONTEXT
msg = os.urandom(32)
session_id = os.urandom(32)
participants = []
active_participants = [ind + 1 for ind in range(ACTIVE_SIGNERS)]

pubkeys = ffi.new("secp256k1_pubkey[%d]" % NUM_PARTICIPANTS)


class Participant:
    def __init__(self, index, num_participants, threshold):
        self.index = index
        self.num_participants = num_participants
        self.threshold = threshold
        self.session = ffi.new("secp256k1_frost_keygen_session *")
        self.secret_key = os.urandom(32)
        self.private_coefficients = ffi.new("secp256k1_scalar[%d]" % threshold)
        self.public_coefficients = ffi.new("secp256k1_pubkey[%d]" % threshold)
        self.secret_shares = ffi.new("secp256k1_frost_share[%d]" % num_participants)
        self.aggregated_share = ffi.new("secp256k1_frost_share *")
        self.partial_signature = ffi.new("unsigned char[32]")
        self.nonce = ffi.new("secp256k1_frost_secnonce *")

    def init_key(self):
        res = lib.secp256k1_frost_keygen_init(context.ctx,
                                              self.session,
                                              self.private_coefficients,
                                              self.public_coefficients,
                                              self.threshold,
                                              self.num_participants,
                                              self.index + 1,
                                              self.secret_key)

        if res == 0:
            raise Exception("Keygen initialization failed for participant %d" % (ind + 1))

    def combine_pubkeys(self, pubkeys_of_others):
        res = lib.secp256k1_frost_pubkey_combine(context.ctx,
                                                 ffi.NULL,
                                                 self.session,
                                                 pubkeys_of_others)
        if res == 0:
            raise Exception("Combining public keys failed for participant %d" % (ind + 1))

    def generate_shares(self):
        lib.secp256k1_frost_generate_shares(self.secret_shares,
                                            self.private_coefficients,
                                            self.session)

    def aggregate_shares(self, other_shares):
        lib.secp256k1_frost_aggregate_shares(self.aggregated_share,
                                             other_shares,
                                             self.session)

    def generate_nonced_pubkey(self):
        serialized_group_key = ffi.new("unsigned char[33]")
        lib.secp256k1_xonly_pubkey_serialize(context.ctx, serialized_group_key, ffi.addressof(self.session, "combined_pk"))
        lib.secp256k1_nonce_function_frost(self.nonce,
                                           session_id,
                                           self.aggregated_share.data,
                                           msg,
                                           serialized_group_key,
                                           b"FROST/non",
                                           9,
                                           ffi.NULL)

        s = ffi.new("secp256k1_scalar *")
        rj = ffi.new("secp256k1_gej *")
        rp = ffi.new("secp256k1_ge *")

        lib.secp256k1_scalar_set_b32(s, self.nonce.data, ffi.NULL)
        lib.secp256k1_ecmult_gen_with_ctx(context.ctx, rj, s)
        lib.secp256k1_ge_set_gej(rp, rj)
        lib.secp256k1_pubkey_save(ffi.addressof(pubkeys, self.session.my_index - 1), rp)  # Save the nonced pubkey in pubkeys

    def compute_partial_signature(self, group_commitment, aggregated_pk, active_participants, pk_parity):
        # Step 4+5 of the sign protocol
        scalar1 = ffi.new("secp256k1_scalar *")
        scalar2 = ffi.new("secp256k1_scalar *")
        c = ffi.new("secp256k1_scalar *")
        l = ffi.new("secp256k1_scalar *")

        # scalar2 is the group commitment
        lib.secp256k1_schnorrsig_challenge(c, group_commitment, msg, ffi.addressof(aggregated_pk, 1))  # Challenge stored in c
        lib.secp256k1_scalar_set_b32(scalar1, self.aggregated_share.data, ffi.NULL)
        lib.secp256k1_frost_lagrange_coefficient(l, active_participants, len(active_participants), self.session.my_index)
        lib.secp256k1_scalar_mul(scalar1, scalar1, l)
        lib.secp256k1_scalar_mul(scalar2, c, scalar1)
        lib.secp256k1_nonce_function_frost(self.nonce, session_id, self.aggregated_share.data, msg,
                                           ffi.addressof(aggregated_pk, 1), b"FROST/non", 9,
                                           ffi.NULL)
        lib.secp256k1_scalar_set_b32(scalar1, participant.nonce.data, ffi.NULL)
        if pk_parity:
            lib.secp256k1_scalar_negate(scalar1, scalar1)
        lib.secp256k1_scalar_add(scalar2, scalar2, scalar1)
        lib.secp256k1_scalar_get_b32(self.partial_signature, scalar2)


class Aggregator:
    def __init__(self, participant, n_signers):
        self.participant = participant
        self.participant.session.n_signers = n_signers
        self.signature = ffi.new("unsigned char[64]")
        self.aggregated_pk = ffi.new("unsigned char[33]")
        self.group_commitment = ffi.new("unsigned char[33]")

    def aggregate_shares(self, aggregated_shares, active_participants):
        scalar1 = ffi.new("secp256k1_scalar *")
        scalar2 = ffi.new("secp256k1_scalar *")
        rj = ffi.new("secp256k1_gej *")
        rp = ffi.new("secp256k1_ge *")
        size = ffi.new("size_t *")
        size[0] = 33

        for participant_index, aggregated_share in aggregated_shares:
            l = ffi.new("secp256k1_scalar *")
            lib.secp256k1_frost_lagrange_coefficient(l, active_participants, len(active_participants), participant_index)
            lib.secp256k1_scalar_set_b32(scalar1, aggregated_share.data, ffi.NULL)
            lib.secp256k1_scalar_mul(scalar1, scalar1, l)
            lib.secp256k1_scalar_add(scalar2, scalar2, scalar1)

        lib.secp256k1_ecmult_gen_with_ctx(context.ctx, rj, scalar2)
        lib.secp256k1_ge_set_gej(rp, rj)
        lib.secp256k1_pubkey_save(ffi.addressof(pubkeys, self.participant.session.my_index - 1), rp)

        assert lib.secp256k1_ec_pubkey_serialize(context.ctx, self.aggregated_pk, size, ffi.addressof(pubkeys, self.participant.session.my_index - 1), lib.SECP256K1_EC_COMPRESSED)

    def compute_signature(self, partial_signatures, group_commitment):
        z = ffi.new("secp256k1_scalar *")
        zi = ffi.new("secp256k1_scalar *")
        for partial_signature in partial_signatures:
            lib.secp256k1_scalar_set_b32(zi, partial_signature, ffi.NULL)
            lib.secp256k1_scalar_add(z, z, zi)

        ffi.memmove(ffi.addressof(self.signature, 0), group_commitment, 32)
        lib.secp256k1_scalar_get_b32(ffi.addressof(self.signature, 32), z)

    def compute_group_commitment(self):
        assert lib.secp256k1_frost_pubkey_combine(context.ctx, ffi.NULL, aggregator.participant.session,
                                                  pubkeys)  # Override the combined_key in the session of the aggregator!
        print("Combined key: %s" % hexlify(bytes(aggregator.participant.session.combined_pk.data)).decode())
        assert lib.secp256k1_xonly_pubkey_serialize(context.ctx, self.group_commitment,
                                                    ffi.addressof(aggregator.participant.session,
                                                                  "combined_pk"))  # group_commitment <- serialized(combined_pk)


# Initialize participants
for ind in range(NUM_PARTICIPANTS):
    participant = Participant(ind, NUM_PARTICIPANTS, THRESHOLD)
    participant.init_key()
    participants.append(participant)

# Round 1.1, 1.2, 1.3, and 1.4
# TODO share public keys with others
for participant in participants:
    pubkeys[participant.index] = participant.session.coeff_pk

# Round 2.4
# Each participant now derives the (same) group public key
for participant in participants:
    participant.combine_pubkeys(pubkeys)

combined_pks = [bytes(participant.session.combined_pk.data) for participant in participants]
assert all(x == combined_pks[0] for x in combined_pks)
print("Group public key: %s" % hexlify(bytes(participants[0].session.combined_pk.data)).decode())

# Round 2.1
# Each participant generates its secret shares
for participant in participants:
    participant.generate_shares()

# Round 2.3
# TODO share secret shares with other participants
for participant in participants:
    rec_shares = []
    for other_participant in participants:
        rec_shares.append(other_participant.secret_shares[participant.session.my_index - 1])

    participant.aggregate_shares(rec_shares)

# DONE BY AGGREGATOR
aggregator = Aggregator(participants[0], len(active_participants))
aggregated_shares = [(ind, participants[ind - 1].aggregated_share) for ind in active_participants]
aggregator.aggregate_shares(aggregated_shares, active_participants)

# Generate nonce pks, done by participants
for participant_index in active_participants:
    participant = participants[participant_index - 1]
    participant.generate_nonced_pubkey()
    print("Nonce pubkey of participant %d: %s" % (participant_index, hexlify(bytes(pubkeys[participant_index - 1].data)).decode()))

# DONE BY AGGREGATOR
aggregator.compute_group_commitment()

# TODO share group commitment with others

# Generate partial signatures, done by participants
for participant_index in active_participants:
    participant = participants[participant_index - 1]
    participant.compute_partial_signature(aggregator.group_commitment, aggregator.aggregated_pk, active_participants, aggregator.participant.session.pk_parity)
    print("Partial signature of participant %d: %s" % (participant_index, hexlify(bytes(participant.partial_signature)).decode()))

# Combine partial signatures (step 7c)
partial_signatures = [participants[ind - 1].partial_signature for ind in active_participants]
aggregator.compute_signature(partial_signatures, aggregator.group_commitment)

sig_hex = hexlify(bytes(aggregator.signature)).decode()
print("Resulting Schnorr signature: %s" % sig_hex)

assert lib.secp256k1_schnorrsig_verify(context.ctx, aggregator.signature, msg, ffi.addressof(participants[1].session, "combined_pk"))
print("SCHNORR SIGNATURE VALID")
