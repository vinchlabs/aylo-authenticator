// T3T1 binding between the vault and the replica areas.
//
// This file used to be the NORCOW adapter: it opened norcow, walked its
// records, and validated a key-shape scheme of 0xff01 for the root, 0xff10+i
// for a credential and 0xff80+i for the 40-byte tag that authenticated it. All
// of that is gone. The snapshot MAC authenticates every record at once, so the
// tags are unnecessary, and the record's own shape is checked by the codec in
// replica_records rather than by a key-range test here.
//
// What is left is a forwarding layer. It is thin on purpose: the snapshot model
// lives in replica_records, and the only thing that knows a replica has a
// physical address is authenticator_replica_io.c. That is also why there are no
// mpu_reconfig()/mpu_restore() pairs left in this file -- the IO adapter opens
// exactly one MPU window per operation and closes it again, which is stricter
// than the per-call bracketing this file used to do.

#include "authenticator_storage.h"

#include "../authenticator_backend.h"
#include "../authenticator_replica_io.h"
#include "memzero.h"

_Static_assert(AUTH_BACKEND_ROOT_CANDIDATES == AUTH_REPLICA_COUNT,
               "backend candidate count must match the replica count");
_Static_assert(AUTH_RECORD_SIZE == AUTH_REPLICA_ROOT_LENGTH,
               "the stored root envelope must fill the format's root region");

auth_result auth_store_open(bool provision) {
  // Provisioning is no longer something the open call arranges: whether it is
  // permitted follows from the classification, and replica_records refuses it
  // on anything but genuinely blank media.
  (void)provision;
  return auth_records_open(auth_replica_io_t3t1());
}

auth_result auth_store_state(void) {
  if (!auth_records_ready()) return AUTH_ERROR;
  // Re-classifying is cheap and keeps the answer honest after an external
  // change.
  return auth_records_open(auth_replica_io_t3t1());
}

auth_result auth_store_root_candidates(
    uint8_t out[AUTH_REPLICA_COUNT][AUTH_RECORD_SIZE], uint8_t *count) {
  return auth_records_root_candidates(out, count);
}

auth_result auth_store_unlock(const uint8_t kek[32], uint8_t root_out[32]) {
  uint8_t candidates[AUTH_REPLICA_COUNT][AUTH_RECORD_SIZE];
  uint8_t count = 0;
  auth_result result = auth_records_root_candidates(candidates, &count);
  if (result == AUTH_OK) {
    result = auth_records_unlock(kek, candidates, count, root_out);
  }
  // Envelopes are ciphertext, but there is no reason to leave them lying
  // around.
  memzero(candidates, sizeof(candidates));
  return result;
}

auth_result auth_store_provision(const uint8_t root[32],
                                 const uint8_t envelope[AUTH_RECORD_SIZE],
                                 const uint8_t nonce[AUTH_REPLICA_NONCE_SIZE]) {
  return auth_records_provision(root, envelope, nonce);
}

auth_result auth_store_commit_root(
    const uint8_t root[32], const uint8_t envelope[AUTH_RECORD_SIZE],
    const uint8_t nonce[AUTH_REPLICA_NONCE_SIZE]) {
  return auth_records_commit_root(root, envelope, nonce);
}

auth_result auth_store_record_read(const uint8_t root[32], uint8_t index,
                                   uint8_t *out, uint16_t capacity,
                                   uint16_t *length) {
  return auth_records_read(root, index, out, capacity, length);
}

auth_result auth_store_record_walk(const uint8_t root[32],
                                   auth_slot_visitor visitor, void *context) {
  return auth_records_walk(root, visitor, context);
}

auth_result auth_store_record_write(
    const uint8_t root[32], uint8_t index, const uint8_t *record,
    uint16_t length, const uint8_t nonce[AUTH_REPLICA_NONCE_SIZE]) {
  return auth_records_write(root, index, record, length, nonce);
}

auth_result auth_store_record_delete(
    const uint8_t root[32], uint8_t index,
    const uint8_t nonce[AUTH_REPLICA_NONCE_SIZE]) {
  return auth_records_delete(root, index, nonce);
}

auth_result auth_store_repair(const uint8_t root[32]) {
  return auth_records_repair(root);
}

auth_result auth_store_resident_capacity(uint8_t index, uint16_t id_len) {
  // Fixed-capacity slots, so this is a bound check rather than the free-space
  // walk the NORCOW version had to perform. No record can displace another.
  return auth_records_capacity(index,
                               (uint16_t)(AUTH_RECORD_HEADER_SIZE + id_len));
}

auth_result auth_store_wipe(void) { return auth_records_wipe(); }
