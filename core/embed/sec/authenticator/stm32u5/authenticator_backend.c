#include "../authenticator_backend.h"
#include <sec/optiga.h>
#include <sec/rng_strong.h>
#include <sec/storage.h>
#include <string.h>
#include "authenticator_storage.h"
#include "memzero.h"

_Static_assert(STRETCHED_PIN_COUNT == 1,
               "authenticator requires one OPTIGA PIN slot");

// Every mutation needs a snapshot nonce. replica_store takes it as an argument
// on purpose so that it stays deterministic and host-testable; supplying it is
// this layer's job, and it comes from the hardware RNG.
static bool fresh_nonce(uint8_t nonce[AUTH_REPLICA_NONCE_SIZE]) {
  return auth_backend_random(nonce, AUTH_REPLICA_NONCE_SIZE);
}

static bool normalize_counter(void) {
  uint32_t rem = 0;
  if (!optiga_pin_get_rem(&rem) || rem < 8 || rem > PIN_MAX_TRIES) return false;
  if (rem > 8 && !optiga_pin_decrease_rem(rem - 8)) return false;
  return optiga_pin_get_rem(&rem) && rem == 8;
}

// Destroys the persistent PIN counter, which is what makes every stored
// envelope undecryptable. Used both by wipe and by the interrupted-cleanup
// paths.
static bool exhaust_counter(void) {
  uint32_t rem = 0;
  if (!optiga_pin_get_rem(&rem) || rem > PIN_MAX_TRIES) return false;
  if (rem && !optiga_pin_decrease_rem(rem)) return false;
  return optiga_pin_get_rem(&rem) && rem == 0;
}

// Reconciles the secure element against the replica areas on every entry.
//
// The NORCOW version of this function reasoned about a one-byte root tombstone
// and about flag aliases in the reserved key range. Neither exists now: a wipe
// erases whole areas rather than rewriting keys, and there is no key namespace
// to alias. What remains is the genuine ambiguity, which is a mismatch between
// the secure element and storage:
//
//   * a snapshot exists but the counter is exhausted -- cleanup was interrupted
//     after the counter was destroyed, so the snapshot is already useless;
//   * storage classifies as anything other than "snapshot" or "ours and empty",
//     which is either foreign data or media we could not read. Both must be
//     surfaced, never resolved by erasing.
static auth_result reconcile(void) {
  auth_result state = auth_store_state();
  if (state == AUTH_MIGRATION_REQUIRED) return state;
  if (state != AUTH_OK && state != AUTH_UNPROVISIONED) return AUTH_ERROR;

  uint32_t rem = 0;
  if (!optiga_pin_get_rem(&rem) || rem > 8) return AUTH_ERROR;

  if (state == AUTH_OK && rem == 0) {
    // Never re-provision the secure element on reconnect; finish the wipe.
    return auth_backend_wipe() ? AUTH_UNPROVISIONED : AUTH_ERROR;
  }
  return state;
}

bool auth_backend_init(void) {
  if (auth_store_open(false) == AUTH_MIGRATION_REQUIRED) {
    // Initialization succeeds so that the vault can report the reason; nothing
    // is read, erased, or provisioned.
    return true;
  }
  auth_result state = reconcile();
  return state == AUTH_OK || state == AUTH_UNPROVISIONED ||
         state == AUTH_MIGRATION_REQUIRED;
}

auth_result auth_backend_root_candidates(
    uint8_t out[AUTH_BACKEND_ROOT_CANDIDATES][AUTH_RECORD_SIZE],
    uint8_t *count) {
  if (count != NULL) *count = 0;
  if (out == NULL || count == NULL) return AUTH_INVALID_ARGUMENT;
  auth_result state = reconcile();
  if (state != AUTH_OK) return state;
  return auth_store_root_candidates(out, count);
}

auth_result auth_backend_unlock(const uint8_t kek[32], uint8_t root_out[32]) {
  if (kek == NULL || root_out == NULL) return AUTH_INVALID_ARGUMENT;
  auth_result state = reconcile();
  if (state != AUTH_OK) return state;
  return auth_store_unlock(kek, root_out);
}

bool auth_backend_write(const uint8_t root[32],
                        const uint8_t record[AUTH_RECORD_SIZE]) {
  if (root == NULL || record == NULL) return false;
  uint8_t nonce[AUTH_REPLICA_NONCE_SIZE];
  if (!fresh_nonce(nonce)) return false;

  // Provisioning creates generation 1; a later write re-wraps the envelope of
  // an existing vault. The classification decides which, so a re-wrap can never
  // erase a vault and provisioning can never overwrite one.
  auth_result state = auth_store_state();
  auth_result result;
  if (state == AUTH_UNPROVISIONED) {
    result = auth_store_provision(root, record, nonce);
  } else if (state == AUTH_OK) {
    result = auth_store_commit_root(root, record, nonce);
  } else {
    result = state;
  }
  memzero(nonce, sizeof(nonce));
  return result == AUTH_OK;
}

bool auth_backend_wipe(void) {
  auth_result state = auth_store_state();
  if (state == AUTH_UNPROVISIONED) {
    // Already ours and empty. Still make sure the counter cannot authorise
    // anything, then report success idempotently.
    return exhaust_counter();
  }
  if (state != AUTH_OK) {
    // Foreign data, or media we could not read. Erasing either on the strength
    // of a failed read is exactly what this design refuses to do.
    return false;
  }
  // Order matters and is unchanged: destroy the persistent counter *before*
  // touching storage, so a power cut between the two leaves every surviving
  // replica cryptographically useless rather than merely orphaned.
  if (!exhaust_counter()) return false;
  if (auth_store_wipe() != AUTH_OK) return false;
  // Read back: a wiped device must classify as ours-and-empty, not as foreign
  // data needing migration, or it could never be provisioned again.
  return auth_store_state() == AUTH_UNPROVISIONED;
}

bool auth_backend_random(uint8_t *out, size_t len) {
  rng_fill_buffer_strong(out, len);  // hardware entropy errors halt fail closed
  return true;
}

bool auth_backend_remaining(uint8_t *remaining) {
  uint32_t rem = 0;
  if (!optiga_pin_get_rem(&rem) || rem > 8) return false;
  *remaining = rem;
  return true;
}

auth_result auth_backend_set_pin(const uint8_t verifier[32],
                                 uint8_t output[32]) {
  uint8_t slots[STRETCHED_PIN_COUNT][32] = {0}, reset_key[32] = {0};
  auth_result result = AUTH_ERROR;
  memcpy(slots[0], verifier, 32);
  auth_result state = auth_store_open(true);
  if (state != AUTH_OK && state != AUTH_UNPROVISIONED) goto done;
  if (reconcile() == AUTH_MIGRATION_REQUIRED) goto done;
  if (!optiga_pin_init(NULL) || !optiga_pin_stretch_cmac_ecdh(NULL, slots[0]) ||
      !optiga_pin_set(NULL, slots, reset_key) || !normalize_counter())
    goto done;
  memcpy(output, slots[0], 32);
  result = AUTH_OK;
done:
  memzero(slots, sizeof(slots));
  memzero(reset_key, sizeof(reset_key));
  if (result != AUTH_OK) memzero(output, 32);
  return result;
}

auth_result auth_backend_verify_pin(const uint8_t verifier[32],
                                    uint8_t output[32]) {
  auth_result result = AUTH_ERROR;
  memcpy(output, verifier, 32);
  if (!optiga_pin_stretch_cmac_ecdh(NULL, output)) goto done;
  // Modern set()/verify() must match; legacy verify_v4 is incompatible.
  switch (optiga_pin_verify(NULL, 0, output)) {
    case OPTIGA_PIN_SUCCESS:
      if (normalize_counter()) result = AUTH_OK;
      break;
    case OPTIGA_PIN_INVALID:
      result = AUTH_PIN_INVALID;
      break;
    case OPTIGA_PIN_COUNTER_EXCEEDED:
      result = AUTH_PIN_BLOCKED;
      break;
    default:
      break;
  }
done:
  if (result != AUTH_OK) memzero(output, 32);
  return result;
}

bool auth_backend_zeroized(const void *buffer, size_t len) {
  const uint8_t *p = buffer;
  uint8_t sum = 0;
  for (size_t i = 0; i < len; i++) sum |= p[i];
  return sum == 0;
}

auth_result auth_backend_slot_read(const uint8_t root[32], uint8_t index,
                                   uint8_t *out, uint16_t capacity,
                                   uint16_t *length) {
  if (length != NULL) *length = 0;
  if (root == NULL || out == NULL || length == NULL) {
    return AUTH_INVALID_ARGUMENT;
  }
  if (index >= AUTH_RESIDENT_CAPACITY) return AUTH_INVALID_ARGUMENT;
  return auth_store_record_read(root, index, out, capacity, length);
}

auth_result auth_backend_slot_walk(const uint8_t root[32],
                                   auth_slot_visitor visitor, void *context) {
  if (root == NULL || visitor == NULL) return AUTH_INVALID_ARGUMENT;
  return auth_store_record_walk(root, visitor, context);
}

bool auth_backend_slot_write(const uint8_t root[32], uint8_t index,
                             const uint8_t *record, uint16_t length) {
  if (root == NULL || record == NULL) return false;
  if (index >= AUTH_RESIDENT_CAPACITY) return false;
  uint8_t nonce[AUTH_REPLICA_NONCE_SIZE];
  if (!fresh_nonce(nonce)) return false;
  // One call, one authenticated snapshot. The old path needed three --
  // invalidate the tag, write the record, write the tag -- precisely because it
  // had no way to make them atomic.
  auth_result result =
      auth_store_record_write(root, index, record, length, nonce);
  memzero(nonce, sizeof(nonce));
  return result == AUTH_OK;
}

bool auth_backend_slot_delete(const uint8_t root[32], uint8_t index) {
  if (root == NULL) return false;
  if (index >= AUTH_RESIDENT_CAPACITY) return false;
  uint8_t nonce[AUTH_REPLICA_NONCE_SIZE];
  if (!fresh_nonce(nonce)) return false;
  auth_result result = auth_store_record_delete(root, index, nonce);
  memzero(nonce, sizeof(nonce));
  return result == AUTH_OK;
}

auth_result auth_backend_slot_capacity(uint8_t index, uint16_t id_len) {
  if (index >= AUTH_RESIDENT_CAPACITY) return AUTH_INVALID_ARGUMENT;
  return auth_store_resident_capacity(index, id_len);
}
