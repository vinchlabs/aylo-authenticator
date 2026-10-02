#include "../authenticator_backend.h"
#include <string.h>
#include "../replica_records.h"
#include "consteq.h"
#include "hmac.h"
#include "memzero.h"

#ifdef AUTH_TEST_BACKEND
#include "../tests/test_backend.h"

// In-memory double. Deliberately *not* backed by the replica manager: the value
// of the native suite is that it exercises the vault's own logic, and the
// manager already has its own host coverage where a simulated flash medium can
// model power cuts properly. What this double does share with the real backend
// is the root envelope, opened through auth_envelope_open() rather than a
// second copy of the AEAD.
static struct {
  uint8_t record[AUTH_RECORD_SIZE], verifier[32], pin_output[32];
  bool exists, configured;
  uint8_t remaining, entropy;
  size_t rng_bytes, zero_checks;
  auth_test_failure failure;
  // One record per slot. The second dimension used to hold the 40-byte commit
  // tag; the snapshot MAC replaces it, which halves this array.
  uint8_t slots[AUTH_RESIDENT_CAPACITY][AUTH_RECORD_MAX];
  uint16_t slot_lengths[AUTH_RESIDENT_CAPACITY];
} backend;

static bool fail(auth_test_failure point) {
  if (backend.failure != point) return false;
  backend.failure = TEST_NONE;
  return true;
}
void auth_test_reset(void) {
  auth_vault_disconnect();
  memzero(&backend, sizeof(backend));
  backend.entropy = 1;
}
void auth_test_fail(auth_test_failure failure) { backend.failure = failure; }
void auth_test_exhaust(void) { backend.remaining = 0; }
void auth_test_corrupt(size_t offset) {
  if (offset < AUTH_RECORD_SIZE) backend.record[offset] ^= 1;
}
const uint8_t *auth_test_record(void) { return backend.record; }
const uint8_t *auth_test_verifier(void) { return backend.verifier; }
size_t auth_test_rng_bytes(void) { return backend.rng_bytes; }
size_t auth_test_zeroize_checks(void) { return backend.zero_checks; }
bool auth_backend_init(void) { return !fail(TEST_PIN_INIT); }

auth_result auth_backend_root_candidates(
    uint8_t out[AUTH_BACKEND_ROOT_CANDIDATES][AUTH_RECORD_SIZE],
    uint8_t *count) {
  if (count != NULL) *count = 0;
  if (out == NULL || count == NULL) return AUTH_INVALID_ARGUMENT;
  memzero(out, (size_t)AUTH_BACKEND_ROOT_CANDIDATES * AUTH_RECORD_SIZE);
  if (fail(TEST_READ)) return AUTH_ERROR;
  if (!backend.exists) return AUTH_UNPROVISIONED;
  // A single logical store, so there is exactly one candidate. The real backend
  // can return up to three after a torn root commit.
  memcpy(out[0], backend.record, AUTH_RECORD_SIZE);
  *count = 1;
  return AUTH_OK;
}

auth_result auth_backend_unlock(const uint8_t kek[32], uint8_t root_out[32]) {
  if (root_out != NULL) memzero(root_out, 32);
  if (kek == NULL || root_out == NULL) return AUTH_INVALID_ARGUMENT;
  if (fail(TEST_READ)) return AUTH_ERROR;
  if (!backend.exists) return AUTH_UNPROVISIONED;
  // There is no snapshot MAC here, so opening the envelope is the whole unlock.
  // A wrong KEK is a retry, matching what the replica path reports.
  if (!auth_envelope_open(kek, backend.record, root_out)) {
    memzero(root_out, 32);
    // Damage, not a retry: the PIN was already verified to get this KEK.
    return AUTH_ERROR;
  }
  return AUTH_OK;
}

bool auth_backend_write(const uint8_t root[32],
                        const uint8_t record[AUTH_RECORD_SIZE]) {
  // The root keys the snapshot MAC on hardware; this double has no snapshot.
  (void)root;
  if (fail(TEST_WRITE)) return false;
  if (fail(TEST_INTERRUPTED)) {
    // Torn root write: half the envelope lands and the call reports failure.
    backend.exists = true;
    memcpy(backend.record, record, AUTH_RECORD_SIZE / 2);
    return false;
  }
  memcpy(backend.record, record, AUTH_RECORD_SIZE);
  backend.exists = true;
  return true;
}

bool auth_backend_wipe(void) {
  if (fail(TEST_ERASE)) return false;
  memzero(backend.record, sizeof(backend.record));
  memzero(backend.verifier, sizeof(backend.verifier));
  memzero(backend.pin_output, sizeof(backend.pin_output));
  backend.exists = backend.configured = false;
  backend.remaining = 0;
  memzero(backend.slots, sizeof(backend.slots));
  memzero(backend.slot_lengths, sizeof(backend.slot_lengths));
  return true;
}
bool auth_backend_random(uint8_t *out, size_t len) {
  if (fail(TEST_RNG)) return false;
  for (size_t i = 0; i < len; i++) out[i] = backend.entropy++;
  backend.rng_bytes += len;
  return true;
}
bool auth_backend_remaining(uint8_t *remaining) {
  if (fail(TEST_COUNTER)) return false;
  *remaining = backend.remaining;
  return true;
}
auth_result auth_backend_set_pin(const uint8_t verifier[32],
                                 uint8_t output[32]) {
  if (!auth_backend_init()) return AUTH_ERROR;
  if (fail(TEST_PIN_SET)) return AUTH_ERROR;
  memcpy(backend.verifier, verifier, 32);
  hmac_sha256(verifier, 32, (const uint8_t *)"test OPTIGA output", 18,
              backend.pin_output);
  memcpy(output, backend.pin_output, 32);
  backend.configured = true;
  backend.remaining = 8;
  uint8_t rem = 0;
  return auth_backend_remaining(&rem) && rem == 8 ? AUTH_OK : AUTH_ERROR;
}
auth_result auth_backend_verify_pin(const uint8_t verifier[32],
                                    uint8_t output[32]) {
  if (fail(TEST_PIN_VERIFY)) return AUTH_ERROR;
  if (!backend.configured) return AUTH_ERROR;
  if (!backend.remaining) return AUTH_PIN_BLOCKED;
  backend.remaining--;
  if (!consteq(verifier, backend.verifier, 32)) return AUTH_PIN_INVALID;
  memcpy(output, backend.pin_output, 32);
  backend.remaining = 8;
  return AUTH_OK;
}
bool auth_backend_zeroized(const void *buffer, size_t len) {
  backend.zero_checks++;
  const uint8_t *p = buffer;
  uint8_t accumulator = 0;
  for (size_t i = 0; i < len; i++) accumulator |= p[i];
  return accumulator == 0 && !fail(TEST_ZEROIZE);
}

auth_result auth_backend_slot_read(const uint8_t root[32], uint8_t index,
                                   uint8_t *out, uint16_t capacity,
                                   uint16_t *length) {
  (void)root;
  if (length != NULL) *length = 0;
  if (out == NULL || length == NULL) return AUTH_INVALID_ARGUMENT;
  if (index >= AUTH_RESIDENT_CAPACITY || fail(TEST_READ)) return AUTH_ERROR;
  uint16_t len = backend.slot_lengths[index];
  if (!len) return AUTH_UNPROVISIONED;
  if (len > capacity) return AUTH_ERROR;
  memcpy(out, backend.slots[index], len);
  *length = len;
  return AUTH_OK;
}

auth_result auth_backend_slot_walk(const uint8_t root[32],
                                   auth_slot_visitor visitor, void *context) {
  (void)root;
  if (visitor == NULL) return AUTH_INVALID_ARGUMENT;
  // The double has no snapshot to authenticate, so the fault it can inject is
  // the read fault, and it injects it once for the whole walk -- which is
  // exactly the shape the real backend has.
  if (fail(TEST_READ)) return AUTH_ERROR;
  for (uint8_t index = 0; index < AUTH_RESIDENT_CAPACITY; index++) {
    uint16_t len = backend.slot_lengths[index];
    bool keep_going =
        len ? visitor(context, index, AUTH_OK, backend.slots[index], len)
            : visitor(context, index, AUTH_UNPROVISIONED, NULL, 0);
    if (!keep_going) break;
  }
  return AUTH_OK;
}

bool auth_backend_slot_write(const uint8_t root[32], uint8_t index,
                             const uint8_t *record, uint16_t length) {
  (void)root;
  if (record == NULL) return false;
  if (index >= AUTH_RESIDENT_CAPACITY || length == 0 ||
      length > AUTH_RECORD_MAX || fail(TEST_WRITE) || fail(TEST_INTERRUPTED))
    return false;
  memzero(backend.slots[index], AUTH_RECORD_MAX);
  memcpy(backend.slots[index], record, length);
  backend.slot_lengths[index] = length;
  return true;
}

bool auth_backend_slot_delete(const uint8_t root[32], uint8_t index) {
  (void)root;
  if (index >= AUTH_RESIDENT_CAPACITY || fail(TEST_ERASE)) return false;
  memzero(backend.slots[index], AUTH_RECORD_MAX);
  backend.slot_lengths[index] = 0;
  return true;
}

auth_result auth_backend_slot_capacity(uint8_t index, uint16_t id_len) {
  return index < AUTH_RESIDENT_CAPACITY && id_len <= AUTH_RESIDENT_ID_MAX
             ? AUTH_OK
             : AUTH_LIMIT_EXCEEDED;
}
#else
// Ordinary emulator builds never obtain synthetic vault state.
bool auth_backend_init(void) { return false; }
auth_result auth_backend_root_candidates(
    uint8_t out[AUTH_BACKEND_ROOT_CANDIDATES][AUTH_RECORD_SIZE],
    uint8_t *count) {
  (void)out;
  if (count != NULL) *count = 0;
  return AUTH_ERROR;
}
auth_result auth_backend_unlock(const uint8_t kek[32], uint8_t root_out[32]) {
  (void)kek;
  if (root_out != NULL) memzero(root_out, 32);
  return AUTH_ERROR;
}
bool auth_backend_write(const uint8_t root[32],
                        const uint8_t record[AUTH_RECORD_SIZE]) {
  (void)root;
  (void)record;
  return false;
}
bool auth_backend_wipe(void) { return false; }
bool auth_backend_random(uint8_t *out, size_t len) {
  (void)out;
  (void)len;
  return false;
}
bool auth_backend_remaining(uint8_t *remaining) {
  (void)remaining;
  return false;
}
auth_result auth_backend_set_pin(const uint8_t verifier[32],
                                 uint8_t output[32]) {
  (void)verifier;
  (void)output;
  return AUTH_ERROR;
}
auth_result auth_backend_verify_pin(const uint8_t verifier[32],
                                    uint8_t output[32]) {
  (void)verifier;
  (void)output;
  return AUTH_ERROR;
}
bool auth_backend_zeroized(const void *buffer, size_t len) {
  (void)buffer;
  (void)len;
  return true;
}
auth_result auth_backend_slot_read(const uint8_t root[32], uint8_t index,
                                   uint8_t *out, uint16_t capacity,
                                   uint16_t *length) {
  (void)root;
  (void)index;
  (void)out;
  (void)capacity;
  if (length != NULL) *length = 0;
  return AUTH_ERROR;
}
auth_result auth_backend_slot_walk(const uint8_t root[32],
                                   auth_slot_visitor visitor, void *context) {
  (void)root;
  (void)visitor;
  (void)context;
  return AUTH_ERROR;
}
bool auth_backend_slot_write(const uint8_t root[32], uint8_t index,
                             const uint8_t *record, uint16_t length) {
  (void)root;
  (void)index;
  (void)record;
  (void)length;
  return false;
}
bool auth_backend_slot_delete(const uint8_t root[32], uint8_t index) {
  (void)root;
  (void)index;
  return false;
}
auth_result auth_backend_slot_capacity(uint8_t index, uint16_t id_len) {
  (void)index;
  (void)id_len;
  return AUTH_ERROR;
}
#endif
