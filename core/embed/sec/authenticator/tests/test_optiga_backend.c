// Compile the actual hardware adapter against existing OPTIGA headers.
//
// Only external hardware and storage calls are doubled; no legacy PIN symbols
// exist. The OPTIGA half of this fixture is unchanged, because the
// secure-element protocol did not change.
//
// The storage half did. The previous version doubled NORCOW at the key level
// and asserted a protocol that no longer exists: a one-byte root tombstone,
// deletion of every key in the reserved 0xff00..0xfffe range, and the survival
// of another application's key 0x8101 through a wipe. None of that has an
// analogue now -- a wipe erases three whole areas that belong exclusively to
// this vault, so there is no foreign key in range to preserve and no per-key
// ordering to get right. That coverage moved to tests/test_replica_io.c, which
// asserts the wipe touches exactly those three areas and all eight pages of
// each.
//
// What this fixture still owns, and what the doubles below exist for, is the
// part that spans both pieces of hardware: the persistent PIN counter must be
// destroyed *before* storage is touched, so that a power cut between the two
// leaves every surviving replica cryptographically useless rather than merely
// orphaned. That ordering is the reason a wipe cannot simply erase and hope.
#define auth_backend_init hw_init
#define auth_backend_root_candidates hw_candidates
#define auth_backend_unlock hw_unlock
#define auth_backend_write hw_write
#define auth_backend_wipe hw_wipe
#define auth_backend_random hw_random
#define auth_backend_remaining hw_remaining
#define auth_backend_set_pin hw_set
#define auth_backend_verify_pin hw_verify
#define auth_backend_zeroized hw_zeroized
#define auth_backend_slot_read hw_slot_read
#define auth_backend_slot_write hw_slot_write
#define auth_backend_slot_delete hw_slot_delete
#define auth_backend_slot_capacity hw_slot_capacity
#define auth_store_open hw_store_open
#define auth_store_state hw_store_state
#define auth_store_root_candidates hw_store_candidates
#define auth_store_unlock hw_store_unlock
#define auth_store_provision hw_store_provision
#define auth_store_commit_root hw_store_commit_root
#define auth_store_record_read hw_store_record_read
#define auth_store_record_write hw_store_record_write
#define auth_store_record_delete hw_store_record_delete
#define auth_store_repair hw_store_repair
#define auth_store_resident_capacity hw_store_resident_capacity
#define auth_store_wipe hw_store_wipe
#define optiga_pin_init hw_optiga_pin_init
#define optiga_pin_stretch_cmac_ecdh hw_optiga_pin_stretch_cmac_ecdh
#define optiga_pin_set hw_optiga_pin_set
#define optiga_pin_verify hw_optiga_pin_verify
#define optiga_pin_get_rem hw_optiga_pin_get_rem
#define optiga_pin_decrease_rem hw_optiga_pin_decrease_rem
#define rng_fill_buffer_strong hw_rng_fill_buffer_strong
#include <assert.h>
#include "../stm32u5/authenticator_backend.c"

static uint32_t rem;
static uint8_t configured[32];
static int injected, set_calls, init_calls;

// ---------------------------------------------------------------------------
// OPTIGA doubles, unchanged
// ---------------------------------------------------------------------------

bool optiga_pin_init(optiga_ui_progress_t cb) {
  assert(cb == NULL);
  init_calls++;
  return injected != 1;
}
bool optiga_pin_stretch_cmac_ecdh(optiga_ui_progress_t cb, uint8_t pin[32]) {
  assert(cb == NULL);
  if (injected == 2) return false;
  for (size_t i = 0; i < 32; i++) pin[i] ^= 0xaa;
  return true;
}
bool optiga_pin_set(optiga_ui_progress_t cb,
                    uint8_t slots[STRETCHED_PIN_COUNT][32], uint8_t reset[32]) {
  assert(cb == NULL);
  set_calls++;
  if (injected == 3) return false;
  memcpy(configured, slots[0], 32);
  for (size_t i = 0; i < 32; i++) {
    slots[0][i] ^= 0x55;
    reset[i] = 0xcc;
  }
  rem = PIN_MAX_TRIES;
  return true;
}
optiga_pin_result optiga_pin_verify(optiga_ui_progress_t cb, uint8_t index,
                                    uint8_t pin[32]) {
  assert(cb == NULL && index == 0);
  if (injected == 4) return OPTIGA_PIN_ERROR;
  if (!rem) return OPTIGA_PIN_COUNTER_EXCEEDED;
  rem--;
  if (memcmp(pin, configured, 32) != 0) return OPTIGA_PIN_INVALID;
  for (size_t i = 0; i < 32; i++) pin[i] ^= 0x55;
  rem = PIN_MAX_TRIES;
  return OPTIGA_PIN_SUCCESS;
}
bool optiga_pin_get_rem(uint32_t *value) {
  if (injected == 5) return false;
  *value = rem;
  return true;
}
bool optiga_pin_decrease_rem(uint32_t count) {
  assert(count <= rem);
  if (injected == 6) return false;
  if (injected != 7) rem -= count;
  return true;
}

void rng_fill_buffer_strong(void *buffer, size_t size) {
  memset(buffer, 0x5a, size);
}

// ---------------------------------------------------------------------------
// Replica storage double
// ---------------------------------------------------------------------------

// The whole storage model reduces to a classification plus "was it erased", so
// that is all the double carries.
static auth_result store_state = AUTH_UNPROVISIONED;
static bool fail_wipe;
static bool erased;
// The counter value observed at the moment storage was erased. This is what
// pins the ordering: it must already be zero.
static uint32_t rem_at_erase = 0xffffffff;

auth_result auth_store_open(bool provision) {
  (void)provision;
  return store_state;
}
auth_result auth_store_state(void) { return store_state; }

auth_result auth_store_root_candidates(
    uint8_t out[AUTH_REPLICA_COUNT][AUTH_RECORD_SIZE], uint8_t *count) {
  *count = 0;
  memset(out, 0, (size_t)AUTH_REPLICA_COUNT * AUTH_RECORD_SIZE);
  if (store_state != AUTH_OK) return store_state;
  out[0][0] = 0xa1;
  out[0][1] = 1;
  *count = 1;
  return AUTH_OK;
}
auth_result auth_store_unlock(const uint8_t kek[32], uint8_t root_out[32]) {
  (void)kek;
  memset(root_out, 0, 32);
  return store_state == AUTH_OK ? AUTH_OK : store_state;
}
auth_result auth_store_provision(const uint8_t root[32],
                                 const uint8_t envelope[AUTH_RECORD_SIZE],
                                 const uint8_t nonce[AUTH_REPLICA_NONCE_SIZE]) {
  (void)root;
  (void)envelope;
  (void)nonce;
  if (store_state != AUTH_UNPROVISIONED) return AUTH_DENIED;
  store_state = AUTH_OK;
  return AUTH_OK;
}
auth_result auth_store_commit_root(
    const uint8_t root[32], const uint8_t envelope[AUTH_RECORD_SIZE],
    const uint8_t nonce[AUTH_REPLICA_NONCE_SIZE]) {
  (void)root;
  (void)envelope;
  (void)nonce;
  return store_state == AUTH_OK ? AUTH_OK : store_state;
}
auth_result auth_store_record_read(const uint8_t root[32], uint8_t index,
                                   uint8_t *out, uint16_t capacity,
                                   uint16_t *length) {
  (void)root;
  (void)index;
  (void)out;
  (void)capacity;
  *length = 0;
  return AUTH_UNPROVISIONED;
}
auth_result auth_store_record_write(
    const uint8_t root[32], uint8_t index, const uint8_t *record,
    uint16_t length, const uint8_t nonce[AUTH_REPLICA_NONCE_SIZE]) {
  (void)root;
  (void)index;
  (void)record;
  (void)length;
  (void)nonce;
  return AUTH_OK;
}
auth_result auth_store_record_delete(
    const uint8_t root[32], uint8_t index,
    const uint8_t nonce[AUTH_REPLICA_NONCE_SIZE]) {
  (void)root;
  (void)index;
  (void)nonce;
  return AUTH_OK;
}
auth_result auth_store_repair(const uint8_t root[32]) {
  (void)root;
  return AUTH_OK;
}
auth_result auth_store_resident_capacity(uint8_t index, uint16_t id_len) {
  (void)index;
  (void)id_len;
  return AUTH_OK;
}
auth_result auth_store_wipe(void) {
  rem_at_erase = rem;
  if (fail_wipe) return AUTH_ERROR;
  erased = true;
  store_state = AUTH_UNPROVISIONED;
  return AUTH_OK;
}

static void reset_store(auth_result state) {
  store_state = state;
  fail_wipe = false;
  erased = false;
  rem_at_erase = 0xffffffff;
}

void test_optiga_backend(void) {
  uint8_t pin[32] = {1}, out[32] = {0}, expected[32] = {0};
  injected = 0;
  set_calls = init_calls = 0;
  reset_store(AUTH_UNPROVISIONED);

  assert(hw_init());
  assert(init_calls == 0 && set_calls == 0);
  assert(hw_set(pin, out) == AUTH_OK && rem == 8 && set_calls == 1);
  memcpy(expected, out, 32);
  assert(hw_init());  // Cold reconnect preserves previously provisioned keys.
  assert(init_calls == 1 && set_calls == 1);
  assert(hw_verify(pin, out) == AUTH_OK && rem == 8 && set_calls == 1);
  assert(memcmp(out, expected, 32) == 0);
  pin[31] ^= 1;
  assert(hw_verify(pin, out) == AUTH_PIN_INVALID && rem == 7);
  for (size_t i = 0; i < 32; i++) assert(out[i] == 0);
  pin[31] ^= 1;
  for (int fault = 1; fault <= 7; fault++) {
    injected = fault;
    if (fault == 4) continue;
    memset(out, 0xcc, 32);
    assert(hw_set(pin, out) == AUTH_ERROR);
    for (size_t i = 0; i < 32; i++) assert(out[i] == 0);
  }
  injected = 0;
  assert(hw_set(pin, out) == AUTH_OK);
  for (int fault = 2; fault <= 7; fault++) {
    if (fault == 3) continue;
    injected = fault;
    assert(hw_verify(pin, out) == AUTH_ERROR);
    for (size_t i = 0; i < 32; i++) assert(out[i] == 0);
  }
  injected = 0;

  // The ordering that matters. A wipe of a provisioned device must have already
  // exhausted the persistent counter by the time storage is erased, so that a
  // power cut in between leaves the surviving replicas undecryptable.
  reset_store(AUTH_OK);
  rem = 8;
  assert(hw_wipe());
  assert(erased && rem == 0);
  assert(rem_at_erase == 0);
  assert(hw_store_state() == AUTH_UNPROVISIONED);

  // An erase that fails after the counter is gone leaves the device unusable
  // but not exposed: the old root can never be recovered, and nothing may be
  // provisioned over it while it still classifies as holding a snapshot.
  reset_store(AUTH_OK);
  rem = 8;
  fail_wipe = true;
  assert(!hw_wipe());
  assert(!erased && rem == 0 && rem_at_erase == 0);
  uint8_t candidates[AUTH_BACKEND_ROOT_CANDIDATES][AUTH_RECORD_SIZE];
  uint8_t count = 0xff;
  // reconcile() sees a snapshot with an exhausted counter and finishes the wipe
  // rather than handing back a root or re-provisioning the secure element. The
  // property is that no OPTIGA provisioning happens, so it is asserted as a
  // delta: absolute call counts here would only be a transcription of whatever
  // the fault loops above happened to do.
  int init_before = init_calls, set_before = set_calls;
  fail_wipe = false;
  assert(hw_candidates(candidates, &count) == AUTH_UNPROVISIONED);
  assert(count == 0 && erased);
  assert(init_calls == init_before && set_calls == set_before);

  // Reconnect resumes the same way, idempotently.
  reset_store(AUTH_OK);
  rem = 0;
  assert(hw_init());
  assert(erased && hw_store_state() == AUTH_UNPROVISIONED);

  // Already ours and empty: a wipe is idempotent and still makes sure the
  // counter cannot authorise anything.
  reset_store(AUTH_UNPROVISIONED);
  rem = 8;
  assert(hw_wipe());
  assert(rem == 0);

  // Data that is not ours is never erased, and the reason survives.
  reset_store(AUTH_MIGRATION_REQUIRED);
  rem = 8;
  assert(!hw_wipe());
  assert(!erased && rem == 8);
  assert(hw_candidates(candidates, &count) == AUTH_MIGRATION_REQUIRED);
  assert(count == 0);
  assert(hw_unlock(configured, out) == AUTH_MIGRATION_REQUIRED);
  // Initialization still succeeds so the vault can report the reason.
  assert(hw_init());
  assert(!erased && rem == 8);

  // Media we could not read is treated the same way: never erased on the
  // strength of a failed read.
  reset_store(AUTH_ERROR);
  rem = 8;
  assert(!hw_wipe());
  assert(!erased && rem == 8);
  assert(!hw_init());
}
