// Credentials end to end over the real replica stack.
//
// Everything from auth_vault_* down to the snapshot codec is the production
// path: authenticator.c, the stm32u5 backend, the storage facade,
// replica_records, replica_store and replica_format. Only three things are
// doubled, and none of them is storage logic: the secure element, the hardware
// RNG, and auth_replica_io_t3t1(), which here addresses a RAM medium instead of
// flash.
//
// Deliberate scope change from the NORCOW version of this fixture. It used to
// cut power at flash_area_write_block/flash_area_erase boundaries and count
// storage operations. That coverage did not survive the move, and did not need
// to:
//
//   * writing a resident record is now a single call, so there is no multi-step
//     sequence at this level whose intermediate states are worth interrupting
//     -- atomicity moved into the snapshot commit;
//   * that commit's power-cut behaviour is already proven exhaustively one
//   layer
//     down, in test_replica_power_cut.c: 7,384 scenarios including every one of
//     the 3,623 boundaries of a replace, with zero unavailable outcomes.
//
// Duplicating it here through a narrower interface would add code and subtract
// signal. What this fixture owns instead is the thing the layer below cannot
// see: that *credentials* -- creation, permissions, replacement, deletion,
// enumeration of 100 slots, and the survival of untouched slots -- travel the
// real stack correctly.
//
// Two NORCOW-specific scenarios are gone with the model. "unrelated key 0x8101
// survives" had no analogue: the three replica areas belong exclusively to this
// vault, so there is no foreign key in range to preserve, and
// test_replica_io.c asserts the wipe touches exactly those areas. "storage full
// returns a precise limit" became an oversize-record check, because slots are
// fixed-capacity and cannot be crowded out by a neighbour.

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sec/authenticator.h>

#include "../authenticator_replica_io.h"
#include "../replica_records.h"
#include "ecdsa.h"
#include "memzero.h"
#include "nist256p1.h"
#include "sha2.h"

// ---------------------------------------------------------------------------
// Crypto-library doubles
// ---------------------------------------------------------------------------

uint32_t random32(void) { return 0x12345678; }
void random_buffer(uint8_t *out, size_t len) { memset(out, 0x23, len); }
void __assert_impl(const char *file, int line) {
  fprintf(stderr, "assert %s:%d\n", file, line);
  abort();
}

// ---------------------------------------------------------------------------
// Secure element double
// ---------------------------------------------------------------------------

#include <sec/optiga.h>

static uint32_t optiga_rem;
static uint8_t optiga_configured[32];

bool optiga_pin_init(optiga_ui_progress_t cb) {
  (void)cb;
  return true;
}
bool optiga_pin_stretch_cmac_ecdh(optiga_ui_progress_t cb, uint8_t pin[32]) {
  (void)cb;
  for (size_t i = 0; i < 32; i++) pin[i] ^= 0xaa;
  return true;
}
bool optiga_pin_set(optiga_ui_progress_t cb,
                    uint8_t slots[STRETCHED_PIN_COUNT][32], uint8_t reset[32]) {
  (void)cb;
  memcpy(optiga_configured, slots[0], 32);
  for (size_t i = 0; i < 32; i++) {
    slots[0][i] ^= 0x55;
    reset[i] = 0xcc;
  }
  optiga_rem = PIN_MAX_TRIES;
  return true;
}
optiga_pin_result optiga_pin_verify(optiga_ui_progress_t cb, uint8_t index,
                                    uint8_t pin[32]) {
  (void)cb;
  (void)index;
  if (!optiga_rem) return OPTIGA_PIN_COUNTER_EXCEEDED;
  optiga_rem--;
  if (memcmp(pin, optiga_configured, 32) != 0) return OPTIGA_PIN_INVALID;
  for (size_t i = 0; i < 32; i++) pin[i] ^= 0x55;
  optiga_rem = PIN_MAX_TRIES;
  return OPTIGA_PIN_SUCCESS;
}
bool optiga_pin_get_rem(uint32_t *value) {
  *value = optiga_rem;
  return true;
}
bool optiga_pin_decrease_rem(uint32_t count) {
  assert(count <= optiga_rem);
  optiga_rem -= count;
  return true;
}

// ---------------------------------------------------------------------------
// Hardware RNG double. Deterministic so a failure is reproducible.
// ---------------------------------------------------------------------------

static uint32_t rng_state = 0xc0ffee01u;
void rng_fill_buffer_strong(void *buffer, size_t size) {
  uint8_t *out = buffer;
  for (size_t i = 0; i < size; i++) {
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 17;
    rng_state ^= rng_state << 5;
    out[i] = (uint8_t)(rng_state >> 11);
  }
}

// ---------------------------------------------------------------------------
// RAM medium standing in for the three replica areas, with the real STM32U5
// constraints: 16-byte program granularity, 8 KiB erase, and programming that
// only clears bits so a double write is caught rather than merged.
// ---------------------------------------------------------------------------

#define AREA AUTH_REPLICA_AREA_SIZE
#define PAGE AUTH_REPLICA_PAGE_SIZE
#define LINE AUTH_REPLICA_LINE_SIZE

static uint8_t medium[AUTH_REPLICA_COUNT][AREA];
static uint8_t medium_saved[AUTH_REPLICA_COUNT][AREA];

// Set by the "unsupported" scenario to model a reader that refuses every read.
// Two real situations have that shape: a platform whose checked reader cannot
// read the replica areas at all, and a device whose three replicas have all
// been quarantined by earlier boots that died on them. The reader answers
// FLASH_CHECKED_UNSUPPORTED and the production adapter maps exactly that code
// to AUTH_REPLICA_IO_FAILED, so this flag reproduces the real path rather than
// inventing a failure mode.
//
// Writes and erases stay functional, because on real hardware they are: only
// reads are refused. That is what makes "nothing was erased" an assertion about
// the vault's behaviour rather than about this double's.
static bool io_reads_fail;
static unsigned io_writes, io_erases;

static auth_replica_io_result io_read(void *context, uint8_t replica,
                                      uint32_t offset, uint8_t *out,
                                      uint32_t len) {
  (void)context;
  if (out == NULL || len == 0) return AUTH_REPLICA_IO_RANGE;
  memzero(out, len);
  if (replica >= AUTH_REPLICA_COUNT) return AUTH_REPLICA_IO_RANGE;
  if (offset > AREA || len > AREA - offset) return AUTH_REPLICA_IO_RANGE;
  // Ordered as the adapter orders it: a malformed request is still RANGE, so a
  // refused load cannot be mistaken for one.
  if (io_reads_fail) return AUTH_REPLICA_IO_FAILED;
  memcpy(out, &medium[replica][offset], len);
  return AUTH_REPLICA_IO_OK;
}

static bool io_write_line(void *context, uint8_t replica, uint32_t offset,
                          const uint8_t line[LINE]) {
  (void)context;
  if (replica >= AUTH_REPLICA_COUNT) return false;
  if (offset % LINE != 0 || offset > AREA - LINE) return false;
  io_writes++;
  uint8_t *target = &medium[replica][offset];
  for (uint32_t i = 0; i < LINE; i++) {
    if (target[i] != 0xff && target[i] != line[i]) return false;
    target[i] &= line[i];
  }
  return true;
}

static bool io_erase_page(void *context, uint8_t replica, uint32_t offset) {
  (void)context;
  if (replica >= AUTH_REPLICA_COUNT) return false;
  if (offset % PAGE != 0 || offset > AREA - PAGE) return false;
  io_erases++;
  memset(&medium[replica][offset], 0xff, PAGE);
  return true;
}

// The production storage facade calls this; here it points at the RAM medium.
const auth_replica_io *auth_replica_io_t3t1(void) {
  static const auth_replica_io io = {
      .read = io_read,
      .write_line = io_write_line,
      .erase_page = io_erase_page,
      .context = NULL,
  };
  return &io;
}

static void medium_blank(void) {
  memset(medium, 0xff, sizeof(medium));
  optiga_rem = 0;
  memzero(optiga_configured, sizeof(optiga_configured));
}
static void medium_save(void) { memcpy(medium_saved, medium, sizeof(medium)); }
static void assert_medium_unchanged(void) {
  assert(memcmp(medium_saved, medium, sizeof(medium)) == 0);
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

static uint8_t rp_hash[32], pin16[16] = {1};
static const uint8_t meta[] = {1,   1,   3,   0,   11,  1,   0,
                               0,   0,   'e', 'x', 'a', 'm', 'p',
                               'l', 'e', '.', 'c', 'o', 'm', 1};
static auth_credential_public first, second, readback;
extern bool auth_test_record_generation(uint8_t index, uint32_t *out);

#include "test_pin_protocol_host.h"

static void unlock_permission(uint8_t permission, bool bound) {
  uint8_t public_key[65], peer[65], scalar[32] = {0}, encrypted[48];
  uint8_t blob[16] = {0};
  size_t n;
  scalar[31] = 1;
  assert(ecdsa_get_public_key65(&nist256p1, scalar, peer) == 0);
  assert(auth_vault_key_agreement(public_key, 65) == AUTH_OK);
  // The PIN hash reaches the vault encrypted under the shared secret, so the
  // fixture plays the platform side of ClientPIN here.
  pin_protocol_host_encrypt(scalar, public_key, 1, pin16, 16, 0, blob);
  assert(auth_vault_issue_token(blob, sizeof(blob), 1, permission,
                                bound ? rp_hash : NULL, bound ? 32 : 0, peer,
                                65, encrypted, 48, &n) == AUTH_OK);
}
static void unlock(void) { unlock_permission(7, true); }

// Like unlock_permission with bound=false, but hands back the result instead of
// insisting on it: for some permissions the refusal is the point.
static auth_result issue_unbound(uint8_t permission) {
  uint8_t public_key[65], peer[65], scalar[32] = {0}, encrypted[48];
  uint8_t blob[16] = {0};
  size_t n;
  scalar[31] = 1;
  assert(ecdsa_get_public_key65(&nist256p1, scalar, peer) == 0);
  assert(auth_vault_key_agreement(public_key, 65) == AUTH_OK);
  pin_protocol_host_encrypt(scalar, public_key, 1, pin16, 16, 0, blob);
  return auth_vault_issue_token(blob, sizeof(blob), 1, permission, NULL, 0, peer,
                                65, encrypted, 48, &n);
}

static void prepare(void) {
  auth_vault_disconnect();
  medium_blank();
  assert(auth_vault_init() == AUTH_OK);
  assert(auth_vault_provision(pin16, 16) == AUTH_OK);
  unlock();
  assert(auth_credential_create(rp_hash, -7, meta, sizeof(meta), &first) ==
         AUTH_OK);
  uint8_t m[sizeof(meta)];
  memcpy(m, meta, sizeof(meta));
  m[sizeof(m) - 1] = 2;
  assert(auth_credential_create(rp_hash, -8, m, sizeof(m), &second) == AUTH_OK);
  assert(auth_resident_set(0, first.id, first.id_len, rp_hash) == AUTH_OK);
  assert(auth_resident_set(99, second.id, second.id_len, rp_hash) == AUTH_OK);
}

// Exactly two slots are occupied, at the ends of the range, and their ids are
// distinct. Replaces the old "unrelated NORCOW key survived" check: what has to
// survive now is every slot the operation did not name.
static void enumeration(void) {
  unsigned count = 0;
  uint8_t ids[2][AUTH_CREDENTIAL_ID_MAX];
  size_t lengths[2];
  for (uint8_t i = 0; i < 100; i++) {
    auth_result result = auth_resident_get(i, &readback);
    if (result == AUTH_UNPROVISIONED) continue;
    assert(result == AUTH_OK && count < 2);
    for (unsigned j = 0; j < count; j++)
      assert(lengths[j] != readback.id_len ||
             memcmp(ids[j], readback.id, readback.id_len) != 0);
    lengths[count] = readback.id_len;
    memcpy(ids[count++], readback.id, readback.id_len);
    assert(i == 0 || i == 99);
  }
  assert(count == 2);
}

int main(int argc, char **argv) {
  assert(argc == 2);
  sha256_Raw((const uint8_t *)"example.com", 11, rp_hash);
  prepare();

  if (!strcmp(argv[1], "records")) {
    enumeration();
    assert(auth_resident_get(0, &readback) == AUTH_OK &&
           readback.id_len == first.id_len &&
           memcmp(readback.id, first.id, first.id_len) == 0);
    assert(auth_resident_get(99, &readback) == AUTH_OK &&
           readback.id_len == second.id_len &&
           memcmp(readback.id, second.id, second.id_len) == 0);
    // A fresh session over the same medium sees the same credentials, which is
    // what proves they were committed rather than merely cached.
    auth_vault_disconnect();
    assert(auth_vault_init() == AUTH_OK);
    unlock();
    enumeration();
    puts("real-storage credential records: PASS");
    return 0;
  }

  if (!strcmp(argv[1], "choose")) {
    // prepare() leaves slots 0 and 99 occupied, so the first free slot is 1.
    uint8_t m[sizeof(meta)];
    memcpy(m, meta, sizeof(meta));
    m[sizeof(m) - 1] = 3;
    auth_credential_public third;
    assert(auth_credential_create(rp_hash, -7, m, sizeof(m), &third) ==
           AUTH_OK);

    // The vault chooses, and lands in the first gap.
    assert(auth_resident_set(AUTH_RESIDENT_ANY, third.id, third.id_len,
                             rp_hash) == AUTH_OK);
    assert(auth_resident_get(1, &readback) == AUTH_OK &&
           readback.id_len == third.id_len &&
           memcmp(readback.id, third.id, third.id_len) == 0);

    // The same identifier a second time is refused rather than stored twice,
    // wherever it is offered.
    assert(auth_resident_set(AUTH_RESIDENT_ANY, third.id, third.id_len,
                             rp_hash) == AUTH_DENIED);
    // And here is the reason the caller must not search: that refusal left
    // through finish(), which invalidated the session, so nothing is authorized
    // any more. A search would have had exactly one attempt.
    assert(auth_resident_get(0, &readback) == AUTH_DENIED);
    unlock();

    // Fill every remaining slot, then ask once more. Full is its own result,
    // not a denial and not a record that is too large, because a platform acts
    // differently on each of the three.
    for (uint8_t i = 2; i < 99; i++) {
      uint8_t filler[sizeof(meta)];
      memcpy(filler, meta, sizeof(filler));
      filler[sizeof(filler) - 1] = (uint8_t)(10 + i);
      auth_credential_public extra;
      assert(auth_credential_create(rp_hash, -7, filler, sizeof(filler),
                                    &extra) == AUTH_OK);
      assert(auth_resident_set(AUTH_RESIDENT_ANY, extra.id, extra.id_len,
                               rp_hash) == AUTH_OK);
    }
    uint8_t last[sizeof(meta)];
    memcpy(last, meta, sizeof(last));
    last[sizeof(last) - 1] = 200;
    auth_credential_public overflow;
    assert(auth_credential_create(rp_hash, -7, last, sizeof(last), &overflow) ==
           AUTH_OK);
    assert(auth_resident_set(AUTH_RESIDENT_ANY, overflow.id, overflow.id_len,
                             rp_hash) == AUTH_STORE_FULL);

    // An index past the sentinel is still an invalid index.
    unlock();
    assert(auth_resident_set(AUTH_RESIDENT_ANY + 1, overflow.id,
                             overflow.id_len,
                             rp_hash) == AUTH_INVALID_ARGUMENT);
    puts("resident slot choice: PASS");
    return 0;
  }
  if (!strcmp(argv[1], "replace")) {
    // A third, distinct credential. Slot 0 cannot be replaced with second.id,
    // because slot 99 already holds it and duplicates across slots are refused
    // -- which is itself asserted below.
    auth_credential_public third;
    uint8_t m[sizeof(meta)];
    memcpy(m, meta, sizeof(meta));
    m[sizeof(m) - 1] = 3;
    assert(auth_credential_create(rp_hash, -7, m, sizeof(m), &third) ==
           AUTH_OK);

    medium_save();
    assert(auth_resident_set(0, third.id, third.id_len, rp_hash) == AUTH_OK);
    // The medium did change -- a replacement that wrote nothing would be a
    // silent failure -- and the named slot now holds the new credential.
    assert(memcmp(medium_saved, medium, sizeof(medium)) != 0);
    assert(auth_resident_get(0, &readback) == AUTH_OK &&
           readback.id_len == third.id_len &&
           memcmp(readback.id, third.id, third.id_len) == 0);
    // The slot that was not named is untouched.
    assert(auth_resident_get(99, &readback) == AUTH_OK &&
           readback.id_len == second.id_len &&
           memcmp(readback.id, second.id, second.id_len) == 0);
    // And a credential cannot end up in two slots at once.
    assert(auth_resident_set(1, third.id, third.id_len, rp_hash) ==
           AUTH_DENIED);
    assert(auth_resident_set(1, second.id, second.id_len, rp_hash) ==
           AUTH_DENIED);
    // Survives a reconnect, so the replacement was committed.
    auth_vault_disconnect();
    assert(auth_vault_init() == AUTH_OK);
    unlock();
    assert(auth_resident_get(0, &readback) == AUTH_OK &&
           readback.id_len == third.id_len &&
           memcmp(readback.id, third.id, third.id_len) == 0);
    puts("real-storage credential replacement: PASS");
    return 0;
  }

  if (!strcmp(argv[1], "delete")) {
    assert(auth_resident_delete(0) == AUTH_OK);
    assert(auth_resident_get(0, &readback) == AUTH_UNPROVISIONED);
    // The slot that was not named survives, across a reconnect too.
    assert(auth_resident_get(99, &readback) == AUTH_OK);
    auth_vault_disconnect();
    assert(auth_vault_init() == AUTH_OK);
    unlock();
    assert(auth_resident_get(0, &readback) == AUTH_UNPROVISIONED);
    assert(auth_resident_get(99, &readback) == AUTH_OK &&
           readback.id_len == second.id_len &&
           memcmp(readback.id, second.id, second.id_len) == 0);
    puts("real-storage credential deletion: PASS");
    return 0;
  }

  if (!strcmp(argv[1], "wipe")) {
    assert(auth_vault_wipe() == AUTH_OK);
    // Nothing is readable, and the device is provisionable again rather than
    // stuck demanding migration.
    assert(auth_vault_init() == AUTH_OK);
    auth_status status = auth_vault_status();
    assert(status.state == AUTH_UNPROVISIONED);
    assert(auth_vault_provision(pin16, 16) == AUTH_OK);
    unlock();
    for (uint8_t i = 0; i < 100; i++)
      assert(auth_resident_get(i, &readback) == AUTH_UNPROVISIONED);
    puts("real-storage wipe and reprovision: PASS");
    return 0;
  }

  if (!strcmp(argv[1], "oversize")) {
    // Slots are fixed-capacity, so the old "storage full" case cannot happen.
    // What can is a credential too large for a slot, and it must be refused
    // with a precise result and without touching the medium. 9 header + 253 rp
    // + 64 + 100 + 22 + 12 = 460 metadata bytes, which makes a 528-byte
    // credential id. The resident cap is 516, so this is genuinely over it. The
    // NORCOW version used 448 metadata bytes, which yields exactly 516 -- the
    // limit, not past it -- and only failed back then because the surrounding
    // storage was artificially full.
    uint8_t m[460] = {1, 1, 3, 0, 253, 64, 100, 22, 12};
    memset(m + 9, 'r', 253);
    memset(m + 262, 'u', 64);
    memset(m + 326, 'n', 134);
    sha256_Raw(m + 9, 253, rp_hash);
    unlock();
    assert(auth_credential_create(rp_hash, -7, m, sizeof(m), &readback) ==
           AUTH_OK);
    medium_save();
    assert(auth_resident_set(1, readback.id, readback.id_len, rp_hash) ==
           AUTH_LIMIT_EXCEEDED);
    assert_medium_unchanged();
    puts("oversize credential returns a precise limit without mutation: PASS");
    return 0;
  }

  if (!strcmp(argv[1], "unsupported")) {
    // The clean recovery gate. An ordinary hardware image refuses every checked
    // load, because ECC double-error containment is unproven until the hardware
    // probe passes. The situation that matters is not a blank device -- that is
    // covered one layer down in test_replica_io.c -- but this one: a device
    // that already holds a populated vault, met by an image that cannot read
    // it.
    //
    // The destructive mistake would be to conclude "blank" and provision over
    // it, or to erase in the name of recovery. Neither may happen, and the
    // refusal must cost nothing that cannot be given back.
    medium_save();
    uint32_t rem_before = optiga_rem;
    io_writes = io_erases = 0;
    io_reads_fail = true;

    auth_vault_disconnect();
    assert(auth_vault_init() == AUTH_ERROR);
    // Not merely "not OK": specifically not the answer that authorises
    // provisioning. Unreadable and unprovisioned must not be the same state.
    auth_status status = auth_vault_status();
    assert(status.state == AUTH_ERROR);
    assert(status.state != AUTH_UNPROVISIONED);
    assert(status.state != AUTH_MIGRATION_REQUIRED);
    assert(auth_vault_provision(pin16, 16) == AUTH_ERROR);

    // No session can be opened. Whether the refusal lands in key agreement or
    // in token issue does not matter; what matters is that no token exists, so
    // no resident operation has a permission to run under.
    uint8_t public_key[65], peer[65], scalar[32] = {0}, encrypted[48];
    size_t n = 0;
    scalar[31] = 1;
    assert(ecdsa_get_public_key65(&nist256p1, scalar, peer) == 0);
    // Encrypting needs a public key to agree against, so the ciphertext is only
    // built when key agreement got that far. Either refusal proves the point.
    uint8_t blob[16] = {0};
    const bool agreed = auth_vault_key_agreement(public_key, 65) == AUTH_OK;
    if (agreed)
      pin_protocol_host_encrypt(scalar, public_key, 1, pin16, 16, 0, blob);
    bool issued = agreed && auth_vault_issue_token(
                                blob, sizeof(blob), 1, 7, rp_hash, 32, peer, 65,
                                encrypted, 48, &n) == AUTH_OK;
    assert(!issued);
    assert(auth_resident_get(0, &readback) != AUTH_OK);
    assert(auth_resident_set(1, first.id, first.id_len, rp_hash) != AUTH_OK);
    assert(auth_resident_delete(0) != AUTH_OK);

    // Wiping is refused as well, and refused without erasing. "Recover by
    // erasing what we could not read" is the one outcome this design must never
    // produce: the media may hold a perfectly good vault that only this image
    // cannot read. The consequence is deliberate and worth naming -- such a
    // device cannot be reset by this image either, only by a validated one.
    assert(auth_vault_wipe() == AUTH_ERROR);

    // Nothing was written or erased. Asserted two ways on purpose: the counters
    // catch an attempt even if it happened to be a no-op, the bytes catch a
    // write the medium accepted.
    assert(io_writes == 0 && io_erases == 0);
    assert_medium_unchanged();
    // And no PIN try was spent, by any of the calls above. A device we cannot
    // read is damaged, not wrongly-PINned, so eight of these must not add up to
    // a wipe -- and a refused wipe must not have destroyed the counter either.
    assert(optiga_rem == rem_before);

    // The refusal was conservative rather than a dead end: the same media, read
    // by an image whose checked reader works, still holds both credentials.
    io_reads_fail = false;
    auth_vault_disconnect();
    assert(auth_vault_init() == AUTH_OK);
    unlock();
    enumeration();
    assert(auth_resident_get(0, &readback) == AUTH_OK &&
           readback.id_len == first.id_len &&
           memcmp(readback.id, first.id, first.id_len) == 0);
    assert(auth_resident_get(99, &readback) == AUTH_OK &&
           readback.id_len == second.id_len &&
           memcmp(readback.id, second.id, second.id_len) == 0);
    assert_medium_unchanged();
    puts("a reader refusing every read erases nothing: PASS");
    return 0;
  }

  if (!strcmp(argv[1], "permissions")) {
    assert(auth_resident_delete(0) == AUTH_OK);
    assert(auth_resident_delete(99) == AUTH_OK);
    unlock_permission(1, true);
    assert(auth_resident_set(0, first.id, first.id_len, rp_hash) == AUTH_OK);
    uint8_t old_rp[32], other_meta[sizeof(meta)];
    memcpy(old_rp, rp_hash, 32);
    memcpy(other_meta, meta, sizeof(meta));
    other_meta[9] = 'a';
    sha256_Raw(other_meta + 9, 11, rp_hash);
    unlock_permission(1, true);
    assert(auth_credential_create(rp_hash, -8, other_meta, sizeof(other_meta),
                                  &second) == AUTH_OK);
    assert(auth_resident_set(1, second.id, second.id_len, rp_hash) == AUTH_OK);
    assert(auth_resident_set(1, second.id, second.id_len, rp_hash) ==
           AUTH_DENIED);
    memcpy(rp_hash, old_rp, 32);
    unlock_permission(2, true);
    assert(auth_resident_get(1, &readback) == AUTH_UNPROVISIONED &&
           readback.id_len == 0);
    assert(auth_resident_get(0, &readback) == AUTH_OK);
    assert(auth_resident_get(1, &readback) == AUTH_UNPROVISIONED);
    assert(auth_resident_get(0, &readback) == AUTH_OK);
    assert(auth_resident_delete(0) == AUTH_DENIED);
    unlock_permission(4, false);
    assert(auth_resident_get(0, &readback) == AUTH_OK &&
           readback.id_len == first.id_len &&
           memcmp(readback.id, first.id, first.id_len) == 0);
    assert(auth_resident_get(1, &readback) == AUTH_OK &&
           readback.id_len == second.id_len &&
           memcmp(readback.id, second.id, second.id_len) == 0);
    assert(auth_resident_delete(1) == AUTH_OK);
    assert(auth_resident_delete(0) == AUTH_OK);
    puts("separate MC/GA/CM real-storage permissions: PASS");
    return 0;
  }

  if (!strcmp(argv[1], "replace_account")) {
    // A creation session, which is all a registration carries: mc, bound. CTAP
    // says a credential for this relying party and this account replaces the
    // record that is there, and this is the only replacement a session without
    // the management permission may make.
    uint32_t before = 0, after = 0;
    assert(auth_test_record_generation(0, &before));
    unlock_permission(1, true);
    auth_credential_public third;
    // The same metadata as `first`, so the same account, sealed into a new id.
    assert(auth_credential_create(rp_hash, -7, meta, sizeof(meta), &third) ==
           AUTH_OK);
    assert(auth_resident_set(AUTH_RESIDENT_ANY, third.id, third.id_len,
                             rp_hash) == AUTH_OK);
    unlock_permission(4, false);
    // The replacement advances the record's generation, which is what decides
    // whether a torn write recovers the new credential or resurrects the old.
    assert(auth_test_record_generation(0, &after) && after > before);
    // Slot 0 held this account and now holds the new record: the slot did not
    // move, nothing was deleted, and slot 99 belongs to another account.
    assert(auth_resident_get(0, &readback) == AUTH_OK &&
           readback.id_len == third.id_len &&
           memcmp(readback.id, third.id, third.id_len) == 0);
    assert(auth_resident_get(99, &readback) == AUTH_OK &&
           readback.id_len == second.id_len &&
           memcmp(readback.id, second.id, second.id_len) == 0);
    unsigned occupied = 0;
    for (uint8_t i = 0; i < 100; i++)
      if (auth_resident_get(i, &readback) == AUTH_OK) occupied++;
    assert(occupied == 2);
    // A fresh session over the same medium sees the replacement, which is what
    // proves the new record was committed rather than merely written.
    auth_vault_disconnect();
    assert(auth_vault_init() == AUTH_OK);
    unlock();
    assert(auth_resident_get(0, &readback) == AUTH_OK &&
           readback.id_len == third.id_len &&
           memcmp(readback.id, third.id, third.id_len) == 0);
    puts("creation session replaces its own account in place: PASS");
    return 0;
  }

  if (!strcmp(argv[1], "replace_other_account")) {
    // A different account of the same party takes a free slot and leaves both
    // records where they are.
    unlock_permission(1, true);
    uint8_t m[sizeof(meta)];
    memcpy(m, meta, sizeof(meta));
    m[sizeof(m) - 1] = 3;
    auth_credential_public third;
    assert(auth_credential_create(rp_hash, -7, m, sizeof(m), &third) == AUTH_OK);
    assert(auth_resident_set(AUTH_RESIDENT_ANY, third.id, third.id_len,
                             rp_hash) == AUTH_OK);
    unlock_permission(4, false);
    assert(auth_resident_get(0, &readback) == AUTH_OK &&
           readback.id_len == first.id_len &&
           memcmp(readback.id, first.id, first.id_len) == 0);
    assert(auth_resident_get(99, &readback) == AUTH_OK &&
           readback.id_len == second.id_len &&
           memcmp(readback.id, second.id, second.id_len) == 0);
    assert(auth_resident_get(1, &readback) == AUTH_OK &&
           readback.id_len == third.id_len &&
           memcmp(readback.id, third.id, third.id_len) == 0);
    puts("a different account takes a free slot: PASS");
    return 0;
  }

  if (!strcmp(argv[1], "replace_other_party")) {
    // The account only decides within one relying party. Somebody else's record
    // for the same account must be left exactly where it is.
    uint8_t old_rp[32], other_meta[sizeof(meta)];
    memcpy(old_rp, rp_hash, 32);
    memcpy(other_meta, meta, sizeof(meta));
    other_meta[9] = 'a';
    sha256_Raw(other_meta + 9, 11, rp_hash);
    unlock_permission(1, true);
    auth_credential_public other;
    assert(auth_credential_create(rp_hash, -7, other_meta, sizeof(other_meta),
                                  &other) == AUTH_OK);
    assert(auth_resident_set(AUTH_RESIDENT_ANY, other.id, other.id_len,
                             rp_hash) == AUTH_OK);
    memcpy(rp_hash, old_rp, 32);
    unlock_permission(4, false);
    assert(auth_resident_get(0, &readback) == AUTH_OK &&
           readback.id_len == first.id_len &&
           memcmp(readback.id, first.id, first.id_len) == 0);
    assert(auth_resident_get(1, &readback) == AUTH_OK &&
           readback.id_len == other.id_len &&
           memcmp(readback.id, other.id, other.id_len) == 0);
    puts("another party's record for the same account is untouched: PASS");
    return 0;
  }

  if (!strcmp(argv[1], "replace_when_full")) {
    // A replacement asks for no room, so a device with every slot occupied must
    // still be able to make one -- and must still refuse a new account.
    unlock();
    for (uint8_t i = 1; i < 99; i++) {
      uint8_t m[sizeof(meta)];
      memcpy(m, meta, sizeof(meta));
      m[sizeof(m) - 1] = (uint8_t)(10 + i);
      auth_credential_public filler;
      assert(auth_credential_create(rp_hash, -7, m, sizeof(m), &filler) ==
             AUTH_OK);
      assert(auth_resident_set(i, filler.id, filler.id_len, rp_hash) == AUTH_OK);
    }
    unlock_permission(1, true);
    auth_credential_public again;
    assert(auth_credential_create(rp_hash, -7, meta, sizeof(meta), &again) ==
           AUTH_OK);
    assert(auth_resident_set(AUTH_RESIDENT_ANY, again.id, again.id_len,
                             rp_hash) == AUTH_OK);
    unlock_permission(4, false);
    assert(auth_resident_get(0, &readback) == AUTH_OK &&
           readback.id_len == again.id_len &&
           memcmp(readback.id, again.id, again.id_len) == 0);
    // And a new account has nowhere to go, which is a different answer from a
    // denial and has to stay one.
    unlock_permission(1, true);
    uint8_t fresh[sizeof(meta)];
    memcpy(fresh, meta, sizeof(meta));
    fresh[sizeof(fresh) - 1] = 200;
    auth_credential_public newcomer;
    assert(auth_credential_create(rp_hash, -7, fresh, sizeof(fresh),
                                  &newcomer) == AUTH_OK);
    assert(auth_resident_set(AUTH_RESIDENT_ANY, newcomer.id, newcomer.id_len,
                             rp_hash) == AUTH_STORE_FULL);
    puts("a full store replaces an account it holds and refuses a new one: PASS");
    return 0;
  }

  if (!strcmp(argv[1], "attest_permission")) {
    // CTAP asks a credential for a signature in two places and the vault cannot
    // tell them apart by their bytes, so each is authorized by the permission CTAP
    // gives that operation: an assertion by ga, the attestation of a creation by
    // mc. Neither permission buys the other, which is the whole point of saying
    // which operation is being asked for.
    static const uint8_t body[] = "message";
    uint8_t signature[72];
    size_t n = 0;
    unlock_permission(1, true);
    auth_credential_public made;
    assert(auth_credential_create(rp_hash, -7, meta, sizeof(meta), &made) ==
           AUTH_OK);
    // Creation attests.
    assert(auth_credential_sign(made.id, made.id_len, rp_hash, -7, body, 7, true,
                                signature, &n) == AUTH_OK &&
           n > 0);
    // Creation does not assert.
    unlock_permission(1, true);
    assert(auth_credential_sign(made.id, made.id_len, rp_hash, -7, body, 7, false,
                                signature, &n) == AUTH_DENIED &&
           n == 0);
    // Assertion asserts.
    unlock_permission(2, true);
    assert(auth_credential_sign(made.id, made.id_len, rp_hash, -7, body, 7, false,
                                signature, &n) == AUTH_OK &&
           n > 0);
    // Assertion does not attest.
    unlock_permission(2, true);
    assert(auth_credential_sign(made.id, made.id_len, rp_hash, -7, body, 7, true,
                                signature, &n) == AUTH_DENIED &&
           n == 0);
    // The attestation also requires the session to be bound, which turns out to be
    // belt and braces: an unbound creation token cannot be issued in the first
    // place. CTAP requires an rpId alongside mc, so a request without one is
    // malformed rather than unauthorized, and the vault says so -- the refusal is
    // AUTH_INVALID_ARGUMENT and not AUTH_DENIED, because there is no such grant to
    // deny. Either way the bound check can never be the only thing standing
    // between a token and a signature.
    assert(issue_unbound(1) == AUTH_INVALID_ARGUMENT);
    // The same holds for an assertion token, and a permission that is not
    // RP-scoped is still issuable unbound, which is what makes the rule a rule
    // about mc and ga rather than about binding in general.
    assert(issue_unbound(2) == AUTH_INVALID_ARGUMENT);
    assert(issue_unbound(4) == AUTH_OK);
    puts("mc attests and ga asserts, and neither buys the other: PASS");
    return 0;
  }

  fprintf(stderr, "unknown scenario %s\n", argv[1]);
  return 1;
}
