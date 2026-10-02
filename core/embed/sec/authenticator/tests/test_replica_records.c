// Host fixture for the record/result translation layer.
//
// The layer under test is small, and almost all of its risk is concentrated in
// one place: deciding what the vault is allowed to do next. The manager reports
// several distinct conditions that all look like "I have no usable snapshot",
// and exactly one of them authorises provisioning. Getting that wrong does not
// produce a wrong answer, it destroys credentials:
//
//   BLANK      every area erased          -> provisioning permitted
//   NO_SOURCE  replicas exist, none authenticated under this root
//                                         -> provisioning MUST be refused
//   MIGRATION  data that is not ours      -> refused, nothing touched
//   IO         cannot read (an ordinary hardware image)
//                                         -> refused, nothing touched
//
// So this fixture drives the real layer over the real manager and codec on a
// simulated STM32U5 medium, and checks both the mapping and, for every refusal,
// that the medium is byte-identical afterwards.

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../replica_records.h"
#include "../replica_store.h"
#include "chacha20poly1305/rfc7539.h"
#include "hmac.h"
#include "memzero.h"
#include "sha2.h"

#define AREA AUTH_REPLICA_AREA_SIZE
#define PAGE AUTH_REPLICA_PAGE_SIZE
#define LINE AUTH_REPLICA_LINE_SIZE

// ---------------------------------------------------------------------------
// Simulated medium: 16-byte program granularity, 8 KiB erase, and programming
// only ever clears bits, so a double write is caught rather than silently
// succeeding.
// ---------------------------------------------------------------------------

static uint8_t g_medium[AUTH_REPLICA_COUNT][AREA];
static unsigned g_writes = 0;
static unsigned g_erases = 0;
// When true, every read fails, which is what an ordinary hardware image does
// while the checked reader refuses to risk an ECC double error.
static bool g_reads_fail = false;

static auth_replica_io_result medium_read(void *context, uint8_t replica,
                                          uint32_t offset, uint8_t *out,
                                          uint32_t len) {
  (void)context;
  if (out == NULL || len == 0) return AUTH_REPLICA_IO_RANGE;
  memzero(out, len);
  if (replica >= AUTH_REPLICA_COUNT) return AUTH_REPLICA_IO_RANGE;
  if (offset > AREA || len > AREA - offset) return AUTH_REPLICA_IO_RANGE;
  if (g_reads_fail) return AUTH_REPLICA_IO_FAILED;
  memcpy(out, &g_medium[replica][offset], len);
  return AUTH_REPLICA_IO_OK;
}

static bool medium_write_line(void *context, uint8_t replica, uint32_t offset,
                              const uint8_t line[LINE]) {
  (void)context;
  if (replica >= AUTH_REPLICA_COUNT) return false;
  if (offset % LINE != 0 || offset > AREA - LINE) return false;
  uint8_t *target = &g_medium[replica][offset];
  for (uint32_t i = 0; i < LINE; i++) {
    // Programming a line that is not erased is a hardware error, not a
    // silently-merged write.
    if (target[i] != 0xff && target[i] != line[i]) return false;
    target[i] &= line[i];
  }
  g_writes++;
  return true;
}

static bool medium_erase_page(void *context, uint8_t replica, uint32_t offset) {
  (void)context;
  if (replica >= AUTH_REPLICA_COUNT) return false;
  if (offset % PAGE != 0 || offset > AREA - PAGE) return false;
  memset(&g_medium[replica][offset], 0xff, PAGE);
  g_erases++;
  return true;
}

static const auth_replica_io kIo = {
    .read = medium_read,
    .write_line = medium_write_line,
    .erase_page = medium_erase_page,
    .context = NULL,
};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

static const uint8_t kRoot[32] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
    0xcc, 0xdd, 0xee, 0xff, 0x00, 0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a,
    0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0};
// A different root: same shape, so it exercises "authentication fails" rather
// than "argument rejected".
static const uint8_t kWrongRoot[32] = {
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa};
static const uint8_t kEnvelope[AUTH_REPLICA_ROOT_LENGTH] = {
    0xa1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
static uint8_t g_nonce[AUTH_REPLICA_NONCE_SIZE] = {
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f};

static void next_nonce(void) { g_nonce[0]++; }

static void medium_blank(void) {
  memset(g_medium, 0xff, sizeof(g_medium));
  g_writes = 0;
  g_erases = 0;
  g_reads_fail = false;
  auth_records_close();
}

static bool all_zero(const uint8_t *data, size_t len) {
  uint8_t sum = 0;
  for (size_t i = 0; i < len; i++) sum |= data[i];
  return sum == 0;
}

static uint8_t g_snapshot[AUTH_REPLICA_COUNT][AREA];
static void medium_save(void) {
  memcpy(g_snapshot, g_medium, sizeof(g_medium));
}
static void assert_medium_unchanged(void) {
  assert(memcmp(g_snapshot, g_medium, sizeof(g_medium)) == 0);
}

// Builds a real provisioned vault with two resident records.
static void provision_with_records(void) {
  medium_blank();
  assert(auth_records_open(&kIo) == AUTH_UNPROVISIONED);
  next_nonce();
  assert(auth_records_provision(kRoot, kEnvelope, g_nonce) == AUTH_OK);

  uint8_t record[AUTH_RECORD_HEADER_SIZE + 8];
  memset(record, 0, sizeof(record));
  record[0] = 0xa2;
  record[1] = 1;
  record[2] = 0;
  memset(record + AUTH_RECORD_HEADER_SIZE, 0x5a, 8);
  next_nonce();
  assert(auth_records_write(kRoot, 0, record, sizeof(record), g_nonce) ==
         AUTH_OK);

  record[2] = 99;
  memset(record + AUTH_RECORD_HEADER_SIZE, 0xa5, 8);
  next_nonce();
  assert(auth_records_write(kRoot, 99, record, sizeof(record), g_nonce) ==
         AUTH_OK);
}

// ---------------------------------------------------------------------------
// The mapping that matters
// ---------------------------------------------------------------------------

static void blank_media_permits_provisioning(void) {
  medium_blank();
  assert(auth_records_open(&kIo) == AUTH_UNPROVISIONED);
  assert(auth_records_ready());
  uint8_t candidates[AUTH_REPLICA_COUNT][AUTH_REPLICA_ROOT_LENGTH];
  uint8_t count = 0xff;
  assert(auth_records_root_candidates(candidates, &count) ==
         AUTH_UNPROVISIONED);
  assert(count == 0);

  next_nonce();
  assert(auth_records_provision(kRoot, kEnvelope, g_nonce) == AUTH_OK);
  assert(g_erases > 0 && g_writes > 0);

  // And the freshly provisioned vault authenticates and yields its envelope.
  assert(auth_records_authenticate(kRoot) == AUTH_OK);
  uint8_t envelope[AUTH_REPLICA_ROOT_LENGTH];
  assert(auth_records_read_root(kRoot, envelope) == AUTH_OK);
  assert(memcmp(envelope, kEnvelope, sizeof(kEnvelope)) == 0);
}

// The case that must never be confused with a blank device.
static void unauthenticated_vault_refuses_provisioning(void) {
  provision_with_records();

  // Reopen and try to authenticate with the wrong root, as a wrong PIN would.
  auth_records_close();
  assert(auth_records_open(&kIo) == AUTH_OK);
  assert(auth_records_authenticate(kWrongRoot) != AUTH_OK);
  // Specifically not "unprovisioned": that answer would authorise a reformat.
  assert(auth_records_authenticate(kWrongRoot) != AUTH_UNPROVISIONED);

  // Provisioning over it must be refused, and must not touch a single byte.
  medium_save();
  unsigned writes = g_writes, erases = g_erases;
  next_nonce();
  // Specifically AUTH_DENIED, which is this layer's own refusal. Asserting only
  // "not OK" would also pass if the layer let the request through and the
  // manager happened to reject it, leaving the guard here untested.
  assert(auth_records_provision(kWrongRoot, kEnvelope, g_nonce) == AUTH_DENIED);
  assert(g_writes == writes && g_erases == erases);
  assert_medium_unchanged();

  // The correct root still opens it afterwards, so the refusal was harmless.
  assert(auth_records_authenticate(kRoot) == AUTH_OK);
  uint8_t out[AUTH_RECORD_MAX];
  uint16_t length = 0;
  assert(auth_records_read(kRoot, 0, out, sizeof(out), &length) == AUTH_OK);
  assert(length == AUTH_RECORD_HEADER_SIZE + 8);
}

static void foreign_media_requires_migration_and_is_untouched(void) {
  // Legacy wallet/NORCOW-looking bytes in one area, the others erased.
  medium_blank();
  memset(g_medium[1], 0x00, PAGE);
  memcpy(g_medium[1], "NRC2", 4);
  medium_save();

  assert(auth_records_open(&kIo) == AUTH_MIGRATION_REQUIRED);
  // Migration is not provisionable and not authenticable, and neither attempt
  // may write. The status also has to survive every other entry point, because
  // the vault surfaces it to the user; a generic error would lose the reason.
  next_nonce();
  assert(auth_records_provision(kRoot, kEnvelope, g_nonce) ==
         AUTH_MIGRATION_REQUIRED);
  assert(auth_records_authenticate(kRoot) == AUTH_MIGRATION_REQUIRED);
  uint8_t out[AUTH_RECORD_MAX];
  uint16_t length = 0;
  assert(auth_records_read(kRoot, 0, out, sizeof(out), &length) ==
         AUTH_MIGRATION_REQUIRED);
  uint8_t envelope[AUTH_REPLICA_ROOT_LENGTH];
  assert(auth_records_read_root(kRoot, envelope) == AUTH_MIGRATION_REQUIRED);
  uint8_t record[AUTH_RECORD_HEADER_SIZE] = {0xa2, 1, 0, 0};
  assert(auth_records_write(kRoot, 0, record, sizeof(record), g_nonce) ==
         AUTH_MIGRATION_REQUIRED);
  assert(auth_records_delete(kRoot, 0, g_nonce) == AUTH_MIGRATION_REQUIRED);
  assert(auth_records_repair(kRoot) == AUTH_MIGRATION_REQUIRED);
  // And a wipe must refuse too: those bytes may be somebody's wallet.
  assert(auth_records_wipe() == AUTH_MIGRATION_REQUIRED);
  assert(g_writes == 0 && g_erases == 0);
  assert_medium_unchanged();
}

// An ordinary hardware image cannot contain an ECC double error yet, so its
// checked reader refuses every load. The layer must report that as an error and
// leave the device completely alone -- not decide it is blank.
static void unreadable_media_fails_closed(void) {
  provision_with_records();
  auth_records_close();
  medium_save();
  unsigned writes = g_writes, erases = g_erases;

  g_reads_fail = true;
  auth_result opened = auth_records_open(&kIo);
  assert(opened != AUTH_OK);
  assert(opened != AUTH_UNPROVISIONED);
  assert(opened != AUTH_MIGRATION_REQUIRED);

  next_nonce();
  assert(auth_records_provision(kRoot, kEnvelope, g_nonce) != AUTH_OK);
  assert(auth_records_authenticate(kRoot) != AUTH_OK);
  // A wipe must also refuse: erasing what we cannot read could destroy a vault,
  // or someone else's wallet, on the strength of a failed read.
  assert(auth_records_wipe() != AUTH_OK);
  assert(g_writes == writes && g_erases == erases);
  assert_medium_unchanged();
  g_reads_fail = false;
}

// ---------------------------------------------------------------------------
// Ordering: nothing works before the areas are classified
// ---------------------------------------------------------------------------

static void every_entry_point_fails_before_open(void) {
  medium_blank();
  assert(!auth_records_ready());

  uint8_t candidates[AUTH_REPLICA_COUNT][AUTH_REPLICA_ROOT_LENGTH];
  uint8_t count = 0xff;
  uint8_t out[AUTH_RECORD_MAX];
  uint16_t length = 0;
  uint8_t envelope[AUTH_REPLICA_ROOT_LENGTH];
  uint8_t record[AUTH_RECORD_HEADER_SIZE] = {0xa2, 1, 0, 0};

  assert(auth_records_root_candidates(candidates, &count) != AUTH_OK);
  assert(auth_records_authenticate(kRoot) != AUTH_OK);
  assert(auth_records_read_root(kRoot, envelope) != AUTH_OK);
  assert(auth_records_read(kRoot, 0, out, sizeof(out), &length) != AUTH_OK);
  assert(auth_records_write(kRoot, 0, record, sizeof(record), g_nonce) !=
         AUTH_OK);
  assert(auth_records_delete(kRoot, 0, g_nonce) != AUTH_OK);
  assert(auth_records_repair(kRoot) != AUTH_OK);
  assert(auth_records_provision(kRoot, kEnvelope, g_nonce) != AUTH_OK);
  assert(auth_records_wipe() != AUTH_OK);
  // None of those may have touched the medium.
  assert(g_writes == 0 && g_erases == 0);
}

// Reading or mutating a record before a snapshot has been selected must fail,
// even though the areas are classified.
static void records_require_authentication_first(void) {
  provision_with_records();
  auth_records_close();
  assert(auth_records_open(&kIo) == AUTH_OK);

  uint8_t out[AUTH_RECORD_MAX];
  uint16_t length = 0;
  assert(auth_records_read(kRoot, 0, out, sizeof(out), &length) != AUTH_OK);

  medium_save();
  unsigned writes = g_writes, erases = g_erases;
  uint8_t record[AUTH_RECORD_HEADER_SIZE] = {0xa2, 1, 0, 0};
  next_nonce();
  assert(auth_records_write(kRoot, 0, record, sizeof(record), g_nonce) !=
         AUTH_OK);
  assert(g_writes == writes && g_erases == erases);
  assert_medium_unchanged();

  assert(auth_records_authenticate(kRoot) == AUTH_OK);
  assert(auth_records_read(kRoot, 0, out, sizeof(out), &length) == AUTH_OK);
}

// ---------------------------------------------------------------------------
// Record round trip and slot semantics
// ---------------------------------------------------------------------------

static void records_round_trip_and_empty_slots_report_unprovisioned(void) {
  provision_with_records();
  assert(auth_records_authenticate(kRoot) == AUTH_OK);

  uint8_t out[AUTH_RECORD_MAX];
  uint16_t length = 0;
  assert(auth_records_read(kRoot, 0, out, sizeof(out), &length) == AUTH_OK);
  assert(length == AUTH_RECORD_HEADER_SIZE + 8);
  assert(out[0] == 0xa2 && out[2] == 0);
  for (unsigned i = 0; i < 8; i++) {
    assert(out[AUTH_RECORD_HEADER_SIZE + i] == 0x5a);
  }

  assert(auth_records_read(kRoot, 99, out, sizeof(out), &length) == AUTH_OK);
  assert(out[2] == 99);
  for (unsigned i = 0; i < 8; i++) {
    assert(out[AUTH_RECORD_HEADER_SIZE + i] == 0xa5);
  }

  // An empty slot is an expected enumeration result, not a failure, and it
  // leaves nothing in the caller's buffer.
  for (uint8_t index = 1; index < 99; index++) {
    memset(out, 0xcc, sizeof(out));
    length = 0xffff;
    assert(auth_records_read(kRoot, index, out, sizeof(out), &length) ==
           AUTH_UNPROVISIONED);
    assert(length == 0);
    for (size_t b = 0; b < sizeof(out); b++) assert(out[b] == 0);
  }

  // Delete makes a populated slot report empty, and leaves its sibling alone.
  next_nonce();
  assert(auth_records_delete(kRoot, 0, g_nonce) == AUTH_OK);
  assert(auth_records_read(kRoot, 0, out, sizeof(out), &length) ==
         AUTH_UNPROVISIONED);
  assert(auth_records_read(kRoot, 99, out, sizeof(out), &length) == AUTH_OK);
  assert(out[2] == 99);
}

static void bad_arguments_are_refused(void) {
  provision_with_records();
  assert(auth_records_authenticate(kRoot) == AUTH_OK);

  uint8_t out[AUTH_RECORD_MAX];
  uint16_t length = 0;
  uint8_t record[AUTH_RECORD_HEADER_SIZE] = {0xa2, 1, 0, 0};

  // Slot index out of range.
  assert(auth_records_read(kRoot, 100, out, sizeof(out), &length) ==
         AUTH_INVALID_ARGUMENT);
  assert(auth_records_read(kRoot, 0xff, out, sizeof(out), &length) ==
         AUTH_INVALID_ARGUMENT);
  assert(auth_records_write(kRoot, 100, record, sizeof(record), g_nonce) ==
         AUTH_INVALID_ARGUMENT);
  assert(auth_records_delete(kRoot, 100, g_nonce) == AUTH_INVALID_ARGUMENT);
  assert(auth_records_capacity(100, 1) == AUTH_INVALID_ARGUMENT);

  // Null pointers.
  assert(auth_records_read(kRoot, 0, NULL, sizeof(out), &length) ==
         AUTH_INVALID_ARGUMENT);
  assert(auth_records_read(kRoot, 0, out, sizeof(out), NULL) ==
         AUTH_INVALID_ARGUMENT);
  assert(auth_records_read(NULL, 0, out, sizeof(out), &length) ==
         AUTH_INVALID_ARGUMENT);
  assert(auth_records_write(kRoot, 0, NULL, sizeof(record), g_nonce) ==
         AUTH_INVALID_ARGUMENT);
  assert(auth_records_write(kRoot, 0, record, sizeof(record), NULL) ==
         AUTH_INVALID_ARGUMENT);

  // A destination too small for the stored record must fail rather than
  // truncate.
  assert(auth_records_read(kRoot, 0, out, AUTH_RECORD_HEADER_SIZE, &length) !=
         AUTH_OK);

  // Capacity is a fixed bound, not a free-space query.
  assert(auth_records_capacity(0, 1) == AUTH_OK);
  assert(auth_records_capacity(0, AUTH_RECORD_MAX) == AUTH_OK);
  assert(auth_records_capacity(0, AUTH_RECORD_MAX + 1) == AUTH_LIMIT_EXCEEDED);
  assert(auth_records_capacity(0, 0) == AUTH_INVALID_ARGUMENT);
  assert(auth_records_write(kRoot, 0, record, AUTH_RECORD_MAX + 1, g_nonce) ==
         AUTH_LIMIT_EXCEEDED);
  assert(auth_records_write(kRoot, 0, record, 0, g_nonce) ==
         AUTH_INVALID_ARGUMENT);
}

// ---------------------------------------------------------------------------
// Repair and wipe
// ---------------------------------------------------------------------------

static void repair_rebuilds_a_damaged_replica(void) {
  provision_with_records();
  assert(auth_records_authenticate(kRoot) == AUTH_OK);

  // Wreck one replica's header so it cannot authenticate.
  memset(g_medium[2], 0x00, LINE);
  auth_records_close();
  assert(auth_records_open(&kIo) == AUTH_OK);
  assert(auth_records_authenticate(kRoot) == AUTH_OK);
  assert(auth_records_repair(kRoot) == AUTH_OK);

  // After repair all three authenticate, so a second repair has nothing to do.
  auth_records_close();
  assert(auth_records_open(&kIo) == AUTH_OK);
  assert(auth_records_authenticate(kRoot) == AUTH_OK);
  unsigned writes = g_writes, erases = g_erases;
  assert(auth_records_repair(kRoot) == AUTH_OK);
  assert(g_writes == writes && g_erases == erases);
}

static void wipe_clears_every_replica(void) {
  provision_with_records();
  assert(auth_records_open(&kIo) == AUTH_OK || auth_records_ready());
  assert(auth_records_wipe() == AUTH_OK);

  // Nothing authenticates afterwards, and the areas read back as ours-and-empty
  // rather than as foreign data needing migration.
  auth_records_close();
  assert(auth_records_open(&kIo) == AUTH_UNPROVISIONED);
  uint8_t candidates[AUTH_REPLICA_COUNT][AUTH_REPLICA_ROOT_LENGTH];
  uint8_t count = 0xff;
  assert(auth_records_root_candidates(candidates, &count) ==
         AUTH_UNPROVISIONED);
  assert(count == 0);
}

// The trap that separates "wiped, reprovision me" from "I cannot see your
// vault". Both look like "our areas, no snapshot" to the manager, so if the
// classification is ignored a device whose replicas merely failed to read
// becomes eligible for a reformat.
static void partly_unreadable_media_is_not_provisionable(void) {
  // Start from a real wiped device, which must be provisionable...
  provision_with_records();
  auth_records_close();
  assert(auth_records_open(&kIo) == AUTH_OK);
  assert(auth_records_wipe() == AUTH_OK);
  auth_records_close();
  assert(auth_records_open(&kIo) == AUTH_UNPROVISIONED);

  // ...then make the reads fail and confirm the same media is refused. Nothing
  // about the bytes changed; only our ability to read them did.
  medium_save();
  unsigned writes = g_writes, erases = g_erases;
  g_reads_fail = true;
  auth_records_close();
  auth_result opened = auth_records_open(&kIo);
  assert(opened != AUTH_UNPROVISIONED);
  assert(opened != AUTH_OK);
  next_nonce();
  assert(auth_records_provision(kRoot, kEnvelope, g_nonce) != AUTH_OK);
  assert(g_writes == writes && g_erases == erases);
  assert_medium_unchanged();
  g_reads_fail = false;
}

// ---------------------------------------------------------------------------
// Nondestructive admission
// ---------------------------------------------------------------------------
//
// The single most expensive mistake this vault could make is to decide that a
// device already holding somebody's wallet is "empty" and reformat it. So for
// every plausible thing that could be sitting in one of the three areas, the
// layer has to refuse and leave all 192 KiB exactly as it found it.
//
// The patterns below use the real on-disk shapes where they exist -- NORCOW's
// actual magic values and inverted version word -- so that this doubles as a
// regression test for converting a real wallet device.

// NORCOW_MAGIC 0x3243524e little-endian, i.e. "NRC2"; V0 is "NRCW". The version
// word is stored inverted (~6 == 0xfffffff9).
static void fill_norcow_v2(uint8_t *area) {
  static const uint8_t kHeader[] = {'N', 'R', 'C', '2', 0xf9, 0xff, 0xff, 0xff};
  memcpy(area, kHeader, sizeof(kHeader));
  // A plausible key/value record after the header.
  area[16] = 0x01;
  area[17] = 0x02;
  area[18] = 0x04;
  area[19] = 0x00;
}

static void fill_norcow_v0(uint8_t *area) {
  static const uint8_t kHeader[] = {'N', 'R', 'C', 'W'};
  memcpy(area, kHeader, sizeof(kHeader));
}

// A legacy authenticator root record as the pre-replica layout stored it: key
// 0xff01, 62-byte value. This is the case where the device is genuinely ours
// but in the old format, which still must not be erased implicitly.
static void fill_legacy_authenticator_key(uint8_t *area) {
  fill_norcow_v2(area);
  area[32] = 0x01;
  area[33] = 0xff;
  area[34] = 62;
  area[35] = 0;
  area[36] = 0xa1;
  area[37] = 1;
  memset(area + 38, 0x5c, 60);
}

static void fill_foreign_app(uint8_t *area) {
  fill_norcow_v2(area);
  // Some other application's namespace.
  area[32] = 0x11;
  area[33] = 0x02;
  area[34] = 8;
  area[35] = 0;
  memset(area + 36, 0x77, 8);
}

// What a translations blob looks like in the assets area.
static void fill_translations(uint8_t *area) {
  static const uint8_t kBlob[] = {'T', 'R', 'T', 'R', 0x00, 0x01, 0x00, 0x00};
  memcpy(area, kBlob, sizeof(kBlob));
  memset(area + 64, 0x2a, 512);
}

// The minimal case: exactly one byte that is not erased, far from the header.
static void fill_single_byte(uint8_t *area) { area[AREA - PAGE - 1] = 0xa7; }

// Our magic with a wrong version character, so the header cannot decode.
static void fill_wrong_replica_magic(uint8_t *area) {
  memcpy(area, "TSAUTHR0", 8);
  memset(area + 8, 0x31, 64);
}

// Our exact magic, but everything after it is garbage.
static void fill_garbled_replica_header(uint8_t *area) {
  memcpy(area, "TSAUTHR1", 8);
  memset(area + 8, 0xc4, AUTH_REPLICA_HEADER_SIZE - 8);
}

static void foreign_content_is_never_touched(void) {
  const struct {
    const char *name;
    void (*fill)(uint8_t *area);
  } kPatterns[] = {
      {"norcow v2", fill_norcow_v2},
      {"norcow v0", fill_norcow_v0},
      {"legacy authenticator key", fill_legacy_authenticator_key},
      {"foreign application", fill_foreign_app},
      {"translations blob", fill_translations},
      {"single non-erased byte", fill_single_byte},
      {"wrong replica magic", fill_wrong_replica_magic},
      {"garbled replica header", fill_garbled_replica_header},
  };

  uint8_t out[AUTH_RECORD_MAX];
  uint8_t envelope[AUTH_REPLICA_ROOT_LENGTH];
  uint8_t record[AUTH_RECORD_HEADER_SIZE] = {0xa2, 1, 0, 0};
  unsigned scenarios = 0;

  for (unsigned p = 0; p < sizeof(kPatterns) / sizeof(kPatterns[0]); p++) {
    // Each area independently, so a pattern that only ever appears in assets
    // (translations) is still checked against the storage areas and vice versa.
    for (uint8_t area = 0; area < AUTH_REPLICA_COUNT; area++) {
      medium_blank();
      kPatterns[p].fill(g_medium[area]);
      medium_save();

      assert(auth_records_open(&kIo) == AUTH_MIGRATION_REQUIRED);

      // Every entry point must refuse with the reason intact, and none of them
      // may write or erase a single byte.
      uint16_t length = 0;
      next_nonce();
      assert(auth_records_provision(kRoot, kEnvelope, g_nonce) ==
             AUTH_MIGRATION_REQUIRED);
      assert(auth_records_authenticate(kRoot) == AUTH_MIGRATION_REQUIRED);
      assert(auth_records_read_root(kRoot, envelope) ==
             AUTH_MIGRATION_REQUIRED);
      assert(auth_records_read(kRoot, 0, out, sizeof(out), &length) ==
             AUTH_MIGRATION_REQUIRED);
      assert(auth_records_write(kRoot, 0, record, sizeof(record), g_nonce) ==
             AUTH_MIGRATION_REQUIRED);
      assert(auth_records_delete(kRoot, 0, g_nonce) == AUTH_MIGRATION_REQUIRED);
      assert(auth_records_repair(kRoot) == AUTH_MIGRATION_REQUIRED);
      assert(auth_records_wipe() == AUTH_MIGRATION_REQUIRED);

      uint8_t candidates[AUTH_REPLICA_COUNT][AUTH_REPLICA_ROOT_LENGTH];
      uint8_t count = 0xff;
      assert(auth_records_root_candidates(candidates, &count) ==
             AUTH_MIGRATION_REQUIRED);
      assert(count == 0);

      assert(g_writes == 0 && g_erases == 0);
      assert_medium_unchanged();
      scenarios++;
    }
  }
  // 8 patterns across 3 areas.
  assert(scenarios == 24);

  // Contrast: our own ownership claim with no header is *not* foreign. It is a
  // destination torn by a power cut, or a wiped area, and it must stay
  // provisionable -- otherwise a single mid-commit power loss would brick the
  // device. This is the line the matrix above must not cross.
  medium_blank();
  memcpy(&g_medium[1][AUTH_REPLICA_CLAIM_OFFSET], "TSAUTHC1", 8);
  assert(auth_records_open(&kIo) == AUTH_UNPROVISIONED);
  next_nonce();
  assert(auth_records_provision(kRoot, kEnvelope, g_nonce) == AUTH_OK);
}

// ---------------------------------------------------------------------------
// Root-envelope unlock
// ---------------------------------------------------------------------------

static const uint8_t kKek[32] = {
    0x21, 0x43, 0x65, 0x87, 0xa9, 0xcb, 0xed, 0x0f, 0x11, 0x33, 0x55,
    0x77, 0x99, 0xbb, 0xdd, 0xff, 0x02, 0x24, 0x46, 0x68, 0x8a, 0xac,
    0xce, 0xe0, 0x13, 0x35, 0x57, 0x79, 0x9b, 0xbd, 0xdf, 0xf1};
static const uint8_t kOtherKek[32] = {
    0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
    0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
    0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a};

// Seals `secret` the way the vault's wrap() does, with a caller-chosen nonce so
// the "torn root commit" case (same secret, different nonce) can be built.
static void seal_envelope(const uint8_t kek[32], const uint8_t secret[32],
                          uint8_t nonce_seed,
                          uint8_t out[AUTH_REPLICA_ROOT_LENGTH]) {
  memset(out, 0, AUTH_REPLICA_ROOT_LENGTH);
  out[0] = AUTH_ENVELOPE_TAG;
  out[1] = AUTH_ENVELOPE_VERSION;
  for (unsigned i = 0; i < AUTH_ENVELOPE_NONCE_SIZE; i++) {
    out[AUTH_ENVELOPE_AAD_SIZE + i] = (uint8_t)(nonce_seed + i);
  }
  chacha20poly1305_ctx aead;
  rfc7539_init(&aead, kek, out + AUTH_ENVELOPE_AAD_SIZE);
  rfc7539_auth(&aead, out, AUTH_ENVELOPE_AAD_SIZE);
  chacha20poly1305_encrypt(
      &aead, secret, out + AUTH_ENVELOPE_AAD_SIZE + AUTH_ENVELOPE_NONCE_SIZE,
      AUTH_ENVELOPE_SECRET_SIZE);
  rfc7539_finish(&aead, AUTH_ENVELOPE_AAD_SIZE, AUTH_ENVELOPE_SECRET_SIZE,
                 out + AUTH_ENVELOPE_AAD_SIZE + AUTH_ENVELOPE_NONCE_SIZE +
                     AUTH_ENVELOPE_SECRET_SIZE);
  memzero(&aead, sizeof(aead));
}

// Provisions a vault whose stored envelope is the real sealed form of kRoot, so
// unlock() has something consistent to authenticate against.
static void provision_sealed(void) {
  uint8_t envelope[AUTH_REPLICA_ROOT_LENGTH];
  seal_envelope(kKek, kRoot, 0x40, envelope);
  medium_blank();
  assert(auth_records_open(&kIo) == AUTH_UNPROVISIONED);
  next_nonce();
  assert(auth_records_provision(kRoot, envelope, g_nonce) == AUTH_OK);
  auth_records_close();
  assert(auth_records_open(&kIo) == AUTH_OK);
}

static void unlock_recovers_the_root_and_selects_a_snapshot(void) {
  provision_sealed();

  uint8_t candidates[AUTH_REPLICA_COUNT][AUTH_REPLICA_ROOT_LENGTH];
  uint8_t count = 0;
  assert(auth_records_root_candidates(candidates, &count) == AUTH_OK);
  // All three replicas carry the same envelope, so dedup leaves exactly one.
  assert(count == 1);

  uint8_t root[32];
  memset(root, 0xcc, sizeof(root));
  assert(auth_records_unlock(kKek, candidates, count, root) == AUTH_OK);
  assert(memcmp(root, kRoot, sizeof(root)) == 0);
  // A snapshot is selected, so records are readable straight away.
  uint8_t out[AUTH_RECORD_MAX];
  uint16_t length = 0;
  assert(auth_records_read(root, 0, out, sizeof(out), &length) ==
         AUTH_UNPROVISIONED);
  uint8_t envelope[AUTH_REPLICA_ROOT_LENGTH];
  assert(auth_records_read_root(root, envelope) == AUTH_OK);
  memzero(root, sizeof(root));
}

// A KEK that opens nothing is damage, not a retry: the secure element has
// already verified the PIN by the time a KEK exists, so a wrong PIN cannot
// reach this path at all.
static void a_kek_that_opens_nothing_is_damage(void) {
  provision_sealed();
  uint8_t candidates[AUTH_REPLICA_COUNT][AUTH_REPLICA_ROOT_LENGTH];
  uint8_t count = 0;
  assert(auth_records_root_candidates(candidates, &count) == AUTH_OK);

  uint8_t root[32];
  memset(root, 0xcc, sizeof(root));
  assert(auth_records_unlock(kOtherKek, candidates, count, root) == AUTH_ERROR);
  assert(all_zero(root, sizeof(root)));

  // And the device is untouched: the right KEK still works afterwards.
  assert(auth_records_unlock(kKek, candidates, count, root) == AUTH_OK);
  assert(memcmp(root, kRoot, sizeof(root)) == 0);
  memzero(root, sizeof(root));
}

// A root commit torn by a power cut leaves replicas carrying different
// envelopes. They differ only in the nonce, so every one that opens must yield
// the same secret and the unlock must succeed.
static void differing_envelopes_for_one_root_still_unlock(void) {
  provision_sealed();

  uint8_t candidates[AUTH_REPLICA_COUNT][AUTH_REPLICA_ROOT_LENGTH];
  uint8_t count = 0;
  assert(auth_records_root_candidates(candidates, &count) == AUTH_OK);
  assert(count == 1);

  // Two more sealings of the same secret under the same KEK, fresh nonces.
  uint8_t torn[AUTH_REPLICA_COUNT][AUTH_REPLICA_ROOT_LENGTH];
  memcpy(torn[0], candidates[0], AUTH_REPLICA_ROOT_LENGTH);
  seal_envelope(kKek, kRoot, 0x70, torn[1]);
  seal_envelope(kKek, kRoot, 0xb0, torn[2]);
  assert(memcmp(torn[0], torn[1], AUTH_REPLICA_ROOT_LENGTH) != 0);
  assert(memcmp(torn[1], torn[2], AUTH_REPLICA_ROOT_LENGTH) != 0);

  uint8_t root[32];
  assert(auth_records_unlock(kKek, torn, AUTH_REPLICA_COUNT, root) == AUTH_OK);
  assert(memcmp(root, kRoot, sizeof(root)) == 0);
  memzero(root, sizeof(root));
}

// One unreadable/damaged envelope among valid ones must not block the unlock.
static void a_damaged_candidate_is_skipped(void) {
  provision_sealed();
  uint8_t candidates[AUTH_REPLICA_COUNT][AUTH_REPLICA_ROOT_LENGTH];
  uint8_t count = 0;
  assert(auth_records_root_candidates(candidates, &count) == AUTH_OK);

  uint8_t mixed[AUTH_REPLICA_COUNT][AUTH_REPLICA_ROOT_LENGTH];
  // A corrupted tag, a wrong version byte, and the good one last, so a
  // short-circuit on the first failure would be visible.
  memcpy(mixed[0], candidates[0], AUTH_REPLICA_ROOT_LENGTH);
  mixed[0][AUTH_REPLICA_ROOT_LENGTH - 1] ^= 0xff;
  memcpy(mixed[1], candidates[0], AUTH_REPLICA_ROOT_LENGTH);
  mixed[1][1] = 0x7f;
  memcpy(mixed[2], candidates[0], AUTH_REPLICA_ROOT_LENGTH);

  uint8_t root[32];
  assert(auth_records_unlock(kKek, mixed, AUTH_REPLICA_COUNT, root) == AUTH_OK);
  assert(memcmp(root, kRoot, sizeof(root)) == 0);
  memzero(root, sizeof(root));
}

// Two envelopes that both open but disagree about the secret. Impossible on a
// healthy device, so the only safe answer is to refuse rather than choose.
static void disagreeing_secrets_fail_closed(void) {
  provision_sealed();
  uint8_t candidates[AUTH_REPLICA_COUNT][AUTH_REPLICA_ROOT_LENGTH];
  uint8_t count = 0;
  assert(auth_records_root_candidates(candidates, &count) == AUTH_OK);

  uint8_t conflicting[AUTH_REPLICA_COUNT][AUTH_REPLICA_ROOT_LENGTH];
  memcpy(conflicting[0], candidates[0], AUTH_REPLICA_ROOT_LENGTH);
  seal_envelope(kKek, kWrongRoot, 0x90, conflicting[1]);
  memcpy(conflicting[2], candidates[0], AUTH_REPLICA_ROOT_LENGTH);

  uint8_t root[32];
  memset(root, 0xcc, sizeof(root));
  assert(auth_records_unlock(kKek, conflicting, AUTH_REPLICA_COUNT, root) ==
         AUTH_ERROR);
  assert(all_zero(root, sizeof(root)));
}

// An envelope that opens cleanly but whose root owns no stored snapshot must be
// rejected: decrypting is not proof of ownership, the snapshot MAC is.
static void an_envelope_without_a_snapshot_is_rejected(void) {
  provision_sealed();
  uint8_t orphan[AUTH_REPLICA_COUNT][AUTH_REPLICA_ROOT_LENGTH];
  seal_envelope(kKek, kWrongRoot, 0x50, orphan[0]);

  uint8_t root[32];
  memset(root, 0xcc, sizeof(root));
  assert(auth_records_unlock(kKek, orphan, 1, root) != AUTH_OK);
  assert(all_zero(root, sizeof(root)));
}

static void unlock_rejects_bad_arguments(void) {
  provision_sealed();
  uint8_t candidates[AUTH_REPLICA_COUNT][AUTH_REPLICA_ROOT_LENGTH];
  uint8_t count = 0;
  assert(auth_records_root_candidates(candidates, &count) == AUTH_OK);

  uint8_t root[32];
  assert(auth_records_unlock(NULL, candidates, count, root) ==
         AUTH_INVALID_ARGUMENT);
  assert(auth_records_unlock(kKek, NULL, count, root) == AUTH_INVALID_ARGUMENT);
  assert(auth_records_unlock(kKek, candidates, count, NULL) ==
         AUTH_INVALID_ARGUMENT);
  assert(auth_records_unlock(kKek, candidates, AUTH_REPLICA_COUNT + 1, root) ==
         AUTH_INVALID_ARGUMENT);
  // No candidates is the blank case, not a failure to open one.
  assert(auth_records_unlock(kKek, candidates, 0, root) == AUTH_UNPROVISIONED);
}

// ---------------------------------------------------------------------------
// Resident record codec
// ---------------------------------------------------------------------------

static const uint8_t kRp[32] = {0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04,
                                0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                                0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
                                0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c};

static void records_round_trip_through_the_codec(void) {
  uint8_t record[AUTH_RECORD_MAX];
  // Deliberately larger than a slot can hold, so the "id too big for a slot"
  // assertion below is not satisfied by a destination-capacity check instead.
  uint8_t roomy[AUTH_RECORD_MAX + 64];
  uint8_t id[AUTH_RESIDENT_ID_MAX + 64];
  for (unsigned i = 0; i < sizeof(id); i++) id[i] = (uint8_t)(i * 7 + 1);

  // Shortest legal id, an ordinary one, and the exact maximum.
  const uint16_t kShortest = AUTH_RECORD_MIN_SIZE - AUTH_RECORD_HEADER_SIZE;
  const uint16_t kLengths[] = {kShortest, 200, AUTH_RESIDENT_ID_MAX};
  const uint8_t kIndices[] = {0, 1, 50, 99};
  const uint32_t kGenerations[] = {0, 1, 0x01020304u, UINT32_MAX};

  for (unsigned l = 0; l < sizeof(kLengths) / sizeof(kLengths[0]); l++) {
    for (unsigned x = 0; x < sizeof(kIndices) / sizeof(kIndices[0]); x++) {
      for (unsigned g = 0; g < sizeof(kGenerations) / sizeof(kGenerations[0]);
           g++) {
        uint16_t length = 0;
        assert(auth_record_encode(kIndices[x], kGenerations[g], kRp, id,
                                  kLengths[l], record, sizeof(record),
                                  &length) == AUTH_OK);
        assert(length == AUTH_RECORD_HEADER_SIZE + kLengths[l]);

        auth_record_view view;
        assert(auth_record_decode(record, length, kIndices[x], &view) ==
               AUTH_OK);
        assert(view.index == kIndices[x]);
        assert(view.generation == kGenerations[g]);
        assert(view.id_len == kLengths[l]);
        assert(memcmp(view.rp, kRp, sizeof(kRp)) == 0);
        assert(memcmp(view.id, id, kLengths[l]) == 0);
      }
    }
  }

  // An id that does not fit a slot, and a destination that is too small.
  uint16_t length = 0;
  // Too big for a slot, with room to spare in the destination: only the slot
  // bound can reject this.
  assert(auth_record_encode(0, 1, kRp, id, AUTH_RESIDENT_ID_MAX + 1, roomy,
                            sizeof(roomy), &length) == AUTH_LIMIT_EXCEEDED);
  assert(auth_record_encode(0, 1, kRp, id, AUTH_RESIDENT_ID_MAX + 64, roomy,
                            sizeof(roomy), &length) == AUTH_LIMIT_EXCEEDED);
  // Fits a slot, but not the destination the caller offered.
  assert(auth_record_encode(0, 1, kRp, id, 200, record, 100, &length) ==
         AUTH_LIMIT_EXCEEDED);
  // A record shorter than the historical minimum would be unreadable, so it is
  // refused at creation rather than stored.
  assert(auth_record_encode(0, 1, kRp, id, kShortest - 1, record,
                            sizeof(record), &length) == AUTH_INVALID_ARGUMENT);
  assert(auth_record_encode(0, 1, kRp, id, 0, record, sizeof(record),
                            &length) == AUTH_INVALID_ARGUMENT);
  assert(auth_record_encode(100, 1, kRp, id, 200, record, sizeof(record),
                            &length) == AUTH_INVALID_ARGUMENT);
  assert(auth_record_encode(0, 1, NULL, id, 200, record, sizeof(record),
                            &length) == AUTH_INVALID_ARGUMENT);
  assert(auth_record_encode(0, 1, kRp, NULL, 200, record, sizeof(record),
                            &length) == AUTH_INVALID_ARGUMENT);
  assert(length == 0);
}

static void malformed_records_are_rejected(void) {
  uint8_t record[AUTH_RECORD_MAX];
  uint8_t id[256];
  memset(id, 0x3c, sizeof(id));
  uint16_t length = 0;
  assert(auth_record_encode(7, 5, kRp, id, sizeof(id), record, sizeof(record),
                            &length) == AUTH_OK);

  auth_record_view view;
  // Baseline decodes.
  assert(auth_record_decode(record, length, 7, &view) == AUTH_OK);

  // The slot it was read from must match the slot it names. This is the check
  // that stops a record from answering for its neighbour.
  assert(auth_record_decode(record, length, 8, &view) == AUTH_ERROR);
  assert(auth_record_decode(record, length, 0, &view) == AUTH_ERROR);

  const struct {
    unsigned offset;
    uint8_t value;
  } kCorruptions[] = {
      {0, 0xa3},                  // wrong tag, e.g. the old commit record's tag
      {0, 0x00}, {1, 0}, {1, 2},  // wrong version
      {3, 1},                     // reserved byte set
  };
  for (unsigned c = 0; c < sizeof(kCorruptions) / sizeof(kCorruptions[0]);
       c++) {
    uint8_t damaged[AUTH_RECORD_MAX];
    memcpy(damaged, record, length);
    damaged[kCorruptions[c].offset] = kCorruptions[c].value;
    assert(auth_record_decode(damaged, length, 7, &view) == AUTH_ERROR);
  }

  // Lengths outside the accepted band.
  assert(auth_record_decode(record, AUTH_RECORD_MIN_SIZE - 1, 7, &view) ==
         AUTH_ERROR);
  assert(auth_record_decode(record, 0, 7, &view) == AUTH_ERROR);
  assert(auth_record_decode(record, AUTH_RECORD_MAX + 1, 7, &view) ==
         AUTH_ERROR);
  assert(auth_record_decode(record, AUTH_RECORD_HEADER_SIZE, 7, &view) ==
         AUTH_ERROR);

  // Null arguments and a bad slot index.
  assert(auth_record_decode(NULL, length, 7, &view) == AUTH_INVALID_ARGUMENT);
  assert(auth_record_decode(record, length, 7, NULL) == AUTH_INVALID_ARGUMENT);
  assert(auth_record_decode(record, length, 100, &view) ==
         AUTH_INVALID_ARGUMENT);

  // Exactly the minimum length is legal.
  assert(auth_record_encode(7, 5, kRp, id,
                            AUTH_RECORD_MIN_SIZE - AUTH_RECORD_HEADER_SIZE,
                            record, sizeof(record), &length) == AUTH_OK);
  assert(length == AUTH_RECORD_MIN_SIZE);
  assert(auth_record_decode(record, length, 7, &view) == AUTH_OK);
}

static void generations_refuse_to_wrap(void) {
  uint32_t next = 0xffffffffu;
  assert(auth_record_next_generation(0, &next) == AUTH_OK && next == 1);
  assert(auth_record_next_generation(1, &next) == AUTH_OK && next == 2);
  assert(auth_record_next_generation(UINT32_MAX - 1, &next) == AUTH_OK &&
         next == UINT32_MAX);
  // Wrapping would let a replacement claim an older generation than the record
  // it replaced.
  assert(auth_record_next_generation(UINT32_MAX, &next) == AUTH_ERROR);
  assert(next == 0);
  assert(auth_record_next_generation(0, NULL) == AUTH_INVALID_ARGUMENT);
}

// End to end: a record built by the codec, stored through the manager, read
// back and decoded, is the same record.
static void stored_records_survive_the_codec(void) {
  provision_with_records();
  assert(auth_records_authenticate(kRoot) == AUTH_OK);

  uint8_t id[AUTH_RESIDENT_ID_MAX];
  for (unsigned i = 0; i < sizeof(id); i++) id[i] = (uint8_t)(0xff - i);
  uint8_t record[AUTH_RECORD_MAX];
  uint16_t length = 0;
  assert(auth_record_encode(42, 0x0a0b0c0du, kRp, id, sizeof(id), record,
                            sizeof(record), &length) == AUTH_OK);
  next_nonce();
  assert(auth_records_write(kRoot, 42, record, length, g_nonce) == AUTH_OK);

  uint8_t out[AUTH_RECORD_MAX];
  uint16_t read_length = 0;
  assert(auth_records_read(kRoot, 42, out, sizeof(out), &read_length) ==
         AUTH_OK);
  assert(read_length == length);

  auth_record_view view;
  assert(auth_record_decode(out, read_length, 42, &view) == AUTH_OK);
  assert(view.generation == 0x0a0b0c0du);
  assert(view.id_len == sizeof(id));
  assert(memcmp(view.rp, kRp, sizeof(kRp)) == 0);
  assert(memcmp(view.id, id, sizeof(id)) == 0);

  // Reading that record from any other slot must not decode, even though the
  // bytes are intact: the slot it came from is part of what makes it valid.
  assert(auth_record_decode(out, read_length, 41, &view) == AUTH_ERROR);
}

int main(void) {
  every_entry_point_fails_before_open();
  blank_media_permits_provisioning();
  unauthenticated_vault_refuses_provisioning();
  foreign_media_requires_migration_and_is_untouched();
  unreadable_media_fails_closed();
  records_require_authentication_first();
  records_round_trip_and_empty_slots_report_unprovisioned();
  bad_arguments_are_refused();
  repair_rebuilds_a_damaged_replica();
  wipe_clears_every_replica();
  partly_unreadable_media_is_not_provisionable();
  foreign_content_is_never_touched();

  unlock_recovers_the_root_and_selects_a_snapshot();
  a_kek_that_opens_nothing_is_damage();
  differing_envelopes_for_one_root_still_unlock();
  a_damaged_candidate_is_skipped();
  disagreeing_secrets_fail_closed();
  an_envelope_without_a_snapshot_is_rejected();
  unlock_rejects_bad_arguments();

  records_round_trip_through_the_codec();
  malformed_records_are_rejected();
  generations_refuse_to_wrap();
  stored_records_survive_the_codec();

  printf("replica records translation: PASS\n");
  return 0;
}
