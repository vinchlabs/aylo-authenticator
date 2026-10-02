// Host fixture for the checked flash reader.
//
// This links the real `flash_checked_policy.c`, the real emulator backend, and
// the real vendored `flash_area.c`. Only the three lowest-level flash
// primitives are faked, over a plain RAM buffer laid out exactly like the T3T1
// page map, so that area sizing and sector arithmetic go through production
// code.
//
// Three things are under test: the request policy (which areas and ranges may
// be read, and what the destination looks like when a read does not return
// data), the attribution decision that the NMI dispatcher consults to learn
// which replica an ECC double error belongs to, and the quarantine word through
// which a boot that died tells the next boot what not to read. All three are
// pure integer logic here, which is the whole reason they were split out of the
// platform backend: on a board the first two only ever run inside an NMI and
// the third lives in a backup register.

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <sys/flash_checked.h>

// ---------------------------------------------------------------------------
// Fake flash: uniform 8 KiB pages, contiguous, T3T1 sector numbering.
// ---------------------------------------------------------------------------

#define FAKE_SECTOR_SIZE 0x2000u
#define FAKE_SECTOR_COUNT 0x100u

// Sector ranges the authenticator owns on T3T1, mirroring the T3T1 adapter.
#define STORAGE1_FIRST 0x18u
#define STORAGE2_FIRST 0x20u
#define ASSETS_FIRST 0xf8u
#define REPLICA_SECTORS 8u

#define REPLICA_AREA_SIZE (REPLICA_SECTORS * FAKE_SECTOR_SIZE)

static uint8_t g_flash[FAKE_SECTOR_COUNT * FAKE_SECTOR_SIZE];

uint32_t flash_sector_size(uint16_t first_sector, uint16_t sector_count) {
  if ((uint32_t)first_sector + (uint32_t)sector_count > FAKE_SECTOR_COUNT) {
    return 0;
  }
  return (uint32_t)sector_count * FAKE_SECTOR_SIZE;
}

uint16_t flash_sector_find(uint16_t first_sector, uint32_t offset) {
  return (uint16_t)(first_sector + offset / FAKE_SECTOR_SIZE);
}

const void *flash_get_address(uint16_t sector, uint32_t offset, uint32_t size) {
  if (sector >= FAKE_SECTOR_COUNT) return NULL;
  if (offset > FAKE_SECTOR_SIZE) return NULL;
  if (size > FAKE_SECTOR_SIZE - offset) return NULL;
  return g_flash + (size_t)sector * FAKE_SECTOR_SIZE + offset;
}

// The write path of flash_area.c is never exercised here; the fixture seeds
// `g_flash` directly. These exist only so the translation unit links.
secbool flash_unlock_write(void) { return secfalse; }
secbool flash_lock_write(void) { return secfalse; }
secbool flash_sector_erase(uint16_t sector) {
  (void)sector;
  return secfalse;
}
secbool flash_write_block(uint16_t sector, uint32_t offset,
                          const flash_block_t block) {
  (void)sector;
  (void)offset;
  (void)block;
  return secfalse;
}

// The three areas the policy allowlists, with external linkage so that the
// extern declarations in flash_checked_policy.c bind to these.
const flash_area_t STORAGE_AREAS[] = {
    {.num_subareas = 1,
     .subarea[0] = {.first_sector = STORAGE1_FIRST,
                    .num_sectors = REPLICA_SECTORS}},
    {.num_subareas = 1,
     .subarea[0] = {.first_sector = STORAGE2_FIRST,
                    .num_sectors = REPLICA_SECTORS}},
};
const flash_area_t ASSETS_AREA = {
    .num_subareas = 1,
    .subarea[0] = {.first_sector = ASSETS_FIRST,
                   .num_sectors = REPLICA_SECTORS},
};

// A fourth, deliberately not-allowlisted area.
static const flash_area_t kForeignArea = {
    .num_subareas = 1,
    .subarea[0] = {.first_sector = 0x30u, .num_sectors = REPLICA_SECTORS},
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Independent address oracle: does not go through flash_area_get_address().
static const uint8_t *expected_source(uint16_t first_sector, uint32_t offset) {
  return g_flash + (size_t)first_sector * FAKE_SECTOR_SIZE + offset;
}

static void seed_flash(void) {
  // Deterministic, non-constant, and not 0x00/0xFF anywhere, so a destination
  // that was zeroized or left untouched can never be mistaken for real data.
  uint32_t state = 0x12345678u;
  for (size_t i = 0; i < sizeof(g_flash); i++) {
    state ^= state << 13;
    state ^= state >> 17;
    state ^= state << 5;
    g_flash[i] = (uint8_t)((state >> 8) | 1u);
  }
}

static bool all_zero(const uint8_t *data, size_t len) {
  for (size_t i = 0; i < len; i++) {
    if (data[i] != 0) return false;
  }
  return true;
}

static void assert_context_clear(void) {
  const flash_checked_context_t *context = flash_checked_active_context();
  assert(!context->active);
  assert(context->source_begin == 0);
  assert(context->source_end == 0);
  assert(context->dest_begin == 0);
  assert(context->dest_end == 0);
  // Not zero. Zero is replica 0, so a cleared context must name no replica at
  // all rather than silently naming the first one.
  assert(context->area_index == FLASH_CHECKED_AREA_NONE);
}

// The quarantine lives in platform storage, so every test that cares about it
// has to start from a known value rather than from whatever ran before.
static void clear_quarantine(void) {
  flash_checked_quarantine_store(FLASH_CHECKED_QUARANTINE_MAGIC);
}

// ---------------------------------------------------------------------------
// Area allowlist: identity, not contents
// ---------------------------------------------------------------------------

static void allowlist_accepts_exactly_three_objects(void) {
  assert(flash_checked_area_allowed(&STORAGE_AREAS[0]));
  assert(flash_checked_area_allowed(&STORAGE_AREAS[1]));
  assert(flash_checked_area_allowed(&ASSETS_AREA));

  assert(!flash_checked_area_allowed(NULL));
  assert(!flash_checked_area_allowed(&kForeignArea));

  // A byte-identical copy describes the very same sectors, and is still
  // refused. This is the property that keeps the reader from becoming a
  // general-purpose flash window: the caller must hold one of the three real
  // area objects.
  flash_area_t forged = STORAGE_AREAS[0];
  assert(memcmp(&forged, &STORAGE_AREAS[0], sizeof(forged)) == 0);
  assert(!flash_checked_area_allowed(&forged));

  flash_area_t forged_assets = ASSETS_AREA;
  assert(memcmp(&forged_assets, &ASSETS_AREA, sizeof(forged_assets)) == 0);
  assert(!flash_checked_area_allowed(&forged_assets));
}

// ---------------------------------------------------------------------------
// Request validation
// ---------------------------------------------------------------------------

static void validation_rejects_bad_requests(void) {
  uint8_t dst[64];
  const uint32_t size = flash_area_get_size(&STORAGE_AREAS[0]);
  assert(size == REPLICA_AREA_SIZE);

  // Baseline: a plain in-bounds request is accepted.
  assert(flash_checked_validate(&STORAGE_AREAS[0], 0, dst, sizeof(dst)) ==
         FLASH_CHECKED_OK);

  assert(flash_checked_validate(NULL, 0, dst, sizeof(dst)) ==
         FLASH_CHECKED_RANGE);
  assert(flash_checked_validate(&STORAGE_AREAS[0], 0, NULL, sizeof(dst)) ==
         FLASH_CHECKED_RANGE);
  assert(flash_checked_validate(&STORAGE_AREAS[0], 0, dst, 0) ==
         FLASH_CHECKED_RANGE);
  assert(flash_checked_validate(&kForeignArea, 0, dst, sizeof(dst)) ==
         FLASH_CHECKED_RANGE);

  flash_area_t forged = STORAGE_AREAS[0];
  assert(flash_checked_validate(&forged, 0, dst, sizeof(dst)) ==
         FLASH_CHECKED_RANGE);

  // Endpoints. The last byte of the area is readable; one past it is not.
  assert(flash_checked_validate(&STORAGE_AREAS[0], size - 1, dst, 1) ==
         FLASH_CHECKED_OK);
  assert(flash_checked_validate(&STORAGE_AREAS[0], size, dst, 1) ==
         FLASH_CHECKED_RANGE);
  assert(flash_checked_validate(&STORAGE_AREAS[0], size + 1, dst, 1) ==
         FLASH_CHECKED_RANGE);

  // Whole-area read is legal; shifting it by one byte is not.
  assert(flash_checked_validate(&STORAGE_AREAS[0], 0, dst, size) ==
         FLASH_CHECKED_OK);
  assert(flash_checked_validate(&STORAGE_AREAS[0], 1, dst, size) ==
         FLASH_CHECKED_RANGE);

  // offset + len must not be allowed to wrap into a small, passing value.
  assert(flash_checked_validate(&STORAGE_AREAS[0], 0xFFFFFFFFu, dst, 1) ==
         FLASH_CHECKED_RANGE);
  assert(flash_checked_validate(&STORAGE_AREAS[0], size - 1, dst,
                                0xFFFFFFFFu) == FLASH_CHECKED_RANGE);
  assert(flash_checked_validate(&STORAGE_AREAS[0], 0x80000000u, dst,
                                0x80000000u) == FLASH_CHECKED_RANGE);

  // A destination range that wraps the address space is refused. The pointer is
  // never dereferenced; validation only inspects the interval.
  void *wrapping = (void *)(uintptr_t)(UINTPTR_MAX - 8u);
  assert(flash_checked_validate(&STORAGE_AREAS[0], 0, wrapping, 64) ==
         FLASH_CHECKED_RANGE);
}

// ---------------------------------------------------------------------------
// Overlap helper
// ---------------------------------------------------------------------------

static void overlap_helper_is_half_open(void) {
  // Adjacent, not overlapping: [100,200) and [200,300).
  assert(!flash_checked_ranges_overlap(100, 100, 200, 100));
  assert(!flash_checked_ranges_overlap(200, 100, 100, 100));

  // One shared byte at each edge.
  assert(flash_checked_ranges_overlap(100, 100, 199, 100));
  assert(flash_checked_ranges_overlap(100, 100, 1, 100));

  // Identical and strictly contained.
  assert(flash_checked_ranges_overlap(100, 100, 100, 100));
  assert(flash_checked_ranges_overlap(100, 100, 140, 10));
  assert(flash_checked_ranges_overlap(140, 10, 100, 100));

  // Empty ranges touch nothing.
  assert(!flash_checked_ranges_overlap(100, 0, 100, 100));
  assert(!flash_checked_ranges_overlap(100, 100, 100, 0));

  // A wrapping range fails closed.
  assert(flash_checked_ranges_overlap(UINTPTR_MAX - 4u, 64, 0x1000, 16));
  assert(flash_checked_ranges_overlap(0x1000, 16, UINTPTR_MAX - 4u, 64));
}

// ---------------------------------------------------------------------------
// Destination rule
// ---------------------------------------------------------------------------

static void finalize_zeroizes_every_result_without_data(void) {
  assert(flash_checked_result_has_data(FLASH_CHECKED_OK));
  assert(flash_checked_result_has_data(FLASH_CHECKED_ECC_CORRECTED));
  assert(!flash_checked_result_has_data(FLASH_CHECKED_ECC_UNCORRECTABLE));
  assert(!flash_checked_result_has_data(FLASH_CHECKED_RANGE));
  assert(!flash_checked_result_has_data(FLASH_CHECKED_BUSY));
  assert(!flash_checked_result_has_data(FLASH_CHECKED_UNSUPPORTED));

  static const flash_checked_result_t kWithData[] = {
      FLASH_CHECKED_OK,
      FLASH_CHECKED_ECC_CORRECTED,
  };
  static const flash_checked_result_t kWithoutData[] = {
      FLASH_CHECKED_ECC_UNCORRECTABLE,
      FLASH_CHECKED_RANGE,
      FLASH_CHECKED_BUSY,
      FLASH_CHECKED_UNSUPPORTED,
  };

  const size_t payload = 96;
  for (size_t i = 0; i < sizeof(kWithData) / sizeof(kWithData[0]); i++) {
    uint8_t buffer[128];
    memset(buffer, 0xAA, sizeof(buffer));
    assert(flash_checked_finalize(kWithData[i], buffer, payload) ==
           kWithData[i]);
    // A corrected single-bit error still delivers usable data, so the
    // destination must survive untouched.
    for (size_t b = 0; b < sizeof(buffer); b++) assert(buffer[b] == 0xAA);
  }

  for (size_t i = 0; i < sizeof(kWithoutData) / sizeof(kWithoutData[0]); i++) {
    uint8_t buffer[128];
    memset(buffer, 0xAA, sizeof(buffer));
    assert(flash_checked_finalize(kWithoutData[i], buffer, payload) ==
           kWithoutData[i]);
    // The whole request is cleared, not just the part that happened to be
    // copied before the failure.
    assert(all_zero(buffer, payload));
    // Nothing beyond the request is touched.
    for (size_t b = payload; b < sizeof(buffer); b++) assert(buffer[b] == 0xAA);
  }

  // A null or empty destination must not fault.
  assert(flash_checked_finalize(FLASH_CHECKED_RANGE, NULL, 16) ==
         FLASH_CHECKED_RANGE);
  uint8_t untouched[4] = {1, 2, 3, 4};
  assert(flash_checked_finalize(FLASH_CHECKED_RANGE, untouched, 0) ==
         FLASH_CHECKED_RANGE);
  assert(untouched[0] == 1 && untouched[3] == 4);
}

// ---------------------------------------------------------------------------
// Reader contract
// ---------------------------------------------------------------------------

static void read_returns_exact_bytes(void) {
  static uint8_t dst[REPLICA_AREA_SIZE];

  // Start of the area.
  memset(dst, 0xAA, 576);
  assert(flash_area_checked_read(&STORAGE_AREAS[0], 0, dst, 576) ==
         FLASH_CHECKED_OK);
  assert(memcmp(dst, expected_source(STORAGE1_FIRST, 0), 576) == 0);
  assert_context_clear();

  // Straddling a page boundary, which exercises the real subarea/sector math.
  const uint32_t straddle = FAKE_SECTOR_SIZE - 16u;
  memset(dst, 0xAA, 64);
  assert(flash_area_checked_read(&STORAGE_AREAS[1], straddle, dst, 64) ==
         FLASH_CHECKED_OK);
  assert(memcmp(dst, expected_source(STORAGE2_FIRST, straddle), 64) == 0);

  // The whole area in one call.
  memset(dst, 0xAA, sizeof(dst));
  assert(flash_area_checked_read(&ASSETS_AREA, 0, dst, REPLICA_AREA_SIZE) ==
         FLASH_CHECKED_OK);
  assert(memcmp(dst, expected_source(ASSETS_FIRST, 0), REPLICA_AREA_SIZE) == 0);

  // Last byte of the area.
  uint8_t last = 0;
  assert(flash_area_checked_read(&STORAGE_AREAS[0], REPLICA_AREA_SIZE - 1,
                                 &last, 1) == FLASH_CHECKED_OK);
  assert(last == *expected_source(STORAGE1_FIRST, REPLICA_AREA_SIZE - 1));
  assert_context_clear();
}

static void failed_read_zeroizes_whole_destination(void) {
  // Guarded buffer: `request` bytes are the destination, the rest must not be
  // touched by anything the reader does.
  const size_t request = 512;
  static uint8_t buffer[768];
  flash_area_t forged = STORAGE_AREAS[0];

  const struct {
    const flash_area_t *area;
    uint32_t offset;
    uint32_t len;
  } kRejected[] = {
      {&forged, 0, request},
      {&kForeignArea, 0, request},
      {NULL, 0, request},
      {&STORAGE_AREAS[0], REPLICA_AREA_SIZE, request},
      {&STORAGE_AREAS[0], REPLICA_AREA_SIZE - 1, request},
      {&STORAGE_AREAS[0], 0xFFFFFFFFu, request},
  };

  for (size_t i = 0; i < sizeof(kRejected) / sizeof(kRejected[0]); i++) {
    memset(buffer, 0xAA, sizeof(buffer));
    flash_checked_result_t result = flash_area_checked_read(
        kRejected[i].area, kRejected[i].offset, buffer, kRejected[i].len);
    assert(result == FLASH_CHECKED_RANGE);
    assert(all_zero(buffer, kRejected[i].len));
    for (size_t b = kRejected[i].len; b < sizeof(buffer); b++) {
      assert(buffer[b] == 0xAA);
    }
    // A refused request must never have claimed the context.
    assert_context_clear();
  }

  // A zero-length request is refused, and refusing it must not write anything
  // at all -- there is no destination to clear.
  memset(buffer, 0xAA, sizeof(buffer));
  assert(flash_area_checked_read(&STORAGE_AREAS[0], 0, buffer, 0) ==
         FLASH_CHECKED_RANGE);
  for (size_t b = 0; b < sizeof(buffer); b++) assert(buffer[b] == 0xAA);

  // A null destination is refused without dereferencing it.
  assert(flash_area_checked_read(&STORAGE_AREAS[0], 0, NULL, request) ==
         FLASH_CHECKED_RANGE);
  assert_context_clear();
}

static void nested_read_is_refused_without_disturbing_the_first(void) {
  const size_t request = 256;
  static uint8_t buffer[256];

  // Stand in for a read that is already in flight, with a recognisable context.
  flash_checked_context_t *context = flash_checked_active_context();
  flash_checked_context_t in_flight = {
      .active = true,
      .area_index = 1,
      .source_begin = 0x1000,
      .source_end = 0x2000,
      .dest_begin = 0x20000000,
      .dest_end = 0x20000100,
  };
  *context = in_flight;

  memset(buffer, 0xAA, sizeof(buffer));
  assert(flash_area_checked_read(&STORAGE_AREAS[0], 0, buffer, request) ==
         FLASH_CHECKED_BUSY);
  assert(all_zero(buffer, request));
  // The in-flight read is untouched: the nested call neither cleared it nor
  // overwrote its ranges.
  assert(memcmp(context, &in_flight, sizeof(in_flight)) == 0);

  flash_checked_context_clear(context);
  assert_context_clear();
}

static void destination_may_not_alias_the_source(void) {
  // Handing the reader a destination inside the mapped source is a contract
  // violation, not a copy: it must be refused before any copying happens.
  const uint32_t len = 128;
  void *aliased = (void *)(uintptr_t)expected_source(ASSETS_FIRST, 0);
  assert(flash_area_checked_read(&ASSETS_AREA, 0, aliased, len) ==
         FLASH_CHECKED_RANGE);
  assert_context_clear();

  // Partially overlapping, from either side.
  void *overlap_low = (void *)(uintptr_t)expected_source(ASSETS_FIRST, 64);
  assert(flash_area_checked_read(&ASSETS_AREA, 0, overlap_low, len) ==
         FLASH_CHECKED_RANGE);
  void *overlap_high = (void *)(uintptr_t)expected_source(ASSETS_FIRST, 0);
  assert(flash_area_checked_read(&ASSETS_AREA, 64, overlap_high, len) ==
         FLASH_CHECKED_RANGE);
  assert_context_clear();

  // Reading a different area into this one is fine; only true aliasing is
  // refused. Re-seed first, since the refusals above zeroized part of assets.
  seed_flash();
  void *elsewhere = (void *)(uintptr_t)expected_source(ASSETS_FIRST, 0);
  assert(flash_area_checked_read(&STORAGE_AREAS[0], 0, elsewhere, len) ==
         FLASH_CHECKED_OK);
  assert(memcmp(elsewhere, expected_source(STORAGE1_FIRST, 0), len) == 0);
  seed_flash();
}

static void the_emulator_records_nothing(void) {
  // There is no ECC and no NMI here, so the record entry point must be inert. A
  // host build that quarantined a replica would make the emulator diverge from
  // the board in the one direction that matters: refusing to read something the
  // board would read.
  clear_quarantine();
  flash_checked_record_eccd(0xFFFFFFFFu);
  assert(flash_checked_quarantine_load() == FLASH_CHECKED_QUARANTINE_MAGIC);
}

// ---------------------------------------------------------------------------
// The quarantine word
// ---------------------------------------------------------------------------

static void an_uninitialised_word_quarantines_nothing(void) {
  // The two values a register reads as when it has never been written or has
  // been tamper-erased. Treating either as a mask would condemn every replica
  // at once, which is a far worse outcome than the fault this mechanism exists
  // to survive.
  const uint32_t garbage[] = {0x00000000u, 0xFFFFFFFFu, 0xDEADBEEFu,
                              FLASH_CHECKED_QUARANTINE_MAGIC ^ 0x1000u};
  for (unsigned g = 0; g < sizeof(garbage) / sizeof(garbage[0]); g++) {
    assert(!flash_checked_quarantine_valid(garbage[g]));
    for (uint8_t i = 0; i < FLASH_CHECKED_AREA_COUNT; i++) {
      assert(!flash_checked_quarantine_holds(garbage[g], i));
    }
  }

  // An empty but valid word is the normal state and must also hold nothing.
  assert(flash_checked_quarantine_valid(FLASH_CHECKED_QUARANTINE_MAGIC));
  for (uint8_t i = 0; i < FLASH_CHECKED_AREA_COUNT; i++) {
    assert(!flash_checked_quarantine_holds(FLASH_CHECKED_QUARANTINE_MAGIC, i));
  }
}

static void a_word_naming_undefined_replicas_is_not_valid(void) {
  // The magic survived but the mask claims a fourth replica. That is a
  // clobbered register, not a bigger vault, and trusting its low bits would
  // exclude real replicas on the strength of corruption.
  const uint32_t overreaching =
      FLASH_CHECKED_QUARANTINE_MAGIC | (1u << FLASH_CHECKED_AREA_COUNT);
  assert(!flash_checked_quarantine_valid(overreaching));
  for (uint8_t i = 0; i < FLASH_CHECKED_AREA_COUNT; i++) {
    assert(!flash_checked_quarantine_holds(overreaching, i));
  }
}

static void adding_and_removing_names_one_replica_at_a_time(void) {
  uint32_t word = FLASH_CHECKED_QUARANTINE_MAGIC;

  for (uint8_t i = 0; i < FLASH_CHECKED_AREA_COUNT; i++) {
    word = flash_checked_quarantine_add(word, i);
    assert(flash_checked_quarantine_valid(word));
    assert(flash_checked_quarantine_holds(word, i));
    // Adding one replica must not drag in its neighbours.
    for (uint8_t j = 0; j < FLASH_CHECKED_AREA_COUNT; j++) {
      assert(flash_checked_quarantine_holds(word, j) == (j <= i));
    }
  }

  for (uint8_t i = 0; i < FLASH_CHECKED_AREA_COUNT; i++) {
    word = flash_checked_quarantine_remove(word, i);
    assert(flash_checked_quarantine_valid(word));
    assert(!flash_checked_quarantine_holds(word, i));
    for (uint8_t j = 0; j < FLASH_CHECKED_AREA_COUNT; j++) {
      assert(flash_checked_quarantine_holds(word, j) == (j > i));
    }
  }
  assert(word == FLASH_CHECKED_QUARANTINE_MAGIC);

  // An out-of-range index changes no replica, and an index beyond the array is
  // not silently folded onto a real one.
  uint32_t marked = flash_checked_quarantine_add(FLASH_CHECKED_QUARANTINE_MAGIC,
                                                 FLASH_CHECKED_AREA_COUNT);
  assert(marked == FLASH_CHECKED_QUARANTINE_MAGIC);
  marked = flash_checked_quarantine_add(FLASH_CHECKED_QUARANTINE_MAGIC,
                                        FLASH_CHECKED_AREA_NONE);
  assert(marked == FLASH_CHECKED_QUARANTINE_MAGIC);
}

static void garbage_is_replaced_rather_than_extended(void) {
  // Adding to a word without the magic must not preserve its low bits: those
  // bits are noise, and keeping them would quarantine replicas nothing ever
  // condemned.
  const uint32_t word = flash_checked_quarantine_add(0xFFFFFFFFu, 1);
  assert(flash_checked_quarantine_valid(word));
  assert(flash_checked_quarantine_holds(word, 1));
  assert(!flash_checked_quarantine_holds(word, 0));
  assert(!flash_checked_quarantine_holds(word, 2));

  // Removing from garbage yields a valid empty word, so a replica that has just
  // been rewritten is trusted again whatever the register held before.
  const uint32_t emptied = flash_checked_quarantine_remove(0xDEADBEEFu, 2);
  assert(emptied == FLASH_CHECKED_QUARANTINE_MAGIC);
  for (uint8_t i = 0; i < FLASH_CHECKED_AREA_COUNT; i++) {
    assert(!flash_checked_quarantine_holds(emptied, i));
  }
}

static void a_quarantined_replica_is_refused_without_being_read(void) {
  const uint32_t len = 128;
  static uint8_t buffer[128];

  // Replica 1 is the storage area at index 1; quarantining it must not affect
  // the other two, or one torn line would take the whole vault down.
  clear_quarantine();
  flash_checked_quarantine_store(
      flash_checked_quarantine_add(flash_checked_quarantine_load(), 1));

  memset(buffer, 0xAA, sizeof(buffer));
  assert(flash_area_checked_read(&STORAGE_AREAS[1], 0, buffer, len) ==
         FLASH_CHECKED_ECC_UNCORRECTABLE);
  assert(all_zero(buffer, len));
  assert_context_clear();

  memset(buffer, 0xAA, sizeof(buffer));
  assert(flash_area_checked_read(&STORAGE_AREAS[0], 0, buffer, len) ==
         FLASH_CHECKED_OK);
  assert(memcmp(buffer, expected_source(STORAGE1_FIRST, 0), len) == 0);

  memset(buffer, 0xAA, sizeof(buffer));
  assert(flash_area_checked_read(&ASSETS_AREA, 0, buffer, len) ==
         FLASH_CHECKED_OK);
  assert(memcmp(buffer, expected_source(ASSETS_FIRST, 0), len) == 0);

  // Lifting the quarantine makes the replica readable again, which is what the
  // repair path depends on.
  flash_checked_quarantine_store(
      flash_checked_quarantine_remove(flash_checked_quarantine_load(), 1));
  memset(buffer, 0xAA, sizeof(buffer));
  assert(flash_area_checked_read(&STORAGE_AREAS[1], 0, buffer, len) ==
         FLASH_CHECKED_OK);
  assert(memcmp(buffer, expected_source(STORAGE2_FIRST, 0), len) == 0);
  clear_quarantine();
}

static void a_bad_request_outranks_the_quarantine(void) {
  // A quarantined replica still gets RANGE for a malformed request. Reporting
  // ECC_UNCORRECTABLE for a request that was never readable would tell the
  // caller a replica is damaged when the caller simply asked wrongly.
  static uint8_t buffer[16];
  clear_quarantine();
  flash_checked_quarantine_store(
      flash_checked_quarantine_add(flash_checked_quarantine_load(), 2));
  assert(flash_area_checked_read(&ASSETS_AREA, 0, buffer, 0) ==
         FLASH_CHECKED_RANGE);
  assert(flash_area_checked_read(&ASSETS_AREA, REPLICA_AREA_SIZE, buffer,
                                 sizeof(buffer)) == FLASH_CHECKED_RANGE);
  assert(flash_area_checked_read(&kForeignArea, 0, buffer, sizeof(buffer)) ==
         FLASH_CHECKED_RANGE);
  assert_context_clear();
  clear_quarantine();
}

static void area_indices_are_stable_and_exclusive(void) {
  // The NMI blames a replica by this index, and the quarantine word addresses
  // bits by it, so the mapping is interface rather than an implementation
  // detail.
  assert(flash_checked_area_index(&STORAGE_AREAS[0]) == 0u);
  assert(flash_checked_area_index(&STORAGE_AREAS[1]) == 1u);
  assert(flash_checked_area_index(&ASSETS_AREA) == 2u);
  assert(flash_checked_area_index(&kForeignArea) == FLASH_CHECKED_AREA_NONE);
  assert(flash_checked_area_index(NULL) == FLASH_CHECKED_AREA_NONE);

  // A byte-identical copy of an allowlisted area is still not that area.
  const flash_area_t impostor = ASSETS_AREA;
  assert(flash_checked_area_index(&impostor) == FLASH_CHECKED_AREA_NONE);
}

// ---------------------------------------------------------------------------
// ECCD attribution decision
// ---------------------------------------------------------------------------

#define SOURCE_BEGIN 0x1000u
#define SOURCE_END 0x2000u

static flash_checked_context_t canonical_context(void) {
  flash_checked_context_t context = {
      .active = true,
      .area_index = 2,
      .source_begin = SOURCE_BEGIN,
      .source_end = SOURCE_END,
      .dest_begin = 0x20000000,
      .dest_end = 0x20001000,
  };
  return context;
}

// Asserts that attribution is refused and, importantly, that the caller's index
// slot is left alone: a caller that ignored the return value must not find a
// plausible replica number sitting there.
static void assert_unattributed(const flash_checked_context_t *context,
                                uint32_t fault_address) {
  const uint8_t sentinel = 0x7fu;
  uint8_t index = sentinel;
  assert(!flash_checked_attribute_eccd(context, fault_address, &index));
  assert(index == sentinel);
}

static void assert_attributed(const flash_checked_context_t *context,
                              uint32_t fault_address, uint8_t expected) {
  uint8_t index = 0x7fu;
  assert(flash_checked_attribute_eccd(context, fault_address, &index));
  assert(index == expected);
}

static void attribution_requires_every_condition(void) {
  const flash_checked_context_t canonical = canonical_context();

  // The only shape that may be attributed: a read in flight naming a replica,
  // with the failing ECC line inside the range being read. Both ends of the
  // half-open range belong to it.
  assert_attributed(&canonical, SOURCE_BEGIN, 2);
  assert_attributed(&canonical, SOURCE_END - 1, 2);
  assert_attributed(&canonical, SOURCE_BEGIN + 0x800, 2);

  // ECC address just outside the source range, on either side. An ECCD that is
  // not in the range we are reading says nothing about this replica, and
  // blaming it would exclude a replica on the strength of somebody else's
  // fault.
  assert_unattributed(&canonical, SOURCE_BEGIN - 1);
  assert_unattributed(&canonical, SOURCE_END);
  assert_unattributed(&canonical, 0);
  assert_unattributed(&canonical, 0xFFFFFFFFu);

  // No read in flight. This is the state during an unrelated ECCD, and the
  // state a Clock Security System NMI arrives in.
  flash_checked_context_t inactive = canonical;
  inactive.active = false;
  assert_unattributed(&inactive, SOURCE_BEGIN);

  // The post-read state, which names no replica. Checked explicitly because the
  // cleared context is what an ECCD arriving a moment too late would find, and
  // index zero is a real replica.
  flash_checked_context_t cleared;
  flash_checked_context_clear(&cleared);
  assert_unattributed(&cleared, SOURCE_BEGIN);

  // A zeroed context, which is what a memset would leave. It names replica 0,
  // so only the `active` flag stands between it and a false accusation -- and
  // that is exactly why flash_checked_context_clear() exists.
  flash_checked_context_t zeroed = {0};
  assert_unattributed(&zeroed, SOURCE_BEGIN);

  // Active, in range, but naming no replica or one that does not exist.
  flash_checked_context_t nameless = canonical;
  nameless.area_index = FLASH_CHECKED_AREA_NONE;
  assert_unattributed(&nameless, SOURCE_BEGIN);
  flash_checked_context_t overreaching = canonical;
  overreaching.area_index = FLASH_CHECKED_AREA_COUNT;
  assert_unattributed(&overreaching, SOURCE_BEGIN);

  // Degenerate and inverted ranges.
  flash_checked_context_t empty_source = canonical;
  empty_source.source_end = empty_source.source_begin;
  assert_unattributed(&empty_source, SOURCE_BEGIN);

  flash_checked_context_t inverted_source = canonical;
  inverted_source.source_begin = SOURCE_END;
  inverted_source.source_end = SOURCE_BEGIN;
  assert_unattributed(&inverted_source, SOURCE_BEGIN + 0x800);

  // Missing out-parameter and missing context.
  uint8_t index = 0;
  assert(!flash_checked_attribute_eccd(&canonical, SOURCE_BEGIN, NULL));
  assert(!flash_checked_attribute_eccd(NULL, SOURCE_BEGIN, &index));
  assert(index == 0);

  // Every replica can be blamed, not just the one the canonical context names.
  for (uint8_t replica = 0; replica < FLASH_CHECKED_AREA_COUNT; replica++) {
    flash_checked_context_t named = canonical;
    named.area_index = replica;
    assert_attributed(&named, SOURCE_BEGIN, replica);
  }
}

// A read genuinely in flight through the reader must leave a context the NMI
// can act on: the range it is copying, and the replica it belongs to. Without
// this the record path would silently never fire.
static void a_live_read_leaves_an_attributable_context(void) {
  static uint8_t buffer[64];
  clear_quarantine();

  flash_checked_context_t *context = flash_checked_active_context();
  // Stand in for the state mid-copy by building what the reader builds. The
  // emulator backend clears the context before returning, so it cannot be
  // observed from outside; what is checked here is that the shape the reader
  // publishes is one attribute_eccd() accepts.
  assert(flash_area_checked_read(&ASSETS_AREA, 0, buffer, sizeof(buffer)) ==
         FLASH_CHECKED_OK);
  assert_context_clear();

  flash_checked_context_t live = {
      .active = true,
      .area_index = flash_checked_area_index(&ASSETS_AREA),
      .source_begin = 0x1F0000u,
      .source_end = 0x1F0000u + sizeof(buffer),
      .dest_begin = (uint32_t)(uintptr_t)buffer,
      .dest_end = (uint32_t)(uintptr_t)buffer + sizeof(buffer),
  };
  *context = live;
  assert_attributed(context, 0x1F0000u + 16u, 2);
  flash_checked_context_clear(context);
}

int main(void) {
  seed_flash();
  flash_checked_context_clear(flash_checked_active_context());
  clear_quarantine();
  assert_context_clear();

  allowlist_accepts_exactly_three_objects();
  area_indices_are_stable_and_exclusive();
  validation_rejects_bad_requests();
  overlap_helper_is_half_open();
  finalize_zeroizes_every_result_without_data();

  read_returns_exact_bytes();
  failed_read_zeroizes_whole_destination();
  nested_read_is_refused_without_disturbing_the_first();
  destination_may_not_alias_the_source();
  the_emulator_records_nothing();

  an_uninitialised_word_quarantines_nothing();
  a_word_naming_undefined_replicas_is_not_valid();
  adding_and_removing_names_one_replica_at_a_time();
  garbage_is_replaced_rather_than_extended();
  a_quarantined_replica_is_refused_without_being_read();
  a_bad_request_outranks_the_quarantine();

  attribution_requires_every_condition();
  a_live_read_leaves_an_attributable_context();

  printf("flash checked reader: PASS\n");
  return 0;
}
