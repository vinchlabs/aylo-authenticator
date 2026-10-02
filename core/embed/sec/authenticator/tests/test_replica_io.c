// Host fixture for the T3T1 replica IO adapter and the device wipe policy.
//
// This compiles the real `stm32u5/authenticator_replica_io.c` and the real
// `sys/flash/flash_utils.c` against recording doubles for flash, the checked
// reader, and the MPU. The adapter is the single place that turns a logical
// replica index into a physical flash area, so what is under test is exactly
// that binding plus the discipline around it:
//
//   * index 0/1/2 land on the storage-1, storage-2 and assets sectors and
//     nowhere else, checked against literal sector numbers rather than the
//     macros the adapter itself uses;
//   * every other index, and every misaligned or wrong-sized request, is
//     refused *before* any flash call happens;
//   * the MPU is switched to the mode that area needs and restored on every
//     path, including the failing ones;
//   * a line program happens with flash write unlocked, and the unlock is
//     always dropped again;
//   * a checked read that does not carry data can never surface as data --
//     in particular FLASH_CHECKED_UNSUPPORTED, which is what an ordinary
//     hardware image returns while ECCD containment is unvalidated;
//   * with reads failing that way the manager must fail closed: no provision,
//     no erase, no write;
//   * the authenticator's own wipe touches those three areas and nothing else;
//   * a full device wipe still covers all three, so replica 2 in assets cannot
//     be orphaned by a wipe that only remembers storage.

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <sys/flash.h>
#include <sys/flash_checked.h>
#include <sys/flash_utils.h>
#include <sys/mpu.h>

#include "../authenticator_replica_io.h"
#include "../replica_store.h"

// ---------------------------------------------------------------------------
// The three areas, defined here with literal T3T1 sector numbers so that the
// mapping assertions have an oracle independent of the macros the adapter uses.
// ---------------------------------------------------------------------------

#define PAGE AUTH_REPLICA_PAGE_SIZE
#define PAGES AUTH_REPLICA_PAGES_PER_AREA
#define AREA AUTH_REPLICA_AREA_SIZE

const flash_area_t STORAGE_AREAS[STORAGE_AREAS_COUNT] = {
    {.num_subareas = 1, .subarea[0] = {.first_sector = 0x18, .num_sectors = 8}},
    {.num_subareas = 1, .subarea[0] = {.first_sector = 0x20, .num_sectors = 8}},
};
const flash_area_t ASSETS_AREA = {
    .num_subareas = 1,
    .subarea[0] = {.first_sector = 0xf8, .num_sectors = 8},
};
// Stands in for a region the adapter must never reach.
static const flash_area_t kFirmwareArea = {
    .num_subareas = 1,
    .subarea[0] = {.first_sector = 0x28, .num_sectors = 208},
};

// ---------------------------------------------------------------------------
// MPU double
// ---------------------------------------------------------------------------

static mpu_mode_t g_mpu_mode = MPU_MODE_DEFAULT;
// Net reconfig-minus-restore count; must be back to zero after every adapter
// call, whether it succeeded or failed.
static int g_mpu_depth = 0;

mpu_mode_t mpu_get_mode(void) { return g_mpu_mode; }

mpu_mode_t mpu_reconfig(mpu_mode_t mode) {
  mpu_mode_t previous = g_mpu_mode;
  g_mpu_mode = mode;
  g_mpu_depth++;
  return previous;
}

void mpu_restore(mpu_mode_t mode) {
  g_mpu_mode = mode;
  g_mpu_depth--;
}

// ---------------------------------------------------------------------------
// Flash doubles, recording every operation
// ---------------------------------------------------------------------------

static bool g_write_unlocked = false;
static unsigned g_unlock_calls = 0;
static unsigned g_lock_calls = 0;

secbool flash_unlock_write(void) {
  g_write_unlocked = true;
  g_unlock_calls++;
  return sectrue;
}

secbool flash_lock_write(void) {
  g_write_unlocked = false;
  g_lock_calls++;
  return sectrue;
}

typedef enum { OP_READ, OP_WRITE, OP_ERASE } op_kind;

typedef struct {
  op_kind kind;
  const flash_area_t *area;
  uint32_t offset;
  uint32_t len;
  mpu_mode_t mode_at_call;
  bool unlocked_at_call;
} trace_entry;

#define TRACE_CAPACITY 8192
static trace_entry g_trace[TRACE_CAPACITY];
static unsigned g_trace_len = 0;
// Set when the trace overflows, so a silently truncated trace cannot pass.
static bool g_trace_overflow = false;

static void record(op_kind kind, const flash_area_t *area, uint32_t offset,
                   uint32_t len) {
  if (g_trace_len >= TRACE_CAPACITY) {
    g_trace_overflow = true;
    return;
  }
  g_trace[g_trace_len++] = (trace_entry){
      .kind = kind,
      .area = area,
      .offset = offset,
      .len = len,
      .mode_at_call = g_mpu_mode,
      .unlocked_at_call = g_write_unlocked,
  };
}

static void trace_reset(void) {
  g_trace_len = 0;
  g_trace_overflow = false;
  g_unlock_calls = 0;
  g_lock_calls = 0;
}

static unsigned count_kind(op_kind kind) {
  unsigned total = 0;
  for (unsigned i = 0; i < g_trace_len; i++) {
    if (g_trace[i].kind == kind) total++;
  }
  return total;
}

static uint8_t g_medium[AUTH_REPLICA_COUNT][AREA];

static int area_index(const flash_area_t *area) {
  if (area == &STORAGE_AREAS[0]) return 0;
  if (area == &STORAGE_AREAS[1]) return 1;
  if (area == &ASSETS_AREA) return 2;
  return -1;
}

uint32_t flash_area_get_size(const flash_area_t *area) {
  return area_index(area) < 0 ? 0 : AREA;
}

secbool flash_area_write_block(const flash_area_t *area, uint32_t offset,
                               const flash_block_t block) {
  record(OP_WRITE, area, offset, AUTH_REPLICA_LINE_SIZE);
  int index = area_index(area);
  if (index < 0 || offset % AUTH_REPLICA_LINE_SIZE != 0) return secfalse;
  if (offset > AREA - AUTH_REPLICA_LINE_SIZE) return secfalse;
  // Flash can only clear bits, and only a write with the flash unlocked lands.
  if (!g_write_unlocked) return secfalse;
  uint8_t bytes[AUTH_REPLICA_LINE_SIZE];
  memcpy(bytes, block, sizeof(bytes));
  for (uint32_t i = 0; i < sizeof(bytes); i++) {
    g_medium[index][offset + i] &= bytes[i];
  }
  return sectrue;
}

// When non-zero, an in-range erase reports this many bytes instead of a whole
// page, standing in for a sector map that is not what the adapter expects.
static uint32_t g_erase_short_count = 0;

secbool flash_area_erase_partial(const flash_area_t *area, uint32_t offset,
                                 uint32_t *bytes_erased) {
  record(OP_ERASE, area, offset, PAGE);
  int index = area_index(area);
  if (index < 0) {
    *bytes_erased = 0;
    return secfalse;
  }
  if (g_erase_short_count != 0 && offset < AREA) {
    memset(&g_medium[index][offset], 0xff, g_erase_short_count);
    *bytes_erased = g_erase_short_count;
    return sectrue;
  }
  if (offset >= AREA) {
    // The contract erase_areas() relies on to terminate its loop.
    *bytes_erased = 0;
    return sectrue;
  }
  if (offset % PAGE != 0) {
    *bytes_erased = 0;
    return secfalse;
  }
  memset(&g_medium[index][offset], 0xff, PAGE);
  *bytes_erased = PAGE;
  return sectrue;
}

// What the checked reader should pretend the hardware reported.
static flash_checked_result_t g_read_result = FLASH_CHECKED_OK;

flash_checked_result_t flash_area_checked_read(const flash_area_t *area,
                                               uint32_t offset, void *dst,
                                               uint32_t len) {
  record(OP_READ, area, offset, len);
  if (dst != NULL && len > 0) memset(dst, 0, len);
  int index = area_index(area);
  if (index < 0 || dst == NULL || len == 0) return FLASH_CHECKED_RANGE;
  if (offset > AREA || len > AREA - offset) return FLASH_CHECKED_RANGE;
  if (g_read_result == FLASH_CHECKED_OK ||
      g_read_result == FLASH_CHECKED_ECC_CORRECTED) {
    memcpy(dst, &g_medium[index][offset], len);
  }
  return g_read_result;
}

// The retained quarantine word. On a board this is a backup register; here it
// is a variable, so a test can put a replica into quarantine and watch the
// adapter take it out again.
static uint32_t g_quarantine = FLASH_CHECKED_QUARANTINE_MAGIC;

uint32_t flash_checked_quarantine_load(void) { return g_quarantine; }

void flash_checked_quarantine_store(uint32_t word) { g_quarantine = word; }

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static void medium_erase_all(void) { memset(g_medium, 0xff, sizeof(g_medium)); }

static bool all_zero(const uint8_t *data, size_t len) {
  for (size_t i = 0; i < len; i++) {
    if (data[i] != 0) return false;
  }
  return true;
}

// Every adapter entry point must leave the MPU exactly as it found it.
static void assert_mpu_balanced(void) {
  assert(g_mpu_depth == 0);
  assert(g_mpu_mode == MPU_MODE_DEFAULT);
}

static const auth_replica_io *io(void) { return auth_replica_io_t3t1(); }

// ---------------------------------------------------------------------------
// Index to area binding
// ---------------------------------------------------------------------------

static void each_index_binds_its_exact_sectors(void) {
  const struct {
    uint8_t replica;
    uint16_t first_sector;
    mpu_mode_t mode;
  } kExpected[AUTH_REPLICA_COUNT] = {
      {0, 0x18, MPU_MODE_STORAGE},
      {1, 0x20, MPU_MODE_STORAGE},
      {2, 0xf8, MPU_MODE_ASSETS},
  };

  for (unsigned i = 0; i < AUTH_REPLICA_COUNT; i++) {
    uint8_t out[AUTH_REPLICA_LINE_SIZE];

    // Read.
    trace_reset();
    assert(io()->read(io()->context, kExpected[i].replica, 0, out,
                      sizeof(out)) == AUTH_REPLICA_IO_OK);
    assert(g_trace_len == 1 && g_trace[0].kind == OP_READ);
    assert(g_trace[0].area->num_subareas == 1);
    assert(g_trace[0].area->subarea[0].first_sector ==
           kExpected[i].first_sector);
    assert(g_trace[0].area->subarea[0].num_sectors == PAGES);
    assert(g_trace[0].mode_at_call == kExpected[i].mode);
    assert_mpu_balanced();

    // Program.
    trace_reset();
    const uint8_t line[AUTH_REPLICA_LINE_SIZE] = {0};
    assert(io()->write_line(io()->context, kExpected[i].replica, 0, line));
    assert(g_trace_len == 1 && g_trace[0].kind == OP_WRITE);
    assert(g_trace[0].area->subarea[0].first_sector ==
           kExpected[i].first_sector);
    assert(g_trace[0].mode_at_call == kExpected[i].mode);
    // A program only lands with the flash unlocked, and the unlock must be
    // dropped again afterwards.
    assert(g_trace[0].unlocked_at_call);
    assert(g_unlock_calls == 1 && g_lock_calls == 1);
    assert(!g_write_unlocked);
    assert_mpu_balanced();

    // Erase.
    trace_reset();
    assert(io()->erase_page(io()->context, kExpected[i].replica, 0));
    assert(g_trace_len == 1 && g_trace[0].kind == OP_ERASE);
    assert(g_trace[0].area->subarea[0].first_sector ==
           kExpected[i].first_sector);
    assert(g_trace[0].mode_at_call == kExpected[i].mode);
    assert_mpu_balanced();
  }

  // The three bindings are distinct areas, not the same one three times.
  assert(area_index(&STORAGE_AREAS[0]) == 0);
  assert(area_index(&STORAGE_AREAS[1]) == 1);
  assert(area_index(&ASSETS_AREA) == 2);
  // And the adapter has no route to firmware.
  assert(area_index(&kFirmwareArea) < 0);
}

static void unknown_index_is_refused_before_touching_flash(void) {
  const uint8_t kBad[] = {AUTH_REPLICA_COUNT,
                          AUTH_REPLICA_COUNT + 1,
                          10,
                          0x7f,
                          AUTH_REPLICA_NONE,
                          0xfe};
  for (unsigned i = 0; i < sizeof(kBad) / sizeof(kBad[0]); i++) {
    uint8_t out[AUTH_REPLICA_LINE_SIZE];
    memset(out, 0xaa, sizeof(out));
    const uint8_t line[AUTH_REPLICA_LINE_SIZE] = {0};

    trace_reset();
    assert(io()->read(io()->context, kBad[i], 0, out, sizeof(out)) ==
           AUTH_REPLICA_IO_RANGE);
    // No flash call, and the caller's buffer is cleared rather than left with
    // whatever it happened to contain.
    assert(g_trace_len == 0);
    assert(all_zero(out, sizeof(out)));
    assert_mpu_balanced();

    trace_reset();
    assert(!io()->write_line(io()->context, kBad[i], 0, line));
    assert(g_trace_len == 0);
    assert(g_unlock_calls == 0);
    assert_mpu_balanced();

    trace_reset();
    assert(!io()->erase_page(io()->context, kBad[i], 0));
    assert(g_trace_len == 0);
    assert_mpu_balanced();
  }
}

// ---------------------------------------------------------------------------
// Alignment and range
// ---------------------------------------------------------------------------

static void line_writes_must_be_line_aligned_and_in_range(void) {
  const uint8_t line[AUTH_REPLICA_LINE_SIZE] = {0};

  const uint32_t kRejected[] = {
      1,
      8,
      15,
      17,
      AUTH_REPLICA_LINE_SIZE - 1,
      AUTH_REPLICA_LINE_SIZE + 1,
      // The last line starts at AREA - 16; anything past that overruns.
      AREA - AUTH_REPLICA_LINE_SIZE + 1,
      AREA,
      AREA + AUTH_REPLICA_LINE_SIZE,
      0xffffffffu,
  };
  for (unsigned i = 0; i < sizeof(kRejected) / sizeof(kRejected[0]); i++) {
    trace_reset();
    assert(!io()->write_line(io()->context, 0, kRejected[i], line));
    assert(g_trace_len == 0);
    assert(g_unlock_calls == 0);
    assert_mpu_balanced();
  }

  const uint32_t kAccepted[] = {0, AUTH_REPLICA_LINE_SIZE, PAGE,
                                AREA - AUTH_REPLICA_LINE_SIZE};
  for (unsigned i = 0; i < sizeof(kAccepted) / sizeof(kAccepted[0]); i++) {
    trace_reset();
    assert(io()->write_line(io()->context, 0, kAccepted[i], line));
    assert(g_trace_len == 1 && g_trace[0].offset == kAccepted[i]);
    assert_mpu_balanced();
  }

  // A null line is refused rather than dereferenced.
  trace_reset();
  assert(!io()->write_line(io()->context, 0, 0, NULL));
  assert(g_trace_len == 0);
  assert_mpu_balanced();
}

static void page_erases_must_be_page_aligned_and_in_range(void) {
  const uint32_t kRejected[] = {
      1,    16,          PAGE - 1,    PAGE + 1, AREA - PAGE + 1,
      AREA, AREA + PAGE, 0xffffffffu,
  };
  for (unsigned i = 0; i < sizeof(kRejected) / sizeof(kRejected[0]); i++) {
    trace_reset();
    assert(!io()->erase_page(io()->context, 0, kRejected[i]));
    assert(g_trace_len == 0);
    assert_mpu_balanced();
  }

  for (unsigned page = 0; page < PAGES; page++) {
    trace_reset();
    assert(io()->erase_page(io()->context, 0, page * PAGE));
    assert(g_trace_len == 1 && g_trace[0].offset == page * PAGE);
    assert_mpu_balanced();
  }

  // The manager counts pages, so an erase that clears something other than one
  // whole page means the sector geometry is not the one this adapter was built
  // against. It must be reported as a failure rather than accepted.
  const uint32_t kShortCounts[] = {AUTH_REPLICA_LINE_SIZE, PAGE / 2, PAGE * 2};
  for (unsigned i = 0; i < sizeof(kShortCounts) / sizeof(kShortCounts[0]);
       i++) {
    g_erase_short_count = kShortCounts[i];
    trace_reset();
    assert(!io()->erase_page(io()->context, 0, 0));
    assert_mpu_balanced();
  }
  g_erase_short_count = 0;
}

static void reads_must_stay_inside_the_area(void) {
  // The IO contract is that `out` really has `len` writable bytes, and the
  // adapter clears the whole of it. So every `len` below is one this buffer can
  // actually absorb; claiming a length the caller does not own is a caller
  // defect the adapter cannot defend against, not a case worth asserting.
  // A length-side 32-bit wrap is unreachable for the same reason the offset
  // check comes first: any offset large enough to wrap is already past the
  // area, and `len > AREA - offset` is written as a subtraction.
  static uint8_t out[AREA + 256];

  const struct {
    uint32_t offset;
    uint32_t len;
  } kRejected[] = {
      {AREA, 1}, {AREA + 1, 1},   {AREA - 1, 2},    {0, AREA + 1},
      {1, AREA}, {AREA - 16, 17}, {0xffffffffu, 1}, {0x80000000u, 16},
  };
  for (unsigned i = 0; i < sizeof(kRejected) / sizeof(kRejected[0]); i++) {
    memset(out, 0xaa, sizeof(out));
    trace_reset();
    assert(io()->read(io()->context, 0, kRejected[i].offset, out,
                      kRejected[i].len) == AUTH_REPLICA_IO_RANGE);
    assert(all_zero(out, kRejected[i].len));
    assert_mpu_balanced();
  }

  // Zero length and a null destination are refused without a flash call.
  trace_reset();
  assert(io()->read(io()->context, 0, 0, out, 0) == AUTH_REPLICA_IO_RANGE);
  assert(g_trace_len == 0);
  assert(io()->read(io()->context, 0, 0, NULL, 16) == AUTH_REPLICA_IO_RANGE);
  assert(g_trace_len == 0);
  assert_mpu_balanced();

  // The exact endpoints are legal.
  trace_reset();
  assert(io()->read(io()->context, 0, AREA - 1, out, 1) == AUTH_REPLICA_IO_OK);
  assert(io()->read(io()->context, 0, AREA - 16, out, 16) ==
         AUTH_REPLICA_IO_OK);
  assert(io()->read(io()->context, 0, 0, out, AREA) == AUTH_REPLICA_IO_OK);
  assert_mpu_balanced();
}

// ---------------------------------------------------------------------------
// Checked-read result mapping
// ---------------------------------------------------------------------------

static void checked_read_results_map_without_inventing_data(void) {
  const struct {
    flash_checked_result_t from;
    auth_replica_io_result to;
    bool carries_data;
  } kMapping[] = {
      {FLASH_CHECKED_OK, AUTH_REPLICA_IO_OK, true},
      {FLASH_CHECKED_ECC_CORRECTED, AUTH_REPLICA_IO_ECC_CORRECTED, true},
      {FLASH_CHECKED_ECC_UNCORRECTABLE, AUTH_REPLICA_IO_ECC_UNCORRECTABLE,
       false},
      {FLASH_CHECKED_RANGE, AUTH_REPLICA_IO_RANGE, false},
      {FLASH_CHECKED_BUSY, AUTH_REPLICA_IO_FAILED, false},
      // The ordinary hardware image returns this for every read while ECCD
      // containment is unvalidated. It must never look like success.
      {FLASH_CHECKED_UNSUPPORTED, AUTH_REPLICA_IO_FAILED, false},
  };

  // Put something recognisable in the medium so "data" is distinguishable from
  // a zeroized buffer.
  memset(g_medium[0], 0x5a, AREA);

  for (unsigned i = 0; i < sizeof(kMapping) / sizeof(kMapping[0]); i++) {
    uint8_t out[64];
    memset(out, 0xaa, sizeof(out));
    g_read_result = kMapping[i].from;
    trace_reset();
    assert(io()->read(io()->context, 0, 0, out, sizeof(out)) == kMapping[i].to);
    if (kMapping[i].carries_data) {
      for (unsigned b = 0; b < sizeof(out); b++) assert(out[b] == 0x5a);
    } else {
      assert(all_zero(out, sizeof(out)));
    }
    assert_mpu_balanced();
  }
  g_read_result = FLASH_CHECKED_OK;
  medium_erase_all();
}

// ---------------------------------------------------------------------------
// Fail-closed behaviour of the whole stack
// ---------------------------------------------------------------------------

// An ordinary hardware image cannot contain an ECC double error yet, so its
// checked reader refuses every load. Wire that through the real manager and
// require it to fail closed: it must not decide the device is blank (which
// would permit provisioning) and it must not erase or program anything.
static void unsupported_reads_fail_closed_with_no_writes(void) {
  medium_erase_all();
  g_read_result = FLASH_CHECKED_UNSUPPORTED;
  trace_reset();

  auth_replica_store store;
  memset(&store, 0, sizeof(store));
  auth_replica_store_result result = auth_replica_probe(&store, io());

  assert(result != AUTH_REPLICA_STORE_OK);
  // BLANK is the dangerous answer: it is the one that authorises provisioning
  // over what may be a perfectly good vault we simply cannot read.
  assert(result != AUTH_REPLICA_STORE_BLANK);
  for (unsigned i = 0; i < AUTH_REPLICA_COUNT; i++) {
    assert(store.state[i] == AUTH_REPLICA_STATE_UNREADABLE);
    assert(!store.authenticated[i]);
  }
  assert(store.selected == AUTH_REPLICA_NONE);
  assert(count_kind(OP_WRITE) == 0);
  assert(count_kind(OP_ERASE) == 0);
  assert(!g_trace_overflow);
  assert(g_unlock_calls == 0);
  assert_mpu_balanced();

  g_read_result = FLASH_CHECKED_OK;
}

// ---------------------------------------------------------------------------
// Wipe coverage
// ---------------------------------------------------------------------------

static void authenticator_wipe_touches_exactly_its_three_areas(void) {
  medium_erase_all();
  // Make every area non-erased so the wipe has real work to do.
  for (unsigned i = 0; i < AUTH_REPLICA_COUNT; i++) {
    memset(g_medium[i], 0x37, AREA);
  }

  auth_replica_store store;
  memset(&store, 0, sizeof(store));
  (void)auth_replica_probe(&store, io());

  trace_reset();
  assert(auth_replica_wipe(&store) == AUTH_REPLICA_STORE_OK);
  assert(!g_trace_overflow);

  bool erased_page[AUTH_REPLICA_COUNT][PAGES];
  memset(erased_page, 0, sizeof(erased_page));
  for (unsigned i = 0; i < g_trace_len; i++) {
    if (g_trace[i].kind != OP_ERASE) continue;
    int index = area_index(g_trace[i].area);
    // Every erase the wipe issues lands in one of the three replica areas.
    assert(index >= 0);
    assert(g_trace[i].offset % PAGE == 0);
    assert(g_trace[i].offset < AREA);
    // And under the MPU mode that area requires.
    assert(g_trace[i].mode_at_call ==
           (index == 2 ? MPU_MODE_ASSETS : MPU_MODE_STORAGE));
    erased_page[index][g_trace[i].offset / PAGE] = true;
  }
  for (unsigned i = 0; i < AUTH_REPLICA_COUNT; i++) {
    for (unsigned p = 0; p < PAGES; p++) {
      assert(erased_page[i][p]);
    }
    // Nothing of the old contents is left behind.
    for (uint32_t b = 0; b < AREA; b++) {
      assert(g_medium[i][b] == 0xff || b >= AUTH_REPLICA_CLAIM_OFFSET);
    }
  }
  assert_mpu_balanced();
}

// A full device wipe must still cover assets, otherwise replica 2 would quietly
// survive an operation the user was told erases everything.
static void device_wipe_covers_all_three_replica_areas(void) {
  medium_erase_all();
  trace_reset();
  assert(erase_device(NULL) == sectrue);

  bool touched[AUTH_REPLICA_COUNT] = {false, false, false};
  for (unsigned i = 0; i < g_trace_len; i++) {
    if (g_trace[i].kind != OP_ERASE) continue;
    int index = area_index(g_trace[i].area);
    assert(index >= 0);
    if (g_trace[i].offset < AREA) touched[index] = true;
  }
  assert(touched[0] && touched[1] && touched[2]);

  // Storage-only erase is a different, narrower operation. It is what a
  // non-upgrade firmware install runs, and it deliberately leaves assets
  // alone -- on a stock image assets holds translations, not vault data. The
  // consequence for this project is recorded here on purpose: after such an
  // install replicas 0 and 1 are gone and replica 2 survives, which the
  // manager repairs from. Security therefore cannot rest on erase_storage().
  trace_reset();
  assert(erase_storage(NULL) == sectrue);
  bool storage_touched[AUTH_REPLICA_COUNT] = {false, false, false};
  for (unsigned i = 0; i < g_trace_len; i++) {
    if (g_trace[i].kind != OP_ERASE) continue;
    int index = area_index(g_trace[i].area);
    assert(index >= 0);
    if (g_trace[i].offset < AREA) storage_touched[index] = true;
  }
  assert(storage_touched[0] && storage_touched[1]);
  assert(!storage_touched[2]);
}

// ---------------------------------------------------------------------------
// Quarantine
// ---------------------------------------------------------------------------

// A replica the last boot died reading is refused by the checked reader until
// something erases it. The adapter is where that release happens, and it is the
// only release there is: get it wrong and a replica damaged once is excluded
// for the life of the device, which turns a survivable fault into a permanent
// loss of redundancy.
static void erasing_a_page_lifts_that_replicas_quarantine(void) {
  // The wipe tests above reach flash_utils.c, which switches MPU mode once per
  // area and restores once at the end -- correct, but not the one-for-one
  // pairing this counter measures, so it arrives here non-zero. Only the mode
  // matters across that boundary, and it is what the wipe path does restore.
  assert(g_mpu_mode == MPU_MODE_DEFAULT);
  g_mpu_depth = 0;
  medium_erase_all();

  // All three quarantined, so the test can see exactly one released.
  g_quarantine = FLASH_CHECKED_QUARANTINE_MAGIC;
  for (uint8_t replica = 0; replica < AUTH_REPLICA_COUNT; replica++) {
    g_quarantine = flash_checked_quarantine_add(g_quarantine, replica);
  }

  trace_reset();
  assert(io()->erase_page(io()->context, 1, 0));
  assert(!flash_checked_quarantine_holds(g_quarantine, 1));
  // The other two are untouched: one erase must not absolve replicas it never
  // wrote to.
  assert(flash_checked_quarantine_holds(g_quarantine, 0));
  assert(flash_checked_quarantine_holds(g_quarantine, 2));
  assert_mpu_balanced();

  // Any page of the replica releases it, not only page zero.
  assert(io()->erase_page(io()->context, 2, PAGE));
  assert(!flash_checked_quarantine_holds(g_quarantine, 2));
  assert(flash_checked_quarantine_holds(g_quarantine, 0));

  // A refused erase releases nothing. The replica is still as unreadable as it
  // was, and saying otherwise would send the manager back to a line that
  // faults.
  trace_reset();
  assert(!io()->erase_page(io()->context, 0, PAGE + 1));
  assert(flash_checked_quarantine_holds(g_quarantine, 0));
  assert(!io()->erase_page(io()->context, AUTH_REPLICA_COUNT, 0));
  assert(flash_checked_quarantine_holds(g_quarantine, 0));
  assert_mpu_balanced();

  // An erase the hardware performed but with the wrong geometry is refused by
  // the adapter, and must not release either.
  g_erase_short_count = AUTH_REPLICA_LINE_SIZE;
  assert(!io()->erase_page(io()->context, 0, 0));
  assert(flash_checked_quarantine_holds(g_quarantine, 0));
  g_erase_short_count = 0;

  // Back to a clean slate for whatever runs next.
  g_quarantine = FLASH_CHECKED_QUARANTINE_MAGIC;
  medium_erase_all();
}

int main(void) {
  medium_erase_all();
  assert_mpu_balanced();

  each_index_binds_its_exact_sectors();
  unknown_index_is_refused_before_touching_flash();
  line_writes_must_be_line_aligned_and_in_range();
  page_erases_must_be_page_aligned_and_in_range();
  reads_must_stay_inside_the_area();
  checked_read_results_map_without_inventing_data();
  unsupported_reads_fail_closed_with_no_writes();
  authenticator_wipe_touches_exactly_its_three_areas();
  device_wipe_covers_all_three_replica_areas();

  erasing_a_page_lifts_that_replicas_quarantine();

  printf("replica io binding and wipe policy: PASS\n");
  return 0;
}
