#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../replica_store.h"

// ---------------------------------------------------------------------------
// Simulated NOR flash with real STM32U5-shaped constraints:
//   * a line can only be programmed while it reads as erased (bits clear
//     only, never set), so an accidental double write is detected;
//   * erase works a whole 8 KiB page at a time;
//   * every read/write/erase is logged so ordering invariants and
//     "the source received zero writes" can be asserted directly.
// ---------------------------------------------------------------------------

#define AREA AUTH_REPLICA_AREA_SIZE
// Mirror of the region offsets that replica_store.c keeps private, so the
// test can poison a specific body region directly.
#define TEST_ROOT_REGION_OFFSET AUTH_REPLICA_HEADER_SIZE
#define TEST_SLOT_REGION_OFFSET \
  (TEST_ROOT_REGION_OFFSET + AUTH_REPLICA_ROOT_REGION_SIZE)

static uint8_t flash[AUTH_REPLICA_COUNT][AREA];

typedef struct {
  uint8_t replica;
  uint32_t offset;
} op;

// One commit programs 3614 lines, so the log is intentionally bounded: it
// records the first MAX_OPS operations for ordering assertions while the
// total_* counters always reflect reality. Tests that inspect ordering reset
// the log immediately before the single transaction they examine.
#define MAX_OPS 8192
static op write_log[MAX_OPS];
static unsigned write_ops;
static unsigned total_writes;
static op erase_log[MAX_OPS];
static unsigned erase_ops;
static unsigned total_erases;
// Reads are counted, not logged: what matters about them is how many a single
// operation needs, which is the whole difference between authenticating a
// snapshot once per pass and once per slot.
static unsigned total_reads;

// Fault/ECC injection.
static unsigned fail_write_after;  // 0 = never
static unsigned fail_erase_after;  // 0 = never
static uint8_t ecc_replica = AUTH_REPLICA_NONE;
static uint32_t ecc_from, ecc_to;
static bool ecc_uncorrectable;

static void reset_flash(void) {
  memset(flash, 0xff, sizeof(flash));
  write_ops = erase_ops = 0;
  total_writes = total_erases = 0;
  total_reads = 0;
  fail_write_after = fail_erase_after = 0;
  ecc_replica = AUTH_REPLICA_NONE;
  ecc_from = ecc_to = 0;
  ecc_uncorrectable = false;
}

static auth_replica_io_result sim_read(void *context, uint8_t replica,
                                       uint32_t offset, uint8_t *out,
                                       uint32_t len) {
  (void)context;
  total_reads++;
  if (replica >= AUTH_REPLICA_COUNT || (uint64_t)offset + len > AREA) {
    memset(out, 0, len);
    return AUTH_REPLICA_IO_RANGE;
  }
  bool hit =
      replica == ecc_replica && offset < ecc_to && offset + len > ecc_from;
  if (hit && ecc_uncorrectable) {
    memset(out, 0, len);
    return AUTH_REPLICA_IO_ECC_UNCORRECTABLE;
  }
  memcpy(out, flash[replica] + offset, len);
  return hit ? AUTH_REPLICA_IO_ECC_CORRECTED : AUTH_REPLICA_IO_OK;
}

static bool sim_write(void *context, uint8_t replica, uint32_t offset,
                      const uint8_t line[AUTH_REPLICA_LINE_SIZE]) {
  (void)context;
  assert(offset % AUTH_REPLICA_LINE_SIZE == 0);
  if (replica >= AUTH_REPLICA_COUNT ||
      (uint64_t)offset + AUTH_REPLICA_LINE_SIZE > AREA)
    return false;
  if (fail_write_after && total_writes >= fail_write_after) return false;
  // NOR: the target must currently be erased.
  for (unsigned i = 0; i < AUTH_REPLICA_LINE_SIZE; i++)
    assert(flash[replica][offset + i] == 0xff);
  memcpy(flash[replica] + offset, line, AUTH_REPLICA_LINE_SIZE);
  total_writes++;
  if (write_ops < MAX_OPS) write_log[write_ops++] = (op){replica, offset};
  return true;
}

static bool sim_erase(void *context, uint8_t replica, uint32_t offset) {
  (void)context;
  assert(offset % AUTH_REPLICA_PAGE_SIZE == 0);
  if (replica >= AUTH_REPLICA_COUNT ||
      (uint64_t)offset + AUTH_REPLICA_PAGE_SIZE > AREA)
    return false;
  if (fail_erase_after && total_erases >= fail_erase_after) return false;
  memset(flash[replica] + offset, 0xff, AUTH_REPLICA_PAGE_SIZE);
  total_erases++;
  if (erase_ops < MAX_OPS) erase_log[erase_ops++] = (op){replica, offset};
  return true;
}

static const auth_replica_io io = {.read = sim_read,
                                   .write_line = sim_write,
                                   .erase_page = sim_erase,
                                   .context = NULL};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

static const uint8_t root_a[32] = {0xa0, 1, 2, 3};
static const uint8_t root_b[32] = {0xb0, 9, 8, 7};
static uint8_t envelope[AUTH_REPLICA_ROOT_LENGTH];
static uint8_t nonce1[16], nonce2[16];

static void init_fixtures(void) {
  for (unsigned i = 0; i < sizeof(envelope); i++)
    envelope[i] = (uint8_t)(i + 1);
  memset(nonce1, 0x11, sizeof(nonce1));
  memset(nonce2, 0x22, sizeof(nonce2));
}

static unsigned writes_to(uint8_t replica) {
  unsigned count = 0;
  for (unsigned i = 0; i < write_ops; i++)
    if (write_log[i].replica == replica) count++;
  return count;
}

static unsigned erases_of(uint8_t replica) {
  unsigned count = 0;
  for (unsigned i = 0; i < erase_ops; i++)
    if (erase_log[i].replica == replica) count++;
  return count;
}

// Provisions generation 1 and leaves the store authenticated.
static void provision(auth_replica_store *store) {
  reset_flash();
  assert(auth_replica_probe(store, &io) == AUTH_REPLICA_STORE_BLANK);
  assert(auth_replica_provision(store, root_a, envelope, nonce1) ==
         AUTH_REPLICA_STORE_OK);
  assert(store->generation == 1);
}

// ---------------------------------------------------------------------------
// Selector tests
// ---------------------------------------------------------------------------

static void test_blank_media_is_blank_not_migration(void) {
  reset_flash();
  auth_replica_store store;
  assert(auth_replica_probe(&store, &io) == AUTH_REPLICA_STORE_BLANK);
  for (uint8_t r = 0; r < AUTH_REPLICA_COUNT; r++)
    assert(store.state[r] == AUTH_REPLICA_STATE_BLANK);
  assert(store.selected == AUTH_REPLICA_NONE);
  // Probing must never write.
  assert(total_writes == 0 && total_erases == 0);
}

static void test_foreign_bytes_require_migration_and_never_erase(void) {
  reset_flash();
  // One stray non-erased byte in the middle of an otherwise blank area, with
  // no replica magic: this models legacy NORCOW/foreign data.
  flash[1][40000] = 0x5a;
  auth_replica_store store;
  assert(auth_replica_probe(&store, &io) == AUTH_REPLICA_STORE_MIGRATION);
  assert(store.state[1] == AUTH_REPLICA_STATE_FOREIGN);
  assert(total_writes == 0 && total_erases == 0);
  // Provisioning on top of foreign data must refuse, still without writing.
  assert(auth_replica_provision(&store, root_a, envelope, nonce1) ==
         AUTH_REPLICA_STORE_MIGRATION);
  assert(total_writes == 0 && total_erases == 0);
  assert(flash[1][40000] == 0x5a);
}

static void test_provisioning_then_authentication_selects_generation_one(void) {
  auth_replica_store store;
  provision(&store);
  // Re-probe from cold and authenticate with the correct root.
  assert(auth_replica_probe(&store, &io) == AUTH_REPLICA_STORE_OK);
  assert(auth_replica_authenticate(&store, root_a) == AUTH_REPLICA_STORE_OK);
  assert(store.generation == 1);
  assert(store.selected != AUTH_REPLICA_NONE);
  // The wrong root authenticates nothing.
  assert(auth_replica_probe(&store, &io) == AUTH_REPLICA_STORE_OK);
  assert(auth_replica_authenticate(&store, root_b) ==
         AUTH_REPLICA_STORE_NO_SOURCE);
  assert(store.selected == AUTH_REPLICA_NONE);
}

static void test_highest_authenticated_generation_wins(void) {
  auth_replica_store store;
  provision(&store);
  uint8_t first = store.selected;
  assert(auth_replica_commit_slot(&store, root_a, 3, envelope, 40, nonce2) ==
         AUTH_REPLICA_STORE_OK);
  assert(store.generation == 2);
  assert(store.selected != first);
  // Cold probe must pick generation 2, not whichever replica comes first.
  assert(auth_replica_probe(&store, &io) == AUTH_REPLICA_STORE_OK);
  assert(auth_replica_authenticate(&store, root_a) == AUTH_REPLICA_STORE_OK);
  assert(store.generation == 2);
  auth_replica_slot_t slot;
  assert(auth_replica_read_slot(&store, root_a, 3, &slot) ==
         AUTH_REPLICA_STORE_OK);
  assert(slot.present && slot.record_len == 40);
  assert(memcmp(slot.record, envelope, 40) == 0);
}

static void test_forged_high_generation_is_never_selected(void) {
  auth_replica_store store;
  provision(&store);
  uint8_t valid = store.selected;
  uint8_t other = valid == 0 ? 1 : 0;
  // Copy the valid snapshot into another area, then forge a huge generation.
  memcpy(flash[other], flash[valid], AREA);
  flash[other][16] = 0xff;
  flash[other][17] = 0xff;
  flash[other][18] = 0xff;
  assert(auth_replica_probe(&store, &io) == AUTH_REPLICA_STORE_OK);
  assert(store.claimed_generation[other] > store.claimed_generation[valid]);
  // Structural claim is high, but the MAC no longer covers it.
  assert(auth_replica_authenticate(&store, root_a) == AUTH_REPLICA_STORE_OK);
  assert(store.selected == valid);
  assert(store.generation == 1);
  assert(!store.authenticated[other]);
}

static void test_identical_same_generation_tie_is_accepted(void) {
  auth_replica_store store;
  provision(&store);
  uint8_t valid = store.selected;
  uint8_t other = valid == 0 ? 1 : 0;
  memcpy(flash[other], flash[valid], AREA);  // byte-identical duplicate
  assert(auth_replica_probe(&store, &io) == AUTH_REPLICA_STORE_OK);
  assert(auth_replica_authenticate(&store, root_a) == AUTH_REPLICA_STORE_OK);
  assert(store.authenticated[valid] && store.authenticated[other]);
  assert(store.generation == 1);
  assert(!store.integrity_failed);
}

static void test_divergent_same_generation_tie_latches_integrity(void) {
  auth_replica_store store;
  provision(&store);
  // Build a second, genuinely authenticated generation-1 snapshot with
  // different contents by provisioning from scratch on a copy of the media.
  uint8_t snapshot_one[AREA];
  uint8_t first = store.selected;
  memcpy(snapshot_one, flash[first], AREA);

  reset_flash();
  auth_replica_store other_store;
  assert(auth_replica_probe(&other_store, &io) == AUTH_REPLICA_STORE_BLANK);
  uint8_t different_envelope[AUTH_REPLICA_ROOT_LENGTH];
  memset(different_envelope, 0x77, sizeof(different_envelope));
  assert(auth_replica_provision(&other_store, root_a, different_envelope,
                                nonce2) == AUTH_REPLICA_STORE_OK);
  uint8_t second = other_store.selected;
  uint8_t snapshot_two[AREA];
  memcpy(snapshot_two, flash[second], AREA);

  // Place both authenticated generation-1 snapshots side by side.
  reset_flash();
  memcpy(flash[0], snapshot_one, AREA);
  memcpy(flash[1], snapshot_two, AREA);
  assert(auth_replica_probe(&store, &io) == AUTH_REPLICA_STORE_OK);
  assert(auth_replica_authenticate(&store, root_a) ==
         AUTH_REPLICA_STORE_INTEGRITY);
  assert(store.integrity_failed);
  assert(store.selected == AUTH_REPLICA_NONE);
  // The latch must survive and block mutations without writing.
  unsigned before = total_writes;
  assert(auth_replica_commit_slot(&store, root_a, 0, envelope, 40, nonce1) ==
         AUTH_REPLICA_STORE_INTEGRITY);
  assert(total_writes == before);
}

static void test_corrected_ecc_still_authenticates_and_is_marked_degraded(
    void) {
  auth_replica_store store;
  provision(&store);
  uint8_t valid = store.selected;
  ecc_replica = valid;
  ecc_from = 0;
  ecc_to = AREA;
  ecc_uncorrectable = false;
  assert(auth_replica_probe(&store, &io) == AUTH_REPLICA_STORE_OK);
  assert(auth_replica_authenticate(&store, root_a) == AUTH_REPLICA_STORE_OK);
  assert(store.selected == valid);
  assert(store.state[valid] == AUTH_REPLICA_STATE_DEGRADED);
}

static void test_uncorrectable_ecc_excludes_only_that_replica(void) {
  auth_replica_store store;
  provision(&store);
  uint8_t valid = store.selected;
  uint8_t other = valid == 0 ? 1 : 0;
  memcpy(flash[other], flash[valid], AREA);
  // Make the originally selected replica unreadable.
  ecc_replica = valid;
  ecc_from = 0;
  ecc_to = AREA;
  ecc_uncorrectable = true;
  assert(auth_replica_probe(&store, &io) == AUTH_REPLICA_STORE_OK);
  assert(store.state[valid] == AUTH_REPLICA_STATE_UNREADABLE);
  assert(auth_replica_authenticate(&store, root_a) == AUTH_REPLICA_STORE_OK);
  assert(store.selected == other);
  assert(store.generation == 1);
}

static void test_no_authenticated_candidate_reports_no_source(void) {
  auth_replica_store store;
  provision(&store);
  // Corrupt every replica body so nothing authenticates.
  for (uint8_t r = 0; r < AUTH_REPLICA_COUNT; r++) {
    if (flash[r][0] != 0xff) flash[r][TEST_SLOT_REGION_OFFSET] ^= 0xff;
  }
  assert(auth_replica_probe(&store, &io) == AUTH_REPLICA_STORE_OK);
  assert(auth_replica_authenticate(&store, root_a) ==
         AUTH_REPLICA_STORE_NO_SOURCE);
  assert(store.selected == AUTH_REPLICA_NONE);
}

// ---------------------------------------------------------------------------
// Transaction tests
// ---------------------------------------------------------------------------

static void test_commit_never_writes_the_source(void) {
  auth_replica_store store;
  provision(&store);
  uint8_t source = store.selected;
  uint8_t before[AREA];
  memcpy(before, flash[source], AREA);
  write_ops = erase_ops = 0;
  total_writes = total_erases = 0;
  assert(auth_replica_commit_slot(&store, root_a, 7, envelope, 62, nonce2) ==
         AUTH_REPLICA_STORE_OK);
  assert(writes_to(source) == 0);
  assert(erases_of(source) == 0);
  assert(memcmp(before, flash[source], AREA) == 0);
  assert(store.selected != source);
}

static void test_destination_erases_all_pages_in_increasing_order(void) {
  auth_replica_store store;
  provision(&store);
  write_ops = erase_ops = 0;
  total_writes = total_erases = 0;
  assert(auth_replica_commit_slot(&store, root_a, 1, envelope, 40, nonce2) ==
         AUTH_REPLICA_STORE_OK);
  uint8_t destination = store.selected;
  assert(erases_of(destination) == AUTH_REPLICA_PAGES_PER_AREA);

  // The claim page is erased first so the ownership claim can be written
  // before the bulk erase begins; without that ordering a power cut during the
  // sweep would leave an unclaimed, garbage-filled area that the conservative
  // migration rule would mistake for foreign data. The remaining pages then
  // follow in increasing offset order, and every page is erased exactly once.
  const uint32_t claim_page =
      (AUTH_REPLICA_CLAIM_OFFSET / AUTH_REPLICA_PAGE_SIZE) *
      AUTH_REPLICA_PAGE_SIZE;
  bool seen[AUTH_REPLICA_PAGES_PER_AREA] = {false};
  unsigned position = 0;
  uint32_t previous = 0;
  for (unsigned i = 0; i < erase_ops; i++) {
    if (erase_log[i].replica != destination) continue;
    uint32_t offset = erase_log[i].offset;
    assert(offset % AUTH_REPLICA_PAGE_SIZE == 0);
    unsigned page = offset / AUTH_REPLICA_PAGE_SIZE;
    assert(page < AUTH_REPLICA_PAGES_PER_AREA);
    assert(!seen[page]);  // exactly once
    seen[page] = true;
    if (position == 0) {
      assert(offset == claim_page);
    } else {
      assert(offset != claim_page);
      if (position > 1) assert(offset > previous);
      previous = offset;
    }
    position++;
  }
  assert(position == AUTH_REPLICA_PAGES_PER_AREA);
  for (unsigned page = 0; page < AUTH_REPLICA_PAGES_PER_AREA; page++)
    assert(seen[page]);

  // The claim must be present in the finished destination.
  uint8_t claim[AUTH_REPLICA_LINE_SIZE];
  assert(sim_read(NULL, destination, AUTH_REPLICA_CLAIM_OFFSET, claim,
                  sizeof(claim)) == AUTH_REPLICA_IO_OK);
  assert(memcmp(claim, AUTH_REPLICA_CLAIM_MAGIC,
                sizeof(AUTH_REPLICA_CLAIM_MAGIC) - 1) == 0);
}

static void test_body_lines_precede_header_lines(void) {
  auth_replica_store store;
  provision(&store);
  write_ops = erase_ops = 0;
  total_writes = total_erases = 0;
  assert(auth_replica_commit_slot(&store, root_a, 2, envelope, 40, nonce2) ==
         AUTH_REPLICA_STORE_OK);
  uint8_t destination = store.selected;
  unsigned last_body = 0, first_header = (unsigned)-1;
  for (unsigned i = 0; i < write_ops; i++) {
    if (write_log[i].replica != destination) continue;
    if (write_log[i].offset >= AUTH_REPLICA_HEADER_SIZE) {
      if (i > last_body) last_body = i;
    } else if (i < first_header) {
      first_header = i;
    }
  }
  assert(first_header != (unsigned)-1);
  assert(last_body < first_header);
  // Header is exactly 10 program lines, written in increasing order.
  uint32_t expected = 0;
  unsigned header_lines = 0;
  for (unsigned i = 0; i < write_ops; i++) {
    if (write_log[i].replica != destination) continue;
    if (write_log[i].offset >= AUTH_REPLICA_HEADER_SIZE) continue;
    assert(write_log[i].offset == expected);
    expected += AUTH_REPLICA_LINE_SIZE;
    header_lines++;
  }
  assert(header_lines == AUTH_REPLICA_HEADER_SIZE / AUTH_REPLICA_LINE_SIZE);
}

static void test_destination_rotates_across_all_three_replicas(void) {
  auth_replica_store store;
  provision(&store);
  uint8_t seen[AUTH_REPLICA_COUNT] = {0};
  seen[store.selected] = 1;
  for (unsigned i = 0; i < 6; i++) {
    assert(auth_replica_commit_slot(&store, root_a, (uint8_t)i, envelope, 40,
                                    nonce2) == AUTH_REPLICA_STORE_OK);
    seen[store.selected] = 1;
  }
  for (uint8_t r = 0; r < AUTH_REPLICA_COUNT; r++) assert(seen[r]);
}

static void test_slot_round_trip_replace_and_delete(void) {
  auth_replica_store store;
  provision(&store);
  uint8_t big[AUTH_REPLICA_SLOT_RECORD_MAX];
  for (unsigned i = 0; i < sizeof(big); i++) big[i] = (uint8_t)(i * 7 + 1);

  assert(auth_replica_commit_slot(&store, root_a, 42, big, sizeof(big),
                                  nonce2) == AUTH_REPLICA_STORE_OK);
  auth_replica_slot_t slot;
  assert(auth_replica_read_slot(&store, root_a, 42, &slot) ==
         AUTH_REPLICA_STORE_OK);
  assert(slot.present && slot.record_len == sizeof(big));
  assert(memcmp(slot.record, big, sizeof(big)) == 0);

  // A different, shorter record replaces it cleanly.
  assert(auth_replica_commit_slot(&store, root_a, 42, envelope, 30, nonce1) ==
         AUTH_REPLICA_STORE_OK);
  assert(auth_replica_read_slot(&store, root_a, 42, &slot) ==
         AUTH_REPLICA_STORE_OK);
  assert(slot.record_len == 30);
  assert(memcmp(slot.record, envelope, 30) == 0);

  // Unrelated slots stay absent.
  assert(auth_replica_read_slot(&store, root_a, 41, &slot) ==
         AUTH_REPLICA_STORE_ABSENT);

  assert(auth_replica_delete_slot(&store, root_a, 42, nonce2) ==
         AUTH_REPLICA_STORE_OK);
  assert(auth_replica_read_slot(&store, root_a, 42, &slot) ==
         AUTH_REPLICA_STORE_ABSENT);
}

static void test_unrelated_slots_survive_every_mutation(void) {
  auth_replica_store store;
  provision(&store);
  // Populate a handful of slots, then mutate one and check the rest.
  const uint8_t indices[] = {0, 5, 50, 99};
  for (unsigned i = 0; i < sizeof(indices); i++) {
    uint8_t record[64];
    memset(record, (uint8_t)(0x40 + i), sizeof(record));
    assert(auth_replica_commit_slot(&store, root_a, indices[i], record,
                                    sizeof(record),
                                    nonce2) == AUTH_REPLICA_STORE_OK);
  }
  assert(auth_replica_delete_slot(&store, root_a, 50, nonce1) ==
         AUTH_REPLICA_STORE_OK);
  auth_replica_slot_t slot;
  for (unsigned i = 0; i < sizeof(indices); i++) {
    auth_replica_store_result expected =
        indices[i] == 50 ? AUTH_REPLICA_STORE_ABSENT : AUTH_REPLICA_STORE_OK;
    assert(auth_replica_read_slot(&store, root_a, indices[i], &slot) ==
           expected);
    if (expected == AUTH_REPLICA_STORE_OK) {
      assert(slot.record_len == 64);
      assert(slot.record[0] == (uint8_t)(0x40 + i));
    }
  }
}

// ---------------------------------------------------------------------------
// Walking reads
// ---------------------------------------------------------------------------

typedef struct {
  unsigned visits;
  unsigned stop_after;  // 0 = run to the end
  auth_replica_store_result status[AUTH_REPLICA_SLOT_COUNT];
  uint16_t length[AUTH_REPLICA_SLOT_COUNT];
  uint8_t first_byte[AUTH_REPLICA_SLOT_COUNT];
} walk_log;

static bool walk_visit(void *context, uint8_t index,
                       auth_replica_store_result status,
                       const auth_replica_slot_t *slot) {
  walk_log *log = (walk_log *)context;
  // Index order with no gaps is part of the contract: a caller matching slots
  // to positions must not have to sort them.
  assert(index == log->visits);
  log->status[index] = status;
  log->length[index] = slot->record_len;
  log->first_byte[index] = slot->record_len ? slot->record[0] : 0;
  log->visits++;
  return !(log->stop_after && log->visits >= log->stop_after);
}

// The reason the walk exists. One pass costs one authentication plus one read
// per slot; authenticating per slot cost a hundred authentications, which on
// the device was six seconds for every command that touched the vault.
static void test_walk_authenticates_once_for_the_whole_pass(void) {
  auth_replica_store store;
  provision(&store);
  uint8_t record[64];
  memset(record, 0x5e, sizeof(record));
  assert(auth_replica_commit_slot(&store, root_a, 7, record, sizeof(record),
                                  nonce2) == AUTH_REPLICA_STORE_OK);

  // What one authenticated slot read costs: the header, the whole body, and the
  // slot itself.
  auth_replica_slot_t slot;
  total_reads = 0;
  assert(auth_replica_read_slot(&store, root_a, 7, &slot) ==
         AUTH_REPLICA_STORE_OK);
  unsigned one = total_reads;
  // The body pass dominates, which is what makes repeating it expensive.
  assert(one > AUTH_REPLICA_SLOT_COUNT);

  walk_log log = {0};
  total_reads = 0;
  assert(auth_replica_walk_slots(&store, root_a, walk_visit, &log) ==
         AUTH_REPLICA_STORE_OK);
  assert(log.visits == AUTH_REPLICA_SLOT_COUNT);
  // Exactly one authentication for the pass: the cost of a single read, plus
  // the ninety-nine further slot reads. Per-slot authentication would be one *
  // 100.
  assert(total_reads == one + AUTH_REPLICA_SLOT_COUNT - 1);

  // And it says the same thing a hundred separate reads would say.
  for (uint8_t index = 0; index < AUTH_REPLICA_SLOT_COUNT; index++) {
    auth_replica_store_result expected =
        auth_replica_read_slot(&store, root_a, index, &slot);
    assert(log.status[index] == expected);
    assert(log.length[index] == slot.record_len);
  }
  assert(log.status[7] == AUTH_REPLICA_STORE_OK);
  assert(log.length[7] == sizeof(record));
  assert(log.first_byte[7] == 0x5e);
  assert(log.status[8] == AUTH_REPLICA_STORE_ABSENT);
  // A walk reads and never writes.
  assert(total_writes == writes_to(0) + writes_to(1) + writes_to(2));
}

static void test_walk_stops_when_the_visitor_says_so(void) {
  auth_replica_store store;
  provision(&store);
  walk_log log = {0};
  log.stop_after = 4;
  assert(auth_replica_walk_slots(&store, root_a, walk_visit, &log) ==
         AUTH_REPLICA_STORE_OK);
  assert(log.visits == 4);
}

static void test_walk_presents_nothing_without_an_authenticated_snapshot(void) {
  auth_replica_store store;
  provision(&store);
  walk_log log = {0};
  assert(auth_replica_probe(&store, &io) == AUTH_REPLICA_STORE_OK);
  // The wrong root authenticates nothing, and an unauthenticated snapshot must
  // not release a single slot.
  assert(auth_replica_authenticate(&store, root_b) ==
         AUTH_REPLICA_STORE_NO_SOURCE);
  assert(auth_replica_walk_slots(&store, root_a, walk_visit, &log) ==
         AUTH_REPLICA_STORE_NO_SOURCE);
  assert(log.visits == 0);
  // A missing visitor is a programming error, not an empty walk.
  assert(auth_replica_walk_slots(&store, root_a, NULL, &log) ==
         AUTH_REPLICA_STORE_INVALID);
}

static void test_full_capacity_of_one_hundred_maximum_records(void) {
  auth_replica_store store;
  provision(&store);
  uint8_t record[AUTH_REPLICA_SLOT_RECORD_MAX];
  memset(record, 0x5c, sizeof(record));
  for (uint8_t index = 0; index < AUTH_REPLICA_SLOT_COUNT; index++) {
    assert(auth_replica_commit_slot(&store, root_a, index, record,
                                    sizeof(record),
                                    nonce2) == AUTH_REPLICA_STORE_OK);
  }
  assert(store.generation == 1 + AUTH_REPLICA_SLOT_COUNT);
  auth_replica_slot_t slot;
  for (uint8_t index = 0; index < AUTH_REPLICA_SLOT_COUNT; index++) {
    assert(auth_replica_read_slot(&store, root_a, index, &slot) ==
           AUTH_REPLICA_STORE_OK);
    assert(slot.record_len == AUTH_REPLICA_SLOT_RECORD_MAX);
    assert(slot.record[0] == 0x5c);
  }
}

static void test_generation_cap_refuses_mutation_without_any_write(void) {
  auth_replica_store store;
  provision(&store);
  // Force the selected generation to the cap.
  store.generation = AUTH_REPLICA_MAX_GENERATION;
  store.claimed_generation[store.selected] = AUTH_REPLICA_MAX_GENERATION;
  write_ops = erase_ops = 0;
  total_writes = total_erases = 0;
  assert(auth_replica_commit_slot(&store, root_a, 0, envelope, 40, nonce2) ==
         AUTH_REPLICA_STORE_LIMIT);
  assert(total_writes == 0 && total_erases == 0);

  store.generation = UINT64_MAX;
  store.claimed_generation[store.selected] = UINT64_MAX;
  assert(auth_replica_commit_slot(&store, root_a, 0, envelope, 40, nonce2) ==
         AUTH_REPLICA_STORE_LIMIT);
  assert(total_writes == 0 && total_erases == 0);

  // Wipe must remain available at the cap.
  assert(auth_replica_wipe(&store) == AUTH_REPLICA_STORE_OK);
  assert(total_erases == AUTH_REPLICA_COUNT * AUTH_REPLICA_PAGES_PER_AREA);
  for (uint8_t r = 0; r < AUTH_REPLICA_COUNT; r++) {
    // Every authenticated byte is gone, so no snapshot can survive.
    for (uint32_t i = 0; i < AUTH_REPLICA_USED_SIZE; i++)
      assert(flash[r][i] == 0xff);
    // The ownership claim deliberately remains: a wiped area is "ours and
    // empty", not "factory blank". Without it, a wipe interrupted on its last
    // page erase would leave garbage that looks like foreign data and would
    // block reprovisioning.
    assert(memcmp(flash[r] + AUTH_REPLICA_CLAIM_OFFSET,
                  AUTH_REPLICA_CLAIM_MAGIC,
                  sizeof(AUTH_REPLICA_CLAIM_MAGIC) - 1) == 0);
  }
  // A wiped device is reusable: it reports no source rather than demanding
  // migration, and can be provisioned again straight away.
  assert(auth_replica_probe(&store, &io) == AUTH_REPLICA_STORE_NO_SOURCE);
  assert(auth_replica_provision(&store, root_a, envelope, nonce1) ==
         AUTH_REPLICA_STORE_OK);
  assert(store.generation == 1);
}

static void test_repair_reproduces_snapshot_without_touching_the_source(void) {
  auth_replica_store store;
  provision(&store);
  assert(auth_replica_commit_slot(&store, root_a, 9, envelope, 50, nonce2) ==
         AUTH_REPLICA_STORE_OK);
  uint8_t source = store.selected;
  uint64_t generation = store.generation;
  uint8_t before[AREA];
  memcpy(before, flash[source], AREA);
  write_ops = erase_ops = 0;
  total_writes = total_erases = 0;

  assert(auth_replica_repair_one(&store, root_a) == AUTH_REPLICA_STORE_OK);
  assert(writes_to(source) == 0 && erases_of(source) == 0);
  assert(memcmp(before, flash[source], AREA) == 0);
  // Repair consumes no generation budget and keeps the same selection.
  assert(store.generation == generation);
  assert(store.selected == source);

  // After repair a second replica authenticates at the same generation.
  assert(auth_replica_probe(&store, &io) == AUTH_REPLICA_STORE_OK);
  assert(auth_replica_authenticate(&store, root_a) == AUTH_REPLICA_STORE_OK);
  unsigned authentic = 0;
  for (uint8_t r = 0; r < AUTH_REPLICA_COUNT; r++)
    if (store.authenticated[r] && store.claimed_generation[r] == generation)
      authentic++;
  assert(authentic >= 2);
  assert(!store.integrity_failed);
}

static void test_failed_write_leaves_previous_snapshot_authoritative(void) {
  auth_replica_store store;
  provision(&store);
  uint8_t source = store.selected;
  uint64_t generation = store.generation;
  uint8_t before[AREA];
  memcpy(before, flash[source], AREA);

  // Abort partway through the destination body.
  write_ops = erase_ops = 0;
  total_writes = total_erases = 0;
  fail_write_after = 200;
  assert(auth_replica_commit_slot(&store, root_a, 4, envelope, 40, nonce2) ==
         AUTH_REPLICA_STORE_IO);
  fail_write_after = 0;
  // Selection must not have moved, and the source is untouched.
  assert(store.selected == source);
  assert(store.generation == generation);
  assert(memcmp(before, flash[source], AREA) == 0);

  // A cold probe still recovers the old snapshot and nothing newer.
  assert(auth_replica_probe(&store, &io) == AUTH_REPLICA_STORE_OK);
  assert(auth_replica_authenticate(&store, root_a) == AUTH_REPLICA_STORE_OK);
  assert(store.generation == generation);
  auth_replica_slot_t slot;
  assert(auth_replica_read_slot(&store, root_a, 4, &slot) ==
         AUTH_REPLICA_STORE_ABSENT);
}

static void test_root_candidates_are_deduplicated(void) {
  auth_replica_store store;
  provision(&store);
  uint8_t valid = store.selected;
  uint8_t other = valid == 0 ? 1 : 0;
  memcpy(flash[other], flash[valid], AREA);  // same envelope twice
  assert(auth_replica_probe(&store, &io) == AUTH_REPLICA_STORE_OK);
  uint8_t candidates[AUTH_REPLICA_COUNT][AUTH_REPLICA_ROOT_LENGTH];
  uint8_t count = 0;
  assert(auth_replica_root_candidates(&store, candidates, &count) ==
         AUTH_REPLICA_STORE_OK);
  assert(count == 1);
  assert(memcmp(candidates[0], envelope, AUTH_REPLICA_ROOT_LENGTH) == 0);
}

// A destination torn by a power cut must stay reusable, while genuine legacy
// data in the very same byte range must still force migration. This is the
// boundary that keeps a mid-commit power loss from bricking the device into a
// permanent migration-required state.
static void test_torn_destination_is_reusable_but_legacy_is_not(void) {
  auth_replica_store store;
  provision(&store);
  uint8_t source = store.selected;
  uint64_t generation = store.generation;

  // Tear a commit partway through the destination body.
  total_writes = total_erases = 0;
  fail_write_after = 150;
  assert(auth_replica_commit_slot(&store, root_a, 6, envelope, 40, nonce2) ==
         AUTH_REPLICA_STORE_IO);
  fail_write_after = 0;

  // The torn area is recognised as ours, so the device stays usable.
  assert(auth_replica_probe(&store, &io) == AUTH_REPLICA_STORE_OK);
  bool saw_torn = false;
  for (uint8_t r = 0; r < AUTH_REPLICA_COUNT; r++)
    if (store.state[r] == AUTH_REPLICA_STATE_TORN) saw_torn = true;
  assert(saw_torn);
  assert(auth_replica_authenticate(&store, root_a) == AUTH_REPLICA_STORE_OK);
  assert(store.generation == generation);
  assert(store.selected == source);

  // And a retry succeeds, reusing the torn area.
  assert(auth_replica_commit_slot(&store, root_a, 6, envelope, 40, nonce2) ==
         AUTH_REPLICA_STORE_OK);
  assert(store.generation == generation + 1);

  // Same byte range, but written by something else: still migration.
  reset_flash();
  uint8_t stray[AUTH_REPLICA_LINE_SIZE];
  memset(stray, 0x5a, sizeof(stray));
  memcpy(flash[2] + AUTH_REPLICA_CLAIM_OFFSET, stray, sizeof(stray));
  assert(auth_replica_probe(&store, &io) == AUTH_REPLICA_STORE_MIGRATION);
  assert(store.state[2] == AUTH_REPLICA_STATE_FOREIGN);
  assert(total_writes == 0 && total_erases == 0);
}

// A first-provisioning attempt interrupted by a power cut must remain
// retryable rather than latching migration on its own scratch area.
static void test_torn_first_provisioning_can_be_retried(void) {
  reset_flash();
  auth_replica_store store;
  assert(auth_replica_probe(&store, &io) == AUTH_REPLICA_STORE_BLANK);
  fail_write_after = 100;
  assert(auth_replica_provision(&store, root_a, envelope, nonce1) ==
         AUTH_REPLICA_STORE_IO);
  fail_write_after = 0;

  assert(auth_replica_probe(&store, &io) == AUTH_REPLICA_STORE_NO_SOURCE);
  assert(auth_replica_provision(&store, root_a, envelope, nonce1) ==
         AUTH_REPLICA_STORE_OK);
  assert(store.generation == 1);
  assert(auth_replica_authenticate(&store, root_a) == AUTH_REPLICA_STORE_OK);
}

// Repair must produce a byte-identical duplicate. A repaired copy carrying a
// fresh nonce would be a divergent same-generation snapshot, which the
// selector is obliged to reject outright.
static void test_repair_duplicate_is_byte_identical(void) {
  auth_replica_store store;
  provision(&store);
  assert(auth_replica_commit_slot(&store, root_a, 11, envelope, 44, nonce2) ==
         AUTH_REPLICA_STORE_OK);
  uint8_t source = store.selected;
  assert(auth_replica_repair_one(&store, root_a) == AUTH_REPLICA_STORE_OK);

  uint8_t copies[AUTH_REPLICA_COUNT], found = 0;
  for (uint8_t r = 0; r < AUTH_REPLICA_COUNT; r++) {
    uint8_t header[AUTH_REPLICA_HEADER_SIZE];
    if (sim_read(NULL, r, 0, header, sizeof(header)) != AUTH_REPLICA_IO_OK)
      continue;
    auth_replica_header_t decoded;
    if (auth_replica_header_decode(header, &decoded) != AUTH_REPLICA_OK)
      continue;
    if (decoded.generation == store.generation) copies[found++] = r;
  }
  assert(found == 2);
  // Byte-for-byte equality across the whole authenticated snapshot.
  assert(memcmp(flash[copies[0]], flash[copies[1]], AUTH_REPLICA_USED_SIZE) ==
         0);
  assert(source == copies[0] || source == copies[1]);
}

int main(void) {
  init_fixtures();

  test_blank_media_is_blank_not_migration();
  test_foreign_bytes_require_migration_and_never_erase();
  test_provisioning_then_authentication_selects_generation_one();
  test_highest_authenticated_generation_wins();
  test_forged_high_generation_is_never_selected();
  test_identical_same_generation_tie_is_accepted();
  test_divergent_same_generation_tie_latches_integrity();
  test_corrected_ecc_still_authenticates_and_is_marked_degraded();
  test_uncorrectable_ecc_excludes_only_that_replica();
  test_no_authenticated_candidate_reports_no_source();

  test_commit_never_writes_the_source();
  test_destination_erases_all_pages_in_increasing_order();
  test_body_lines_precede_header_lines();
  test_destination_rotates_across_all_three_replicas();
  test_slot_round_trip_replace_and_delete();
  test_unrelated_slots_survive_every_mutation();
  test_walk_authenticates_once_for_the_whole_pass();
  test_walk_stops_when_the_visitor_says_so();
  test_walk_presents_nothing_without_an_authenticated_snapshot();
  test_full_capacity_of_one_hundred_maximum_records();
  test_generation_cap_refuses_mutation_without_any_write();
  test_repair_reproduces_snapshot_without_touching_the_source();
  test_repair_duplicate_is_byte_identical();
  test_torn_destination_is_reusable_but_legacy_is_not();
  test_torn_first_provisioning_can_be_retried();
  test_failed_write_leaves_previous_snapshot_authoritative();
  test_root_candidates_are_deduplicated();

  printf("replica store: PASS\n");
  return 0;
}
