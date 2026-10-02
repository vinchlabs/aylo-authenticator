// Exhaustive power-cut / unknown-content / ECC recovery model for the
// three-replica vault.
//
// A power loss is modelled as a hard stop, not as an error return: the
// simulated flash applies an indeterminate pattern to the program line or
// erase page that was in flight and then longjmp()s straight out of the
// manager. No error path runs, nothing is cleaned up, and the manager gets no
// chance to react -- exactly what happens when the rail collapses mid-write.
//
// The interrupted unit is deliberately NOT assumed to be atomic. ST documents
// that an interrupted STM32U5 program or erase leaves unknown contents and may
// raise ECCD, so each cut is replayed with every pattern in `unknown_pattern`
// and, separately, with the torn range configured to fail reads with an
// uncorrectable ECC error.
//
// Headline requirement: for any single interruption, recovery after unlock
// must yield the old authenticated state, the new authenticated state, or (for
// a committed wipe) an intentionally empty one. `unexpected_unavailable` must
// finish at zero.
//
// Performance note: verification authenticates the recovered snapshot once
// through the production selector and then decodes slot regions directly from
// the simulated medium. Routing each of the 100 slot reads through
// auth_replica_read_slot() would re-authenticate the whole 57 KiB body every
// time, which is correct behaviour for production but turns this matrix into
// hundreds of gigabytes of hashing.

#include <assert.h>
#include <setjmp.h>
#include <stdio.h>
#include <string.h>

#include "../replica_store.h"

#define AREA AUTH_REPLICA_AREA_SIZE

// Mirror of the region offsets replica_store.c keeps private.
#define TEST_ROOT_REGION_OFFSET AUTH_REPLICA_HEADER_SIZE
#define TEST_SLOT_REGION_OFFSET \
  (TEST_ROOT_REGION_OFFSET + AUTH_REPLICA_ROOT_REGION_SIZE)
#define TEST_SLOT_OFFSET(index) \
  (TEST_SLOT_REGION_OFFSET + (uint32_t)(index) * AUTH_REPLICA_SLOT_SIZE)

// ---------------------------------------------------------------------------
// Simulated flash with power-cut injection
// ---------------------------------------------------------------------------

static uint8_t flash[AUTH_REPLICA_COUNT][AREA];
static uint8_t baseline[AUTH_REPLICA_COUNT][AREA];

typedef enum {
  PATTERN_ZERO = 0,     // every bit programmed
  PATTERN_ERASED,       // operation had no observable effect
  PATTERN_ALTERNATING,  // partially programmed bit soup
  PATTERN_RANDOM,       // deterministic pseudorandom soup
  PATTERN_COUNT,
} unknown_pattern;

static const char *pattern_name[PATTERN_COUNT] = {"zero", "erased",
                                                  "alternating", "random"};

static jmp_buf power_cut;
static bool cut_armed;
static unsigned cut_at;      // ordinal of the mutating op to interrupt
static unsigned op_ordinal;  // counts erases and writes together
static unknown_pattern cut_pattern;
static bool cut_raises_eccd;  // torn range reads as uncorrectable ECC

// ECC injection window (also used to model ECCD on the torn unit).
static uint8_t ecc_replica = AUTH_REPLICA_NONE;
static uint32_t ecc_from, ecc_to;

static uint32_t lcg_state;
static uint8_t lcg_next(void) {
  lcg_state = lcg_state * 1103515245u + 12345u;
  return (uint8_t)(lcg_state >> 16);
}

static void apply_unknown(uint8_t *target, uint32_t len) {
  switch (cut_pattern) {
    case PATTERN_ZERO:
      memset(target, 0x00, len);
      break;
    case PATTERN_ERASED:
      break;  // the in-flight operation simply left no trace
    case PATTERN_ALTERNATING:
      for (uint32_t i = 0; i < len; i++) target[i] = (i & 1) ? 0x5a : 0xa5;
      break;
    case PATTERN_RANDOM:
      for (uint32_t i = 0; i < len; i++) target[i] = lcg_next();
      break;
    default:
      break;
  }
}

static void trigger_cut(uint8_t replica, uint32_t offset, uint32_t len) {
  apply_unknown(flash[replica] + offset, len);
  if (cut_raises_eccd && len) {
    ecc_replica = replica;
    ecc_from = offset;
    ecc_to = offset + len;
  }
  cut_armed = false;
  longjmp(power_cut, 1);
}

static auth_replica_io_result sim_read(void *context, uint8_t replica,
                                       uint32_t offset, uint8_t *out,
                                       uint32_t len) {
  (void)context;
  if (replica >= AUTH_REPLICA_COUNT || (uint64_t)offset + len > AREA) {
    memset(out, 0, len);
    return AUTH_REPLICA_IO_RANGE;
  }
  if (replica == ecc_replica && offset < ecc_to && offset + len > ecc_from) {
    memset(out, 0, len);
    return AUTH_REPLICA_IO_ECC_UNCORRECTABLE;
  }
  memcpy(out, flash[replica] + offset, len);
  return AUTH_REPLICA_IO_OK;
}

static bool sim_write(void *context, uint8_t replica, uint32_t offset,
                      const uint8_t line[AUTH_REPLICA_LINE_SIZE]) {
  (void)context;
  assert(offset % AUTH_REPLICA_LINE_SIZE == 0);
  if (replica >= AUTH_REPLICA_COUNT ||
      (uint64_t)offset + AUTH_REPLICA_LINE_SIZE > AREA)
    return false;
  if (cut_armed && op_ordinal == cut_at) {
    op_ordinal++;
    trigger_cut(replica, offset, AUTH_REPLICA_LINE_SIZE);
  }
  op_ordinal++;
  memcpy(flash[replica] + offset, line, AUTH_REPLICA_LINE_SIZE);
  return true;
}

static bool sim_erase(void *context, uint8_t replica, uint32_t offset) {
  (void)context;
  assert(offset % AUTH_REPLICA_PAGE_SIZE == 0);
  if (replica >= AUTH_REPLICA_COUNT ||
      (uint64_t)offset + AUTH_REPLICA_PAGE_SIZE > AREA)
    return false;
  if (cut_armed && op_ordinal == cut_at) {
    op_ordinal++;
    // An interrupted page erase leaves the page indeterminate; the "erased"
    // pattern models the erase not having taken effect at all.
    trigger_cut(replica, offset,
                cut_pattern == PATTERN_ERASED ? 0 : AUTH_REPLICA_PAGE_SIZE);
  }
  op_ordinal++;
  memset(flash[replica] + offset, 0xff, AUTH_REPLICA_PAGE_SIZE);
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
static uint8_t envelope[AUTH_REPLICA_ROOT_LENGTH];
static uint8_t nonce1[16], nonce2[16];

static const uint8_t tracked[] = {0, 5, 50, 99};
#define TRACKED_COUNT (sizeof(tracked) / sizeof(tracked[0]))
#define TRACKED_LEN 64
static uint8_t mutated_record[96];

static void fill_tracked(uint8_t index, uint8_t *out) {
  for (unsigned i = 0; i < TRACKED_LEN; i++)
    out[i] = (uint8_t)(index * 3 + i + 1);
}

static void reset_injection(void) {
  cut_armed = false;
  cut_raises_eccd = false;
  cut_pattern = PATTERN_ZERO;
  op_ordinal = 0;
  ecc_replica = AUTH_REPLICA_NONE;
  ecc_from = ecc_to = 0;
  lcg_state = 0x12345678u;
}

static void blank_flash(void) {
  memset(flash, 0xff, sizeof(flash));
  reset_injection();
}

// ---------------------------------------------------------------------------
// Matrix operations
// ---------------------------------------------------------------------------

typedef enum {
  OP_PROVISION,
  OP_CREATE,
  OP_REPLACE,
  OP_DELETE,
  OP_FULL_REPLACE,
  OP_REPAIR_FROM_ONE,
  OP_REPAIR_FROM_TWO,
  OP_WIPE,
  OP_COUNT,
} matrix_op;

static const char *op_name[OP_COUNT] = {
    "provision",    "create",          "replace",         "delete",
    "full-replace", "repair-from-one", "repair-from-two", "wipe"};

#define OP_CREATE_SLOT 7
#define OP_REPLACE_SLOT 5
#define OP_DELETE_SLOT 50
#define OP_FULL_REPLACE_SLOT 50

static void run_operation(auth_replica_store *store, matrix_op op) {
  switch (op) {
    case OP_PROVISION:
      auth_replica_provision(store, root_a, envelope, nonce1);
      break;
    case OP_CREATE:
      auth_replica_commit_slot(store, root_a, OP_CREATE_SLOT, mutated_record,
                               sizeof(mutated_record), nonce2);
      break;
    case OP_REPLACE:
      auth_replica_commit_slot(store, root_a, OP_REPLACE_SLOT, mutated_record,
                               sizeof(mutated_record), nonce2);
      break;
    case OP_DELETE:
      auth_replica_delete_slot(store, root_a, OP_DELETE_SLOT, nonce2);
      break;
    case OP_FULL_REPLACE:
      auth_replica_commit_slot(store, root_a, OP_FULL_REPLACE_SLOT,
                               mutated_record, sizeof(mutated_record), nonce2);
      break;
    case OP_REPAIR_FROM_ONE:
    case OP_REPAIR_FROM_TWO:
      auth_replica_repair_one(store, root_a);
      break;
    case OP_WIPE:
      auth_replica_wipe(store);
      break;
    default:
      break;
  }
}

static uint64_t build_baseline(matrix_op op) {
  blank_flash();
  auth_replica_store store;

  if (op == OP_PROVISION) {
    assert(auth_replica_probe(&store, &io) == AUTH_REPLICA_STORE_BLANK);
    memcpy(baseline, flash, sizeof(flash));
    return 0;
  }

  assert(auth_replica_probe(&store, &io) == AUTH_REPLICA_STORE_BLANK);
  assert(auth_replica_provision(&store, root_a, envelope, nonce1) ==
        AUTH_REPLICA_STORE_OK);

  if (op == OP_FULL_REPLACE) {
    // Worst case: all 100 slots occupied at maximum record length.
    uint8_t record[AUTH_REPLICA_SLOT_RECORD_MAX];
    memset(record, 0x3c, sizeof(record));
    for (uint8_t index = 0; index < AUTH_REPLICA_SLOT_COUNT; index++) {
      assert(auth_replica_commit_slot(&store, root_a, index, record,
                                      sizeof(record), nonce2) ==
            AUTH_REPLICA_STORE_OK);
    }
  } else {
    uint8_t record[TRACKED_LEN];
    for (unsigned i = 0; i < TRACKED_COUNT; i++) {
      fill_tracked(tracked[i], record);
      assert(auth_replica_commit_slot(&store, root_a, tracked[i], record,
                                      TRACKED_LEN, nonce2) ==
            AUTH_REPLICA_STORE_OK);
    }
  }

  if (op == OP_REPAIR_FROM_TWO) {
    assert(auth_replica_repair_one(&store, root_a) == AUTH_REPLICA_STORE_OK);
  }

  uint64_t generation = store.generation;
  memcpy(baseline, flash, sizeof(flash));
  reset_injection();
  return generation;
}

// ---------------------------------------------------------------------------
// Recovery verification
// ---------------------------------------------------------------------------

static unsigned unexpected_unavailable;
static unsigned recovered_old, recovered_new, recovered_empty;
// Interrupted *first* provisioning that left the device needing an explicit
// reformat. Never counted as a clean recovery.
static unsigned provision_needs_reformat;

// Decodes one slot region of an already-authenticated replica directly.
static bool read_slot_direct(uint8_t replica, uint8_t index,
                             auth_replica_slot_t *out) {
  uint8_t region[AUTH_REPLICA_SLOT_SIZE];
  if (sim_read(NULL, replica, TEST_SLOT_OFFSET(index), region,
               sizeof(region)) != AUTH_REPLICA_IO_OK)
    return false;
  return auth_replica_slot_decode(region, index, out) == AUTH_REPLICA_OK;
}

// The advertised bitmap/present-count must agree with what the slots actually
// contain, so a torn write cannot leave a snapshot whose enumeration disagrees
// with its own contents or double-counts an entry.
static bool check_enumeration(uint8_t replica) {
  uint8_t header_bytes[AUTH_REPLICA_HEADER_SIZE];
  if (sim_read(NULL, replica, 0, header_bytes, sizeof(header_bytes)) !=
      AUTH_REPLICA_IO_OK)
    return false;
  auth_replica_header_t header;
  if (auth_replica_header_decode(header_bytes, &header) != AUTH_REPLICA_OK)
    return false;

  unsigned present = 0;
  for (uint8_t index = 0; index < AUTH_REPLICA_SLOT_COUNT; index++) {
    auth_replica_slot_t slot;
    if (!read_slot_direct(replica, index, &slot)) return false;
    bool bit = ((header.bitmap[index / 8] >> (index % 8)) & 1u) != 0;
    if (slot.present != bit) return false;
    if (slot.present) present++;
  }
  return present == header.present_count;
}

// Tracked slots the operation was not supposed to touch must be intact.
static bool check_unrelated_slots(uint8_t replica, matrix_op op) {
  if (op == OP_FULL_REPLACE) return true;  // uniform records
  uint8_t mutating = 0xff;
  if (op == OP_REPLACE) mutating = OP_REPLACE_SLOT;
  if (op == OP_DELETE) mutating = OP_DELETE_SLOT;

  uint8_t expected[TRACKED_LEN];
  for (unsigned i = 0; i < TRACKED_COUNT; i++) {
    if (tracked[i] == mutating) continue;
    auth_replica_slot_t slot;
    if (!read_slot_direct(replica, tracked[i], &slot)) return false;
    if (!slot.present || slot.record_len != TRACKED_LEN) return false;
    fill_tracked(tracked[i], expected);
    if (memcmp(slot.record, expected, TRACKED_LEN) != 0) return false;
  }
  return true;
}

static void report(matrix_op op, unsigned cut_point, const char *why) {
  if (unexpected_unavailable < 20) {
    printf("FAIL %s cut=%u pattern=%s eccd=%d: %s\n", op_name[op], cut_point,
           pattern_name[cut_pattern], cut_raises_eccd ? 1 : 0, why);
  }
  unexpected_unavailable++;
}

static void verify_recovery(matrix_op op, uint64_t old_generation,
                            unsigned cut_point) {
  // A reboot starts from a cold probe; nothing from the interrupted call
  // survives in RAM.
  auth_replica_store store;
  auth_replica_store_result probed = auth_replica_probe(&store, &io);

  if (probed == AUTH_REPLICA_STORE_MIGRATION) {
    // Accepted in exactly one situation: a *first* provisioning interrupted
    // during the claim-page erase, before this device was ever claimed. No
    // vault and no user data existed, so nothing became unavailable; the
    // device simply requires an explicit provision-with-reformat.
    //
    // This window is left deliberately conservative rather than closed with a
    // "the low pages look erased, so it cannot be legacy data" inference. The
    // risk is asymmetric: wrongly erasing a real wallet is far worse than
    // asking a brand-new device to be provisioned explicitly. It is counted
    // separately so it can never be mistaken for a clean recovery.
    if (op == OP_PROVISION) {
      provision_needs_reformat++;
      return;
    }
    report(op, cut_point, "probe demanded migration");
    return;
  }

  if (op == OP_PROVISION) {
    if (probed == AUTH_REPLICA_STORE_BLANK ||
        probed == AUTH_REPLICA_STORE_NO_SOURCE) {
      recovered_empty++;
      return;
    }
    if (auth_replica_authenticate(&store, root_a) == AUTH_REPLICA_STORE_OK) {
      if (store.generation != 1 || !check_enumeration(store.selected)) {
        report(op, cut_point, "provisioned snapshot inconsistent");
        return;
      }
      recovered_new++;
      return;
    }
    // No authenticated snapshot after an interrupted first provisioning is an
    // acceptable, retryable empty outcome.
    recovered_empty++;
    return;
  }

  if (op == OP_WIPE) {
    // Wipe is asymmetric on purpose: either something still survives because
    // the erase sweep had not finished, or everything is gone. It must never
    // come back as a corrupt or ambiguous state.
    //
    // A partially completed wipe can legitimately expose an *older* surviving
    // generation: the baseline spans several generations across the rotating
    // replicas, so erasing the newest one first leaves an older authenticated
    // snapshot behind. That is a correct outcome, not a rollback defect -- in
    // production the root is destroyed before the erase sweep begins, which is
    // what makes every surviving replica cryptographically useless.
    if (probed == AUTH_REPLICA_STORE_BLANK ||
        probed == AUTH_REPLICA_STORE_NO_SOURCE) {
      recovered_empty++;
      return;
    }
    auth_replica_store_result authed =
        auth_replica_authenticate(&store, root_a);
    if (authed == AUTH_REPLICA_STORE_OK) {
      if (store.generation > old_generation || store.generation == 0) {
        report(op, cut_point, "wipe exposed an impossible generation");
        return;
      }
      if (!check_enumeration(store.selected)) {
        report(op, cut_point, "wipe left an inconsistent snapshot");
        return;
      }
      recovered_old++;
      return;
    }
    if (authed == AUTH_REPLICA_STORE_NO_SOURCE) {
      recovered_empty++;
      return;
    }
    report(op, cut_point, "wipe left an integrity failure");
    return;
  }

  // Every other operation had an intact authenticated source before the cut,
  // so recovery is mandatory.
  if (auth_replica_authenticate(&store, root_a) != AUTH_REPLICA_STORE_OK) {
    report(op, cut_point, "no authenticated snapshot after recovery");
    return;
  }

  bool is_old = store.generation == old_generation;
  bool is_new = store.generation == old_generation + 1;
  if (!is_old && !is_new) {
    report(op, cut_point, "generation is neither the old nor the new one");
    return;
  }
  // The selected snapshot must be genuinely authenticated, never the torn
  // destination that was mid-write when power vanished.
  if (!store.authenticated[store.selected]) {
    report(op, cut_point, "selected replica is not authenticated");
    return;
  }
  if (!check_enumeration(store.selected)) {
    report(op, cut_point, "enumeration disagrees with contents");
    return;
  }
  if (!check_unrelated_slots(store.selected, op)) {
    report(op, cut_point, "an unrelated slot was lost or altered");
    return;
  }

  if (is_old)
    recovered_old++;
  else
    recovered_new++;
}

// ---------------------------------------------------------------------------
// Matrix driver
// ---------------------------------------------------------------------------

static void prepare(auth_replica_store *store, matrix_op op) {
  memcpy(flash, baseline, sizeof(flash));
  reset_injection();
  auth_replica_probe(store, &io);
  if (op != OP_PROVISION) auth_replica_authenticate(store, root_a);
}

static unsigned count_operations(matrix_op op) {
  auth_replica_store store;
  prepare(&store, op);
  op_ordinal = 0;
  run_operation(&store, op);
  return op_ordinal;
}

static void run_one_cut(matrix_op op, uint64_t old_generation, unsigned point,
                        unknown_pattern pattern, bool eccd) {
  auth_replica_store store;
  prepare(&store, op);
  cut_pattern = pattern;
  cut_raises_eccd = eccd;

  op_ordinal = 0;
  cut_at = point;
  if (setjmp(power_cut) == 0) {
    cut_armed = true;
    run_operation(&store, op);
  }
  cut_armed = false;

  verify_recovery(op, old_generation, point);
}

// Structurally interesting boundaries: the erase sweep, the ownership claim,
// the region edges, and every header line (the commit condition). A coprime
// stride keeps long runs of body lines from going unexercised.
static bool interesting(unsigned point, unsigned total) {
  if (point < 16) return true;
  if (total >= 24 && point >= total - 24) return true;
  return point % 197 == 0;
}

static unsigned total_scenarios;

static void run_matrix(matrix_op op) {
  uint64_t old_generation = build_baseline(op);
  unsigned total = count_operations(op);
  assert(total > 0);

  unsigned points = 0;
  // `point == total` interrupts nothing: every write lands and the operation
  // completes, but power vanishes before the manager returns. That case must
  // recover as the NEW state, and it is the only way to reach it -- cutting at
  // any earlier ordinal leaves the final header line unwritten.
  for (unsigned point = 0; point <= total; point++) {
    if (point != total && !interesting(point, total)) continue;
    points++;
    for (unsigned pattern = 0; pattern < PATTERN_COUNT; pattern++) {
      run_one_cut(op, old_generation, point, (unknown_pattern)pattern, false);
      // Same cut, but the torn unit now raises an uncorrectable ECC error.
      run_one_cut(op, old_generation, point, (unknown_pattern)pattern, true);
      total_scenarios += 2;
    }
  }
  printf("  %-16s boundaries=%5u sampled=%4u\n", op_name[op], total, points);
}

// One operation is swept across *every* boundary rather than a sample, to
// prove the sampling stride is not hiding anything.
static void run_exhaustive(matrix_op op) {
  uint64_t old_generation = build_baseline(op);
  unsigned total = count_operations(op);
  for (unsigned point = 0; point <= total; point++) {
    run_one_cut(op, old_generation, point, PATTERN_RANDOM, false);
    total_scenarios++;
  }
  printf("  %-16s exhaustive over %u boundaries\n", op_name[op], total);
}

// Review Focus: a cut during repair must never damage the selected source, and
// the vault must stay usable afterwards.
static void run_repair_source_integrity(void) {
  uint64_t old_generation = build_baseline(OP_REPAIR_FROM_ONE);
  unsigned total = count_operations(OP_REPAIR_FROM_ONE);

  auth_replica_store probe_store;
  prepare(&probe_store, OP_REPAIR_FROM_ONE);
  uint8_t source = probe_store.selected;
  static uint8_t source_before[AREA];
  memcpy(source_before, flash[source], AREA);

  unsigned checked = 0;
  // Both loop variables live across setjmp(), so they must not be kept in
  // call-saved registers that longjmp() would restore.
  for (volatile unsigned point = 0; point < total; point++) {
    if (!interesting((unsigned)point, total)) continue;
    for (volatile unsigned pattern = 0; pattern < PATTERN_COUNT; pattern++) {
      auth_replica_store store;
      prepare(&store, OP_REPAIR_FROM_ONE);
      assert(store.selected == source);
      cut_pattern = (unknown_pattern)(unsigned)pattern;

      op_ordinal = 0;
      cut_at = (unsigned)point;
      if (setjmp(power_cut) == 0) {
        cut_armed = true;
        auth_replica_repair_one(&store, root_a);
      }
      cut_armed = false;

      // The source must be byte-identical no matter where the repair died.
      assert(memcmp(source_before, flash[source], AREA) == 0);
      verify_recovery(OP_REPAIR_FROM_ONE, old_generation, (unsigned)point);
      checked++;
      total_scenarios++;
    }
  }
  printf("  %-16s source-integrity checks=%u\n", "repair-cut", checked);
}

int main(void) {
  for (unsigned i = 0; i < sizeof(envelope); i++) envelope[i] = (uint8_t)(i + 1);
  memset(nonce1, 0x11, sizeof(nonce1));
  memset(nonce2, 0x22, sizeof(nonce2));
  memset(mutated_record, 0x6d, sizeof(mutated_record));

  printf("power-cut matrix:\n");
  for (unsigned op = 0; op < OP_COUNT; op++) run_matrix((matrix_op)op);
  run_exhaustive(OP_REPLACE);
  run_repair_source_integrity();

  printf("scenarios=%u recovered_old=%u recovered_new=%u recovered_empty=%u\n",
         total_scenarios, recovered_old, recovered_new, recovered_empty);
  printf("provision_needs_reformat=%u (interrupted first provisioning, no vault existed)\n",
         provision_needs_reformat);
  printf("unexpected_unavailable=%u\n", unexpected_unavailable);
  if (unexpected_unavailable) {
    printf("replica power-cut: FAIL\n");
    return 1;
  }
  // Guard against the sweep silently losing a whole outcome class. Every one of
  // these must be reachable, or the matrix is not exercising what it claims.
  if (!recovered_old || !recovered_new || !recovered_empty) {
    printf("replica power-cut: FAIL (an outcome class was never reached)\n");
    return 1;
  }
  printf("replica power-cut: PASS\n");
  return 0;
}
