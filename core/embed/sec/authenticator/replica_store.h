#pragma once
// Three-replica authenticated snapshot manager.
//
// Responsibilities: classify the three replica areas, expose root-envelope
// candidates, select the newest *authenticated* snapshot, and perform logical
// mutations as copy-on-write transactions that never write the source.
//
// Explicit non-responsibilities:
//   * no flash addresses or MPU handling (see authenticator_replica_io.h);
//   * no PIN/OPTIGA/KEK logic and no root unwrapping (see authenticator.c);
//   * no RNG: the snapshot nonce is supplied by the caller so this module
//     stays deterministic and host-testable;
//   * no persistent retention of the root or any root-derived key. The root
//     is passed per call, the replica MAC key is derived into a local, and
//     both are zeroized before return. The struct below keeps only the
//     selected index, its generation, and public classification.
//
// Commit protocol (per the design's immutable-source rule):
//   1. authenticate the source snapshot;
//   2. pick a destination that is not the source;
//   3. erase the destination's pages in increasing offset order;
//   4. stream the new body (root region, then slots in physical order),
//      applying exactly one logical mutation, computing the body digest as
//      it is written;
//   5. read the body back and compute the snapshot MAC over the header head
//      plus the read-back body, confirming the digest still matches;
//   6. write the 160-byte header last;
//   7. independently re-read and authenticate the whole destination;
//   8. only then move the selected index/generation.
//
// A power loss anywhere before step 7 succeeds leaves the previous source
// authoritative, because authentication of the complete destination -- not
// the presence of a header or a commit flag -- is the commit condition.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "authenticator_replica_io.h"
#include "replica_format.h"

// HKDF-SHA256 label deriving the snapshot MAC key from the 32-byte root.
#define AUTH_REPLICA_MAC_LABEL "trezor authenticator replica v1"

// Ownership claim marker, written into the format's reserved headroom right
// after a destination is erased and before its body is streamed.
//
// Its only purpose is to distinguish "an area this vault was in the middle of
// writing" from "an area holding legacy wallet/NORCOW or foreign data". Without
// it, a power cut during a commit would leave a partially written area that is
// non-erased and header-less, which the conservative migration rule would
// classify as foreign -- permanently refusing to touch the device even though
// the torn area is our own scratch space. That would turn any mid-commit power
// loss into exactly the unavailable outcome this design exists to prevent.
//
// It is deliberately NOT a commit flag and NOT covered by the snapshot MAC: it
// lives outside AUTH_REPLICA_USED_SIZE, is never consulted when selecting or
// validating a snapshot, and can only ever make an area eligible to be erased
// and rewritten. Authentication of a complete snapshot remains the sole commit
// condition.
#define AUTH_REPLICA_CLAIM_OFFSET AUTH_REPLICA_USED_SIZE
#define AUTH_REPLICA_CLAIM_MAGIC "TSAUTHC1"

typedef enum {
  AUTH_REPLICA_STORE_OK = 0,
  // Every area is fully erased. Provisioning is permitted.
  AUTH_REPLICA_STORE_BLANK,
  // At least one area holds non-erased bytes that are not a canonical
  // replica header. Never erased or rewritten implicitly; the caller must
  // surface this as migration-required.
  AUTH_REPLICA_STORE_MIGRATION,
  // Replicas exist but none authenticated under the supplied root.
  AUTH_REPLICA_STORE_NO_SOURCE,
  // Latched integrity failure, e.g. two authenticated replicas share the
  // highest generation but have different authenticated contents.
  AUTH_REPLICA_STORE_INTEGRITY,
  // Generation/wear ceiling reached. Mutations refuse; wipe still allowed.
  AUTH_REPLICA_STORE_LIMIT,
  // Erase/program/read failure from the IO layer.
  AUTH_REPLICA_STORE_IO,
  AUTH_REPLICA_STORE_INVALID,
  // Requested slot is canonically empty (an expected enumeration result).
  AUTH_REPLICA_STORE_ABSENT,
} auth_replica_store_result;

typedef enum {
  AUTH_REPLICA_STATE_BLANK = 0,
  // Non-erased bytes without a canonical replica header and without our
  // ownership claim: legacy wallet data, another application, or damage.
  AUTH_REPLICA_STATE_FOREIGN,
  // Carries our ownership claim but no valid header: a destination torn by a
  // power cut mid-commit. Safe to erase and reuse; never selectable as data.
  AUTH_REPLICA_STATE_TORN,
  // Header decodes canonically. NOT yet proof of authenticity.
  AUTH_REPLICA_STATE_STRUCTURAL,
  // Canonical header, but a corrected ECC error was observed while reading.
  AUTH_REPLICA_STATE_DEGRADED,
  // Uncorrectable ECC or IO failure; this replica is excluded.
  AUTH_REPLICA_STATE_UNREADABLE,
} auth_replica_state;

typedef struct {
  const auth_replica_io *io;
  // AUTH_REPLICA_NONE until a snapshot has been authenticated.
  uint8_t selected;
  uint64_t generation;
  bool integrity_failed;
  auth_replica_state state[AUTH_REPLICA_COUNT];
  // Structural (unauthenticated) generation claim, for destination choice
  // and diagnostics only. Never used to select data.
  uint64_t claimed_generation[AUTH_REPLICA_COUNT];
  bool authenticated[AUTH_REPLICA_COUNT];
} auth_replica_store;

// Classifies all three areas. Performs no writes and releases no slot data.
// Returns BLANK, MIGRATION, or OK (at least one structural candidate).
auth_replica_store_result auth_replica_probe(auth_replica_store *store,
                                             const auth_replica_io *io);

// Copies up to AUTH_REPLICA_COUNT deduplicated root envelopes from
// structurally valid replicas into `out`. These are ciphertext envelopes, not
// roots; the caller unwraps them behind its own PIN/KEK boundary.
auth_replica_store_result auth_replica_root_candidates(
    auth_replica_store *store,
    uint8_t out[AUTH_REPLICA_COUNT][AUTH_REPLICA_ROOT_LENGTH], uint8_t *count);

// Authenticates every structural replica under `root` and selects the
// highest authenticated generation. A same-generation pair with identical
// authenticated contents is accepted; a divergent one latches INTEGRITY.
auth_replica_store_result auth_replica_authenticate(auth_replica_store *store,
                                                    const uint8_t root[32]);

// Reads the 62-byte root envelope from the selected authenticated snapshot.
auth_replica_store_result auth_replica_read_root(
    auth_replica_store *store, const uint8_t root[32],
    uint8_t out[AUTH_REPLICA_ROOT_LENGTH]);

// Reads one slot from the selected authenticated snapshot. Returns ABSENT for
// a canonically empty slot.
auth_replica_store_result auth_replica_read_slot(auth_replica_store *store,
                                                 const uint8_t root[32],
                                                 uint8_t index,
                                                 auth_replica_slot_t *out);

// Presented once per slot, in index order. `status` is OK for a decoded record,
// ABSENT for a canonically empty slot, or INTEGRITY for bytes that do not
// decode. Returning false ends the walk.
typedef bool (*auth_replica_slot_visitor)(void *context, uint8_t index,
                                          auth_replica_store_result status,
                                          const auth_replica_slot_t *slot);

// Reads every slot from the selected authenticated snapshot, authenticating
// that snapshot exactly once for the whole walk.
//
// Why this keeps what auth_replica_read_slot promises. The snapshot MAC is
// computed in its own pass across the body, and the bytes handed back come from
// a separate later read, so authenticating per slot never made the released
// bytes authenticated -- it attested that the snapshot was intact a moment
// earlier. A walk attests exactly that for the walk, which is the granularity
// at which a caller consumes it. Per-read ECC detection is untouched: every
// slot is still read through the checked reader, so a corrected or
// uncorrectable error is seen on the read that meets it.
//
// What genuinely changes: damage appearing *during* a walk is caught at the
// walk's start rather than at each slot. Producing that requires an attacker
// able to alter secure flash while this call runs, who could equally strike
// between the MAC pass and the slot read in the per-slot version.
auth_replica_store_result auth_replica_walk_slots(
    auth_replica_store *store, const uint8_t root[32],
    auth_replica_slot_visitor visitor, void *context);

// Creates generation 1 on blank media. `root` is the new root secret whose
// MAC key protects the snapshot; `envelope` is its wrapped form.
auth_replica_store_result auth_replica_provision(
    auth_replica_store *store, const uint8_t root[32],
    const uint8_t envelope[AUTH_REPLICA_ROOT_LENGTH],
    const uint8_t nonce[AUTH_REPLICA_NONCE_SIZE]);

// Replaces the stored root envelope, keeping every slot. The MAC key is
// derived from `root`, so this is only valid when the root secret itself is
// unchanged.
auth_replica_store_result auth_replica_commit_root(
    auth_replica_store *store, const uint8_t root[32],
    const uint8_t envelope[AUTH_REPLICA_ROOT_LENGTH],
    const uint8_t nonce[AUTH_REPLICA_NONCE_SIZE]);

// Writes/replaces one resident slot.
auth_replica_store_result auth_replica_commit_slot(
    auth_replica_store *store, const uint8_t root[32], uint8_t index,
    const uint8_t *record, uint16_t record_len,
    const uint8_t nonce[AUTH_REPLICA_NONCE_SIZE]);

// Clears one resident slot.
auth_replica_store_result auth_replica_delete_slot(
    auth_replica_store *store, const uint8_t root[32], uint8_t index,
    const uint8_t nonce[AUTH_REPLICA_NONCE_SIZE]);

// Rebuilds one stale/invalid replica from the selected authenticated
// snapshot, at the same generation, using the same write-then-verify
// protocol. Returns OK when nothing needs repair.
//
// Takes no nonce on purpose: a repaired replica must be a byte-for-byte
// duplicate of its source, so it inherits the source's nonce. A fresh nonce
// would produce a *different* authenticated snapshot at the same generation,
// which the selector is required to treat as a divergent tie and refuse.
auth_replica_store_result auth_replica_repair_one(auth_replica_store *store,
                                                  const uint8_t root[32]);

// Erases all three replicas. Intended to run only after the caller has
// already destroyed the root in the secure element, so that a replica
// surviving a power cut is cryptographically useless.
auth_replica_store_result auth_replica_wipe(auth_replica_store *store);
