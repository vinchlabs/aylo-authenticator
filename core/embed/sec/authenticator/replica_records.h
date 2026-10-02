#pragma once
// Translates the replica manager's snapshot model into the vault's record and
// result vocabulary.
//
// The manager (replica_store.h) deals in snapshots, generations and slots. The
// vault (authenticator.c) deals in a root envelope, 100 resident records, and
// `auth_result`. This layer is the only place those two vocabularies meet, and
// it exists as its own translation unit for one reason: the mapping contains a
// decision that is easy to get wrong and expensive to get wrong, so it is worth
// testing on the host rather than only on a board.
//
// That decision is the difference between "no vault here" and "a vault I cannot
// open":
//
//   * BLANK means every area is erased. Provisioning may proceed.
//   * NO_SOURCE means replicas exist but none authenticated under the supplied
//     root -- a wrong PIN-derived root, or damage. Provisioning must NOT
//     proceed, because it would erase a real vault.
//
// Collapsing the second into AUTH_UNPROVISIONED would turn a recoverable
// "wrong PIN" into silent credential destruction, so they map to different
// results and the host tests pin that apart.
//
// This layer is platform independent. It reaches flash only through the
// caller-supplied auth_replica_io table, which is what lets the T3T1 binding
// (stm32u5/authenticator_replica_io.c) stay the single place that knows a
// replica has an address.
//
// It holds no secrets: the root is passed per call and never copied here, and
// the snapshot nonce is supplied by the caller so this module stays
// deterministic.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <sec/authenticator.h>

#include "authenticator_replica_io.h"
#include "replica_format.h"

// Resident record header: tag, version, index, reserved, generation[4], rp[32].
// The credential id follows. This is the existing on-device record shape and is
// deliberately unchanged by the move to replicas.
#define AUTH_RECORD_HEADER_SIZE 40
// Largest record the wire format can carry; see the slot capacity derivation in
// replica_format.h.
#define AUTH_RECORD_MAX AUTH_REPLICA_SLOT_RECORD_MAX

// Classifies the three areas. Performs no writes. Must be called before any
// other entry point here; every one of them fails closed if it was not.
//
// Returns AUTH_OK when at least one structural candidate exists,
// AUTH_UNPROVISIONED when every area is erased, AUTH_MIGRATION_REQUIRED when an
// area holds data that is not ours, and AUTH_ERROR on an IO failure -- which
// includes an ordinary hardware image, where the checked reader refuses every
// load until the ECCD probe is validated.
auth_result auth_records_open(const auth_replica_io *io);

// True once auth_records_open() has classified the areas.
bool auth_records_ready(void);

// Forgets the classification. The next call must open() again.
void auth_records_close(void);

// Copies up to AUTH_REPLICA_COUNT deduplicated root envelopes. These are
// ciphertext envelopes, not roots. Returns AUTH_UNPROVISIONED when there are
// none.
auth_result auth_records_root_candidates(
    uint8_t out[AUTH_REPLICA_COUNT][AUTH_REPLICA_ROOT_LENGTH], uint8_t *count);

// Authenticates the stored snapshots under `root` and selects the newest one.
// AUTH_OK means a snapshot is selected and records may be read.
auth_result auth_records_authenticate(const uint8_t root[32]);

// Creates generation 1 on blank media. Refuses unless open() reported
// AUTH_UNPROVISIONED, so it can never overwrite a vault that merely failed to
// authenticate.
auth_result auth_records_provision(
    const uint8_t root[32], const uint8_t envelope[AUTH_REPLICA_ROOT_LENGTH],
    const uint8_t nonce[AUTH_REPLICA_NONCE_SIZE]);

// Reads the selected snapshot's root envelope.
auth_result auth_records_read_root(const uint8_t root[32],
                                   uint8_t out[AUTH_REPLICA_ROOT_LENGTH]);

// Replaces the stored root envelope, keeping every record. The snapshot MAC key
// comes from `root`, so this is only valid when the root secret itself is
// unchanged -- re-wrapping it under a new KEK, not rekeying the vault.
auth_result auth_records_commit_root(
    const uint8_t root[32], const uint8_t envelope[AUTH_REPLICA_ROOT_LENGTH],
    const uint8_t nonce[AUTH_REPLICA_NONCE_SIZE]);

// Reads one resident record. Returns AUTH_UNPROVISIONED for an empty slot,
// which is an expected enumeration result rather than a failure.
auth_result auth_records_read(const uint8_t root[32], uint8_t index,
                              uint8_t *out, uint16_t capacity,
                              uint16_t *length);

// Writes or replaces one resident record as a whole new authenticated snapshot.
auth_result auth_records_write(const uint8_t root[32], uint8_t index,
                               const uint8_t *record, uint16_t length,
                               const uint8_t nonce[AUTH_REPLICA_NONCE_SIZE]);

// Clears one resident record.
auth_result auth_records_delete(const uint8_t root[32], uint8_t index,
                                const uint8_t nonce[AUTH_REPLICA_NONCE_SIZE]);

// Rebuilds any stale or unreadable replica from the selected snapshot. Returns
// AUTH_OK when nothing needed repair.
auth_result auth_records_repair(const uint8_t root[32]);

// Whether a record of `length` bytes fits slot `index`. The replica format is
// fixed-capacity, so this is a bound check rather than a free-space query.
auth_result auth_records_capacity(uint8_t index, uint16_t length);

// Erases all three replicas. Intended to run only after the caller has already
// destroyed the root in the secure element, so that a replica surviving a power
// cut is cryptographically useless.
auth_result auth_records_wipe(void);

// ---------------------------------------------------------------------------
// Resident record shape
// ---------------------------------------------------------------------------
//
// One resident credential, exactly as the device has always stored it:
//
//   [0]      0xa2 tag
//   [1]      version 1
//   [2]      slot index, which must equal the slot it is stored in
//   [3]      reserved, zero
//   [4..7]   per-slot generation, big endian
//   [8..39]  relying-party hash
//   [40..]   credential id
//
// The shape is unchanged by the move to replicas, so the Python credential
// format is unaffected. What *is* gone is the separate 40-byte commit record
// the NORCOW layout needed beside each of these: it existed to authenticate the
// data record and to mark it committed, and the snapshot MAC now does both for
// the whole vault at once.
//
// The index byte is kept even though the slot position already implies it. It
// is what makes a record self-describing, so a record that somehow ends up in
// the wrong slot is detected instead of silently answering for its neighbour.
#define AUTH_RECORD_TAG 0xa2
#define AUTH_RECORD_VERSION 1
// The smallest record the previous layout ever accepted, preserved so that a
// truncated or hand-made record cannot pass as a credential.
#define AUTH_RECORD_MIN_SIZE 118

// Borrowed view of a decoded record. The pointers address the caller's buffer;
// nothing is copied, and the view is only valid while that buffer lives.
typedef struct {
  uint8_t index;
  uint32_t generation;
  const uint8_t *rp;
  const uint8_t *id;
  uint16_t id_len;
} auth_record_view;

// Builds a record for `index`. Fails with AUTH_INVALID_ARGUMENT on a bad index
// or null argument, and AUTH_LIMIT_EXCEEDED when the id does not fit a slot or
// the destination is too small.
auth_result auth_record_encode(uint8_t index, uint32_t generation,
                               const uint8_t rp[32], const uint8_t *id,
                               uint16_t id_len, uint8_t *out, uint16_t capacity,
                               uint16_t *length);

// Validates a stored record and describes it. `index` is the slot it was read
// from; a record whose own index byte disagrees is rejected rather than
// trusted.
auth_result auth_record_decode(const uint8_t *record, uint16_t length,
                               uint8_t index, auth_record_view *out);

// Advances a per-slot generation, refusing to wrap. Replacing a record must
// never reuse or lower its generation.
auth_result auth_record_next_generation(uint32_t current, uint32_t *next);

// Presents every slot's record to `visitor` in the vault's vocabulary, with the
// snapshot authenticated once for the whole walk. See auth_replica_walk_slots
// in replica_store.h for why once per walk is the honest granularity.
auth_result auth_records_walk(const uint8_t root[32], auth_slot_visitor visitor,
                              void *context);

// ---------------------------------------------------------------------------
// Root-envelope unlock
// ---------------------------------------------------------------------------

// Root envelope layout, as the vault has always written it:
//   [0]     0xa1 tag
//   [1]     version 1
//   [2..13] 12-byte AEAD nonce
//   [14..45] 32-byte ciphertext (the root secret)
//   [46..61] 16-byte tag
// The first two bytes are the AEAD's additional data.
#define AUTH_ENVELOPE_TAG 0xa1
#define AUTH_ENVELOPE_VERSION 1
#define AUTH_ENVELOPE_AAD_SIZE 2
#define AUTH_ENVELOPE_NONCE_SIZE 12
#define AUTH_ENVELOPE_SECRET_SIZE 32
#define AUTH_ENVELOPE_MAC_SIZE 16

// Recovers the root from the candidate envelopes and selects a snapshot.
//
// Why this is not simply "unwrap the envelope": a power cut during a root
// commit can leave replicas carrying *different* envelopes. They are different
// because each wrap uses a fresh nonce, not because the secret differs, so
// every envelope that opens under the same KEK must yield the same root. This
// function therefore requires a consistent answer rather than trusting the
// first success:
//
//   * every candidate that authenticates under `kek` must produce an identical
//     root -- two distinct roots both opening means the vault is inconsistent,
//     and it fails closed rather than picking one;
//   * that root must then authenticate a stored snapshot, so an envelope that
//     decrypts but belongs to no snapshot is rejected;
//   * candidates that fail, and every intermediate, are zeroized.
//
// On success `root_out` holds the root and the manager has a snapshot selected.
// On any failure `root_out` is zeroized. Returns AUTH_UNPROVISIONED when there
// are no candidates and AUTH_ERROR otherwise -- including when nothing opens.
//
// "Nothing opened" is deliberately not a PIN retry. The secure element verifies
// the PIN before this KEK is derived, so a wrong PIN fails earlier and never
// reaches here; a KEK that opens nothing means the stored envelopes no longer
// match the secret that sealed them, which is damage.
auth_result auth_records_unlock(
    const uint8_t kek[32],
    const uint8_t candidates[AUTH_REPLICA_COUNT][AUTH_REPLICA_ROOT_LENGTH],
    uint8_t count, uint8_t root_out[32]);

// Opens a single envelope under `kek`, returning false without disclosing
// anything on a bad tag, a bad version, or a failed AEAD check.
//
// Exposed so that a backend without the replica manager -- the emulator double
// -- can recover a root without carrying a second copy of the envelope layout
// and the AEAD around it.
bool auth_envelope_open(const uint8_t kek[32],
                        const uint8_t envelope[AUTH_REPLICA_ROOT_LENGTH],
                        uint8_t root_out[AUTH_ENVELOPE_SECRET_SIZE]);
