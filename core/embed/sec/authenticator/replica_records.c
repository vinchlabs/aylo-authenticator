// Record/result translation between the replica manager and the vault.
//
// See replica_records.h for why this is its own translation unit. In short: the
// manager reports several conditions that all look like "no usable snapshot",
// and exactly one of them authorises provisioning. Keeping that mapping in one
// testable place is worth more than the indirection costs.

#include "replica_records.h"

#include <string.h>

#include "chacha20poly1305/rfc7539.h"
#include "consteq.h"
#include "memzero.h"
#include "replica_store.h"

static struct {
  auth_replica_store store;
  // Result of the last classification. Provisioning is permitted only when this
  // says the media really is blank.
  auth_result opened;
  bool ready;
} g_records;

// Translates a manager result into the vault's vocabulary.
//
// The two entries that carry the weight are BLANK and NO_SOURCE. BLANK means
// every area is erased, so there is nothing to lose. NO_SOURCE means replicas
// are present but none authenticated under the root we were given -- a wrong
// PIN, or damage. Both are "no snapshot selected", and only the first may ever
// lead to a reformat, so NO_SOURCE deliberately does not map to
// AUTH_UNPROVISIONED.
static auth_result translate(auth_replica_store_result result) {
  switch (result) {
    case AUTH_REPLICA_STORE_OK:
      return AUTH_OK;
    case AUTH_REPLICA_STORE_BLANK:
      return AUTH_UNPROVISIONED;
    case AUTH_REPLICA_STORE_ABSENT:
      // A canonically empty slot. The vault treats this as an expected
      // enumeration result, same as it always has.
      return AUTH_UNPROVISIONED;
    case AUTH_REPLICA_STORE_MIGRATION:
      return AUTH_MIGRATION_REQUIRED;
    case AUTH_REPLICA_STORE_LIMIT:
      return AUTH_LIMIT_EXCEEDED;
    case AUTH_REPLICA_STORE_INVALID:
      return AUTH_INVALID_ARGUMENT;
    case AUTH_REPLICA_STORE_NO_SOURCE:
    case AUTH_REPLICA_STORE_INTEGRITY:
    case AUTH_REPLICA_STORE_IO:
    default:
      return AUTH_ERROR;
  }
}

bool auth_records_ready(void) { return g_records.ready; }

void auth_records_close(void) {
  memzero(&g_records, sizeof(g_records));
  g_records.opened = AUTH_ERROR;
}

auth_result auth_records_open(const auth_replica_io *io) {
  if (io == NULL || io->read == NULL || io->write_line == NULL ||
      io->erase_page == NULL) {
    auth_records_close();
    return AUTH_INVALID_ARGUMENT;
  }
  memzero(&g_records, sizeof(g_records));
  auth_replica_store_result probed = auth_replica_probe(&g_records.store, io);

  auth_result result;
  if (probed == AUTH_REPLICA_STORE_NO_SOURCE) {
    // From probe(), NO_SOURCE means "these are our areas and none of them holds
    // a snapshot". Two very different situations produce it:
    //
    //   * a wiped device, or one torn mid-provisioning. Our claim marker is
    //     there, the header is not. Provisioning must be allowed, otherwise a
    //     wipe would brick the device.
    //   * every area unreadable. On an ordinary hardware image the checked
    //     reader refuses every load, so this is also what a perfectly good
    //     vault looks like when we cannot see it. Provisioning here would
    //     destroy it.
    //
    // The per-replica classification is what separates them, so the decision is
    // made from that rather than from the returned code.
    bool unreadable = false;
    for (uint8_t replica = 0; replica < AUTH_REPLICA_COUNT; replica++) {
      if (g_records.store.state[replica] == AUTH_REPLICA_STATE_UNREADABLE) {
        unreadable = true;
      }
    }
    result = unreadable ? AUTH_ERROR : AUTH_UNPROVISIONED;
  } else {
    result = translate(probed);
  }

  // Classified is classified: migration and IO failure are still states the
  // caller may query, but nothing here may mutate in them, which is enforced by
  // `opened` below rather than by refusing to be open at all.
  g_records.ready = true;
  g_records.opened = result;
  return result;
}

auth_result auth_records_root_candidates(
    uint8_t out[AUTH_REPLICA_COUNT][AUTH_REPLICA_ROOT_LENGTH], uint8_t *count) {
  if (out == NULL || count == NULL) return AUTH_INVALID_ARGUMENT;
  *count = 0;
  memzero(out, (size_t)AUTH_REPLICA_COUNT * AUTH_REPLICA_ROOT_LENGTH);
  if (!g_records.ready) return AUTH_ERROR;
  if (g_records.opened != AUTH_OK && g_records.opened != AUTH_UNPROVISIONED) {
    return g_records.opened;
  }
  // The manager reports NO_SOURCE for an empty candidate list regardless of
  // *why* it is empty, which is correct at its level but ambiguous at this one:
  // blank media and media we could not read both produce it. The count, plus
  // the classification from open(), are the unambiguous signals, so the
  // decision is made from those rather than from the returned code.
  auth_replica_store_result reported =
      auth_replica_root_candidates(&g_records.store, out, count);
  if (reported == AUTH_REPLICA_STORE_INVALID) {
    *count = 0;
    return AUTH_INVALID_ARGUMENT;
  }
  if (*count == 0) {
    memzero(out, (size_t)AUTH_REPLICA_COUNT * AUTH_REPLICA_ROOT_LENGTH);
    // Only genuinely blank media may answer "unprovisioned" here. Anything
    // else with no candidates is a vault we failed to read, and saying
    // "unprovisioned" about it would invite a reformat.
    return g_records.opened == AUTH_UNPROVISIONED ? AUTH_UNPROVISIONED
                                                  : AUTH_ERROR;
  }
  return AUTH_OK;
}

auth_result auth_records_authenticate(const uint8_t root[32]) {
  if (root == NULL) return AUTH_INVALID_ARGUMENT;
  if (!g_records.ready) return AUTH_ERROR;
  if (g_records.opened != AUTH_OK) return g_records.opened;
  return translate(auth_replica_authenticate(&g_records.store, root));
}

auth_result auth_records_provision(
    const uint8_t root[32], const uint8_t envelope[AUTH_REPLICA_ROOT_LENGTH],
    const uint8_t nonce[AUTH_REPLICA_NONCE_SIZE]) {
  if (root == NULL || envelope == NULL || nonce == NULL) {
    return AUTH_INVALID_ARGUMENT;
  }
  if (!g_records.ready) return AUTH_ERROR;
  // The gate that matters: only genuinely blank media may be provisioned. The
  // manager refuses non-blank media too, but this check makes the rule visible
  // at the layer that owns the decision rather than relying on a callee.
  if (g_records.opened != AUTH_UNPROVISIONED) {
    return g_records.opened == AUTH_OK ? AUTH_DENIED : g_records.opened;
  }
  auth_result result = translate(
      auth_replica_provision(&g_records.store, root, envelope, nonce));
  if (result == AUTH_OK) {
    // No longer blank, so a second provisioning attempt is refused here too.
    g_records.opened = AUTH_OK;
  }
  return result;
}

auth_result auth_records_read_root(const uint8_t root[32],
                                   uint8_t out[AUTH_REPLICA_ROOT_LENGTH]) {
  if (root == NULL || out == NULL) return AUTH_INVALID_ARGUMENT;
  memzero(out, AUTH_REPLICA_ROOT_LENGTH);
  if (!g_records.ready) return AUTH_ERROR;
  if (g_records.opened != AUTH_OK) return g_records.opened;
  auth_result result =
      translate(auth_replica_read_root(&g_records.store, root, out));
  if (result != AUTH_OK) memzero(out, AUTH_REPLICA_ROOT_LENGTH);
  return result;
}

auth_result auth_records_commit_root(
    const uint8_t root[32], const uint8_t envelope[AUTH_REPLICA_ROOT_LENGTH],
    const uint8_t nonce[AUTH_REPLICA_NONCE_SIZE]) {
  if (root == NULL || envelope == NULL || nonce == NULL) {
    return AUTH_INVALID_ARGUMENT;
  }
  if (!g_records.ready) return AUTH_ERROR;
  if (g_records.opened != AUTH_OK) return g_records.opened;
  return translate(
      auth_replica_commit_root(&g_records.store, root, envelope, nonce));
}

auth_result auth_records_read(const uint8_t root[32], uint8_t index,
                              uint8_t *out, uint16_t capacity,
                              uint16_t *length) {
  if (length != NULL) *length = 0;
  if (root == NULL || out == NULL || length == NULL) {
    return AUTH_INVALID_ARGUMENT;
  }
  if (capacity > 0) memzero(out, capacity);
  if (index >= AUTH_REPLICA_SLOT_COUNT) return AUTH_INVALID_ARGUMENT;
  if (!g_records.ready) return AUTH_ERROR;
  if (g_records.opened != AUTH_OK) return g_records.opened;

  // The slot buffer is a local so no decoded record outlives this call.
  auth_replica_slot_t slot;
  memzero(&slot, sizeof(slot));
  auth_result result =
      translate(auth_replica_read_slot(&g_records.store, root, index, &slot));
  if (result == AUTH_OK) {
    if (slot.record_len == 0 || slot.record_len > capacity) {
      // Too small a destination is a failure, never a truncated record.
      result = slot.record_len == 0 ? AUTH_ERROR : AUTH_LIMIT_EXCEEDED;
    } else {
      memcpy(out, slot.record, slot.record_len);
      *length = slot.record_len;
    }
  }
  memzero(&slot, sizeof(slot));
  // No second clearing of `out` here: it was cleared before the read, the
  // length check happens before any copy, so a partial record can never exist.
  if (result != AUTH_OK) *length = 0;
  return result;
}

// Adapts one replica-layer visit into the vault's vocabulary. A record longer
// than a record may be is a failure rather than something to pass on, the same
// judgement auth_records_read makes about a destination that is too small.
typedef struct {
  auth_slot_visitor visitor;
  void *context;
} records_walk_t;

static bool records_walk_step(void *context, uint8_t index,
                              auth_replica_store_result status,
                              const auth_replica_slot_t *slot) {
  records_walk_t *walk = (records_walk_t *)context;
  auth_result translated = translate(status);
  const uint8_t *record = NULL;
  uint16_t length = 0;
  if (translated == AUTH_OK) {
    if (slot->record_len == 0 || slot->record_len > AUTH_RECORD_MAX) {
      translated = slot->record_len == 0 ? AUTH_ERROR : AUTH_LIMIT_EXCEEDED;
    } else {
      record = slot->record;
      length = slot->record_len;
    }
  }
  return walk->visitor(walk->context, index, translated, record, length);
}

auth_result auth_records_walk(const uint8_t root[32], auth_slot_visitor visitor,
                              void *context) {
  if (root == NULL || visitor == NULL) return AUTH_INVALID_ARGUMENT;
  if (!g_records.ready) return AUTH_ERROR;
  if (g_records.opened != AUTH_OK) return g_records.opened;
  records_walk_t walk = {visitor, context};
  return translate(auth_replica_walk_slots(&g_records.store, root,
                                           records_walk_step, &walk));
}

auth_result auth_records_capacity(uint8_t index, uint16_t length) {
  if (index >= AUTH_REPLICA_SLOT_COUNT) return AUTH_INVALID_ARGUMENT;
  if (length == 0) return AUTH_INVALID_ARGUMENT;
  // Every slot has the same fixed capacity, so this is a bound check rather
  // than a free-space query: no record can ever be displaced by another.
  if (length > AUTH_RECORD_MAX) return AUTH_LIMIT_EXCEEDED;
  return AUTH_OK;
}

auth_result auth_records_write(const uint8_t root[32], uint8_t index,
                               const uint8_t *record, uint16_t length,
                               const uint8_t nonce[AUTH_REPLICA_NONCE_SIZE]) {
  if (root == NULL || record == NULL || nonce == NULL) {
    return AUTH_INVALID_ARGUMENT;
  }
  auth_result bounded = auth_records_capacity(index, length);
  if (bounded != AUTH_OK) return bounded;
  if (!g_records.ready) return AUTH_ERROR;
  if (g_records.opened != AUTH_OK) return g_records.opened;
  return translate(auth_replica_commit_slot(&g_records.store, root, index,
                                            record, length, nonce));
}

auth_result auth_records_delete(const uint8_t root[32], uint8_t index,
                                const uint8_t nonce[AUTH_REPLICA_NONCE_SIZE]) {
  if (root == NULL || nonce == NULL) return AUTH_INVALID_ARGUMENT;
  if (index >= AUTH_REPLICA_SLOT_COUNT) return AUTH_INVALID_ARGUMENT;
  if (!g_records.ready) return AUTH_ERROR;
  if (g_records.opened != AUTH_OK) return g_records.opened;
  return translate(
      auth_replica_delete_slot(&g_records.store, root, index, nonce));
}

auth_result auth_records_repair(const uint8_t root[32]) {
  if (root == NULL) return AUTH_INVALID_ARGUMENT;
  if (!g_records.ready) return AUTH_ERROR;
  if (g_records.opened != AUTH_OK) return g_records.opened;
  // The manager repairs at most one replica per call and reports OK when there
  // is nothing left to do, so a bounded sweep converges without needing to ask
  // how many are stale.
  for (unsigned attempt = 0; attempt < AUTH_REPLICA_COUNT; attempt++) {
    auth_result result =
        translate(auth_replica_repair_one(&g_records.store, root));
    if (result != AUTH_OK) return result;
  }
  return AUTH_OK;
}

auth_result auth_records_wipe(void) {
  if (!g_records.ready) return AUTH_ERROR;
  // A wipe is allowed from any classified state except one we could not read at
  // all: erasing blind could destroy a wallet the checked reader simply refused
  // to show us. Migration is likewise left alone.
  if (g_records.opened != AUTH_OK && g_records.opened != AUTH_UNPROVISIONED) {
    return g_records.opened;
  }
  auth_result result = translate(auth_replica_wipe(&g_records.store));
  if (result == AUTH_OK) g_records.opened = AUTH_UNPROVISIONED;
  return result;
}

// ---------------------------------------------------------------------------
// Root-envelope unlock
// ---------------------------------------------------------------------------

_Static_assert(AUTH_ENVELOPE_AAD_SIZE + AUTH_ENVELOPE_NONCE_SIZE +
                       AUTH_ENVELOPE_SECRET_SIZE + AUTH_ENVELOPE_MAC_SIZE ==
                   AUTH_REPLICA_ROOT_LENGTH,
               "root envelope layout does not fill the stored record");

bool auth_envelope_open(const uint8_t kek[32],
                        const uint8_t envelope[AUTH_REPLICA_ROOT_LENGTH],
                        uint8_t root_out[AUTH_ENVELOPE_SECRET_SIZE]) {
  // Checked before the memzero below, which is itself a dereference. The only
  // caller validates all three already, but this is a declared entry point.
  if (kek == NULL || envelope == NULL || root_out == NULL) return false;
  memzero(root_out, AUTH_ENVELOPE_SECRET_SIZE);
  if (envelope[0] != AUTH_ENVELOPE_TAG ||
      envelope[1] != AUTH_ENVELOPE_VERSION) {
    return false;
  }

  chacha20poly1305_ctx aead;
  uint8_t mac[AUTH_ENVELOPE_MAC_SIZE];
  rfc7539_init(&aead, kek, envelope + AUTH_ENVELOPE_AAD_SIZE);
  rfc7539_auth(&aead, envelope, AUTH_ENVELOPE_AAD_SIZE);
  chacha20poly1305_decrypt(
      &aead, envelope + AUTH_ENVELOPE_AAD_SIZE + AUTH_ENVELOPE_NONCE_SIZE,
      root_out, AUTH_ENVELOPE_SECRET_SIZE);
  rfc7539_finish(&aead, AUTH_ENVELOPE_AAD_SIZE, AUTH_ENVELOPE_SECRET_SIZE, mac);
  bool authentic =
      consteq(mac,
              envelope + AUTH_ENVELOPE_AAD_SIZE + AUTH_ENVELOPE_NONCE_SIZE +
                  AUTH_ENVELOPE_SECRET_SIZE,
              AUTH_ENVELOPE_MAC_SIZE);

  memzero(&aead, sizeof(aead));
  memzero(mac, sizeof(mac));
  // The decrypt writes plaintext before the tag is checked, so a rejected
  // envelope leaves unauthenticated bytes behind. Clearing them here is decrypt
  // hygiene rather than a property callers can observe: the caller re-clears on
  // the next attempt and zeroizes after the loop either way.
  if (!authentic) memzero(root_out, AUTH_ENVELOPE_SECRET_SIZE);
  return authentic;
}

auth_result auth_records_unlock(
    const uint8_t kek[32],
    const uint8_t candidates[AUTH_REPLICA_COUNT][AUTH_REPLICA_ROOT_LENGTH],
    uint8_t count, uint8_t root_out[32]) {
  if (root_out != NULL) memzero(root_out, 32);
  if (kek == NULL || candidates == NULL || root_out == NULL) {
    return AUTH_INVALID_ARGUMENT;
  }
  if (count > AUTH_REPLICA_COUNT) return AUTH_INVALID_ARGUMENT;
  if (count == 0) return AUTH_UNPROVISIONED;
  if (!g_records.ready) return AUTH_ERROR;
  if (g_records.opened != AUTH_OK) return g_records.opened;

  uint8_t recovered[AUTH_ENVELOPE_SECRET_SIZE];
  uint8_t agreed[AUTH_ENVELOPE_SECRET_SIZE];
  memzero(recovered, sizeof(recovered));
  memzero(agreed, sizeof(agreed));
  bool have_agreed = false;
  bool inconsistent = false;

  for (uint8_t candidate = 0; candidate < count; candidate++) {
    if (!auth_envelope_open(kek, candidates[candidate], recovered)) {
      // A candidate that does not open is not evidence of anything: a torn root
      // commit can leave an envelope from a different KEK behind. Keep looking.
      continue;
    }
    if (!have_agreed) {
      memcpy(agreed, recovered, sizeof(agreed));
      have_agreed = true;
    } else if (!consteq(agreed, recovered, sizeof(agreed))) {
      // Two envelopes opened under the same KEK but disagree about the secret.
      // Each wrap only re-randomises the nonce, so this cannot happen to a
      // healthy vault; refuse rather than choose.
      inconsistent = true;
      break;
    }
  }
  memzero(recovered, sizeof(recovered));

  auth_result result;
  if (inconsistent) {
    result = AUTH_ERROR;
  } else if (!have_agreed) {
    // Nothing opened, and that is damage rather than a retry. The secure
    // element has already verified the PIN by the time this KEK exists -- a
    // wrong PIN never gets this far, it fails at optiga_pin_verify. So a KEK
    // that opens no envelope means the stored envelopes no longer match the
    // secret that sealed them, which is a broken device, not a wrong guess.
    result = AUTH_ERROR;
  } else {
    // The envelope opening is not proof that this root owns the stored
    // snapshots; only the snapshot MAC is. Authenticate before handing it back.
    result = auth_records_authenticate(agreed);
    if (result == AUTH_OK) memcpy(root_out, agreed, 32);
  }

  memzero(agreed, sizeof(agreed));
  // No second clearing of root_out: it is cleared on entry and written only on
  // the success path, so every failure already returns it zeroized.
  return result;
}

// ---------------------------------------------------------------------------
// Resident record shape
// ---------------------------------------------------------------------------

#define RECORD_INDEX_OFFSET 2
#define RECORD_RESERVED_OFFSET 3
#define RECORD_GENERATION_OFFSET 4
#define RECORD_RP_OFFSET 8
#define RECORD_RP_SIZE 32

_Static_assert(RECORD_RP_OFFSET + RECORD_RP_SIZE == AUTH_RECORD_HEADER_SIZE,
               "record header must end where the credential id begins");
_Static_assert(AUTH_RECORD_MIN_SIZE > AUTH_RECORD_HEADER_SIZE,
               "the minimum record must contain at least some id bytes");

auth_result auth_record_encode(uint8_t index, uint32_t generation,
                               const uint8_t rp[32], const uint8_t *id,
                               uint16_t id_len, uint8_t *out, uint16_t capacity,
                               uint16_t *length) {
  if (length != NULL) *length = 0;
  if (rp == NULL || id == NULL || out == NULL || length == NULL) {
    return AUTH_INVALID_ARGUMENT;
  }
  if (index >= AUTH_REPLICA_SLOT_COUNT) return AUTH_INVALID_ARGUMENT;
  if (id_len == 0) return AUTH_INVALID_ARGUMENT;

  uint32_t total = (uint32_t)AUTH_RECORD_HEADER_SIZE + id_len;
  // A record shorter than the historical minimum would be rejected on read, so
  // refuse to create one rather than storing something unreadable.
  if (total < AUTH_RECORD_MIN_SIZE) return AUTH_INVALID_ARGUMENT;
  if (total > AUTH_RECORD_MAX) return AUTH_LIMIT_EXCEEDED;
  if (total > capacity) return AUTH_LIMIT_EXCEEDED;

  memzero(out, capacity);
  out[0] = AUTH_RECORD_TAG;
  out[1] = AUTH_RECORD_VERSION;
  out[RECORD_INDEX_OFFSET] = index;
  out[RECORD_RESERVED_OFFSET] = 0;
  for (unsigned byte = 0; byte < 4; byte++) {
    out[RECORD_GENERATION_OFFSET + byte] =
        (uint8_t)(generation >> (24 - 8 * byte));
  }
  memcpy(out + RECORD_RP_OFFSET, rp, RECORD_RP_SIZE);
  memcpy(out + AUTH_RECORD_HEADER_SIZE, id, id_len);
  *length = (uint16_t)total;
  return AUTH_OK;
}

auth_result auth_record_decode(const uint8_t *record, uint16_t length,
                               uint8_t index, auth_record_view *out) {
  if (out != NULL) memzero(out, sizeof(*out));
  if (record == NULL || out == NULL) return AUTH_INVALID_ARGUMENT;
  if (index >= AUTH_REPLICA_SLOT_COUNT) return AUTH_INVALID_ARGUMENT;

  if (length < AUTH_RECORD_MIN_SIZE || length > AUTH_RECORD_MAX) {
    return AUTH_ERROR;
  }
  if (record[0] != AUTH_RECORD_TAG || record[1] != AUTH_RECORD_VERSION) {
    return AUTH_ERROR;
  }
  if (record[RECORD_RESERVED_OFFSET] != 0) return AUTH_ERROR;
  // The record names its own slot. Disagreement means it is not the record that
  // belongs here, so it must not answer for this slot.
  if (record[RECORD_INDEX_OFFSET] != index) return AUTH_ERROR;

  uint32_t generation = 0;
  for (unsigned byte = 0; byte < 4; byte++) {
    generation = (generation << 8) | record[RECORD_GENERATION_OFFSET + byte];
  }

  out->index = index;
  out->generation = generation;
  out->rp = record + RECORD_RP_OFFSET;
  out->id = record + AUTH_RECORD_HEADER_SIZE;
  out->id_len = (uint16_t)(length - AUTH_RECORD_HEADER_SIZE);
  return AUTH_OK;
}

auth_result auth_record_next_generation(uint32_t current, uint32_t *next) {
  if (next == NULL) return AUTH_INVALID_ARGUMENT;
  *next = 0;
  // Wrapping would let a replaced record claim an older generation than the one
  // it replaced, so the ceiling is a refusal rather than a rollover.
  if (current == UINT32_MAX) return AUTH_ERROR;
  *next = current + 1;
  return AUTH_OK;
}
