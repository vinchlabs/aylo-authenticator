#include "replica_store.h"

#include <string.h>

#include "hmac.h"
#include "memzero.h"
#include "sha2.h"

// ---------------------------------------------------------------------------
// Fixed region offsets inside one replica.
// ---------------------------------------------------------------------------

#define ROOT_REGION_OFFSET AUTH_REPLICA_HEADER_SIZE  // 160
#define SLOT_REGION_OFFSET \
  (ROOT_REGION_OFFSET + AUTH_REPLICA_ROOT_REGION_SIZE)  // 224
#define SLOT_OFFSET(index) \
  (SLOT_REGION_OFFSET + (uint32_t)(index) * AUTH_REPLICA_SLOT_SIZE)

_Static_assert(SLOT_OFFSET(AUTH_REPLICA_SLOT_COUNT) == AUTH_REPLICA_USED_SIZE,
               "region offsets must exactly cover the used size");
_Static_assert(AUTH_REPLICA_HEADER_SIZE % AUTH_REPLICA_LINE_SIZE == 0,
               "header must be a whole number of program lines");
_Static_assert(AUTH_REPLICA_ROOT_REGION_SIZE % AUTH_REPLICA_LINE_SIZE == 0,
               "root region must be a whole number of program lines");
_Static_assert(AUTH_REPLICA_SLOT_SIZE % AUTH_REPLICA_LINE_SIZE == 0,
               "slot region must be a whole number of program lines");
_Static_assert(AUTH_REPLICA_AREA_SIZE % AUTH_REPLICA_PAGE_SIZE == 0,
               "area must be a whole number of erase pages");
_Static_assert(AUTH_REPLICA_CLAIM_OFFSET % AUTH_REPLICA_LINE_SIZE == 0,
               "the claim marker must start on a program-line boundary");
_Static_assert(AUTH_REPLICA_CLAIM_OFFSET + AUTH_REPLICA_LINE_SIZE <=
                   AUTH_REPLICA_AREA_SIZE,
               "the claim marker must fit inside the reserved headroom");
_Static_assert(AUTH_REPLICA_CLAIM_OFFSET >= AUTH_REPLICA_USED_SIZE,
               "the claim marker must never overlap authenticated bytes");

// ---------------------------------------------------------------------------
// Key derivation. Same single-block HKDF-SHA256 construction the vault
// already uses, with a distinct versioned label so the replica MAC key is
// domain separated from the credential/root-KEK keys.
// ---------------------------------------------------------------------------

static void derive_mac_key(const uint8_t root[32], uint8_t out[32]) {
  uint8_t salt[32] = {0}, prk[32] = {0};
  HMAC_SHA256_CTX ctx = {0};
  const uint8_t one = 1;
  hmac_sha256(salt, sizeof(salt), root, 32, prk);
  hmac_sha256_Init(&ctx, prk, sizeof(prk));
  hmac_sha256_Update(&ctx, (const uint8_t *)AUTH_REPLICA_MAC_LABEL,
                     (uint32_t)strlen(AUTH_REPLICA_MAC_LABEL));
  hmac_sha256_Update(&ctx, &one, 1);
  hmac_sha256_Final(&ctx, out);
  memzero(salt, sizeof(salt));
  memzero(prk, sizeof(prk));
  memzero(&ctx, sizeof(ctx));
}

// ---------------------------------------------------------------------------
// IO helpers
// ---------------------------------------------------------------------------

typedef enum { READ_OK, READ_DEGRADED, READ_FAILED } read_status;

static read_status read_at(const auth_replica_io *io, uint8_t replica,
                           uint32_t offset, uint8_t *out, uint32_t len) {
  switch (io->read(io->context, replica, offset, out, len)) {
    case AUTH_REPLICA_IO_OK:
      return READ_OK;
    case AUTH_REPLICA_IO_ECC_CORRECTED:
      return READ_DEGRADED;
    default:
      memzero(out, len);
      return READ_FAILED;
  }
}

static bool write_claim(const auth_replica_io *io, uint8_t replica) {
  uint8_t line[AUTH_REPLICA_LINE_SIZE] = {0};
  memcpy(line, AUTH_REPLICA_CLAIM_MAGIC, sizeof(AUTH_REPLICA_CLAIM_MAGIC) - 1);
  return io->write_line(io->context, replica, AUTH_REPLICA_CLAIM_OFFSET, line);
}

static bool has_claim(const auth_replica_io *io, uint8_t replica) {
  uint8_t line[AUTH_REPLICA_LINE_SIZE];
  if (read_at(io, replica, AUTH_REPLICA_CLAIM_OFFSET, line, sizeof(line)) ==
      READ_FAILED)
    return false;
  return memcmp(line, AUTH_REPLICA_CLAIM_MAGIC,
                sizeof(AUTH_REPLICA_CLAIM_MAGIC) - 1) == 0;
}

static bool area_is_erased(const auth_replica_io *io, uint8_t replica) {
  uint8_t region[AUTH_REPLICA_SLOT_SIZE];
  for (uint32_t offset = 0; offset < AUTH_REPLICA_AREA_SIZE;) {
    uint32_t chunk = AUTH_REPLICA_AREA_SIZE - offset;
    if (chunk > sizeof(region)) chunk = sizeof(region);
    if (read_at(io, replica, offset, region, chunk) == READ_FAILED)
      return false;
    for (uint32_t i = 0; i < chunk; i++) {
      if (region[i] != 0xff) return false;
    }
    offset += chunk;
  }
  return true;
}

// ---------------------------------------------------------------------------
// Authentication of one complete replica. Streams the body in 576-byte
// chunks so peak working memory stays far below one snapshot.
// ---------------------------------------------------------------------------

static bool authenticate_one(const auth_replica_io *io, uint8_t replica,
                             const uint8_t mac_key[32],
                             auth_replica_header_t *header_out,
                             bool *degraded) {
  uint8_t header_bytes[AUTH_REPLICA_HEADER_SIZE];
  read_status status =
      read_at(io, replica, 0, header_bytes, sizeof(header_bytes));
  if (status == READ_FAILED) return false;
  if (status == READ_DEGRADED && degraded) *degraded = true;
  if (auth_replica_header_decode(header_bytes, header_out) != AUTH_REPLICA_OK)
    return false;

  auth_replica_mac_ctx_t mac;
  auth_replica_mac_init(&mac, mac_key);
  auth_replica_mac_update(&mac, header_bytes, AUTH_REPLICA_HEADER_MAC_SIZE);

  SHA256_CTX sha;
  sha256_Init(&sha);

  uint8_t region[AUTH_REPLICA_SLOT_SIZE];
  bool failed = false;
  uint32_t offset = ROOT_REGION_OFFSET;
  uint32_t remaining = AUTH_REPLICA_BODY_SIZE;
  while (remaining && !failed) {
    uint32_t chunk = remaining < sizeof(region) ? remaining : sizeof(region);
    status = read_at(io, replica, offset, region, chunk);
    if (status == READ_FAILED) {
      failed = true;
      break;
    }
    if (status == READ_DEGRADED && degraded) *degraded = true;
    auth_replica_mac_update(&mac, region, chunk);
    sha256_Update(&sha, region, chunk);
    offset += chunk;
    remaining -= chunk;
  }

  uint8_t tag[32] = {0}, digest[32] = {0};
  auth_replica_mac_final(&mac, tag);
  sha256_Final(&sha, digest);

  bool authentic =
      !failed &&
      auth_replica_verify_tag(digest, header_out->body_digest) ==
          AUTH_REPLICA_OK &&
      auth_replica_verify_tag(tag, header_out->tag) == AUTH_REPLICA_OK;

  memzero(tag, sizeof(tag));
  memzero(digest, sizeof(digest));
  memzero(region, sizeof(region));
  if (!authentic) memzero(header_out, sizeof(*header_out));
  return authentic;
}

// ---------------------------------------------------------------------------
// Probe and selection
// ---------------------------------------------------------------------------

auth_replica_store_result auth_replica_probe(auth_replica_store *store,
                                             const auth_replica_io *io) {
  if (!store || !io || !io->read || !io->write_line || !io->erase_page)
    return AUTH_REPLICA_STORE_INVALID;
  memzero(store, sizeof(*store));
  store->io = io;
  store->selected = AUTH_REPLICA_NONE;

  bool any_structural = false, any_foreign = false, all_blank = true;
  for (uint8_t replica = 0; replica < AUTH_REPLICA_COUNT; replica++) {
    uint8_t header_bytes[AUTH_REPLICA_HEADER_SIZE];
    read_status status =
        read_at(io, replica, 0, header_bytes, sizeof(header_bytes));
    if (status == READ_FAILED) {
      store->state[replica] = AUTH_REPLICA_STATE_UNREADABLE;
      all_blank = false;
      continue;
    }
    auth_replica_header_t header;
    if (auth_replica_header_decode(header_bytes, &header) == AUTH_REPLICA_OK) {
      store->state[replica] = status == READ_DEGRADED
                                  ? AUTH_REPLICA_STATE_DEGRADED
                                  : AUTH_REPLICA_STATE_STRUCTURAL;
      store->claimed_generation[replica] = header.generation;
      any_structural = true;
      all_blank = false;
    } else if (has_claim(io, replica)) {
      // Our own scratch area, torn by a power cut before its header landed.
      store->state[replica] = AUTH_REPLICA_STATE_TORN;
      all_blank = false;
    } else if (area_is_erased(io, replica)) {
      store->state[replica] = AUTH_REPLICA_STATE_BLANK;
    } else {
      // Non-erased, not our format, and never claimed by us: legacy NORCOW,
      // foreign app data, or damage. Never implicitly erased or imported.
      store->state[replica] = AUTH_REPLICA_STATE_FOREIGN;
      any_foreign = true;
      all_blank = false;
    }
    memzero(&header, sizeof(header));
  }

  // Device-ownership rule. The conservative migration check exists to protect
  // a device that might still hold a wallet or another application's data. Once
  // any area carries a canonical replica header, this device demonstrably
  // belongs to the authenticator, so a sibling area full of indeterminate bytes
  // is our own scratch space -- for example a destination whose claim-page
  // erase was interrupted before the claim could be written. Treating it as
  // foreign would make a single mid-erase power cut permanently refuse the
  // device even though a perfectly good snapshot is sitting next to it.
  //
  // This never promotes data: a reclassified area is only ever eligible to be
  // erased and rewritten, and can never be selected as a snapshot.
  if (any_structural && any_foreign) {
    for (uint8_t replica = 0; replica < AUTH_REPLICA_COUNT; replica++) {
      if (store->state[replica] == AUTH_REPLICA_STATE_FOREIGN)
        store->state[replica] = AUTH_REPLICA_STATE_TORN;
    }
    any_foreign = false;
  }

  if (any_foreign) return AUTH_REPLICA_STORE_MIGRATION;
  if (all_blank) return AUTH_REPLICA_STORE_BLANK;
  if (!any_structural) return AUTH_REPLICA_STORE_NO_SOURCE;
  return AUTH_REPLICA_STORE_OK;
}

auth_replica_store_result auth_replica_root_candidates(
    auth_replica_store *store,
    uint8_t out[AUTH_REPLICA_COUNT][AUTH_REPLICA_ROOT_LENGTH], uint8_t *count) {
  if (!store || !store->io || !out || !count) return AUTH_REPLICA_STORE_INVALID;
  *count = 0;
  memzero(out, AUTH_REPLICA_COUNT * AUTH_REPLICA_ROOT_LENGTH);
  uint8_t region[AUTH_REPLICA_ROOT_REGION_SIZE];
  for (uint8_t replica = 0; replica < AUTH_REPLICA_COUNT; replica++) {
    if (store->state[replica] != AUTH_REPLICA_STATE_STRUCTURAL &&
        store->state[replica] != AUTH_REPLICA_STATE_DEGRADED)
      continue;
    if (read_at(store->io, replica, ROOT_REGION_OFFSET, region,
                sizeof(region)) == READ_FAILED)
      continue;
    bool duplicate = false;
    for (uint8_t existing = 0; existing < *count; existing++) {
      if (memcmp(out[existing], region, AUTH_REPLICA_ROOT_LENGTH) == 0) {
        duplicate = true;
        break;
      }
    }
    if (duplicate) continue;
    memcpy(out[*count], region, AUTH_REPLICA_ROOT_LENGTH);
    (*count)++;
  }
  memzero(region, sizeof(region));
  return *count ? AUTH_REPLICA_STORE_OK : AUTH_REPLICA_STORE_NO_SOURCE;
}

auth_replica_store_result auth_replica_authenticate(auth_replica_store *store,
                                                    const uint8_t root[32]) {
  if (!store || !store->io || !root) return AUTH_REPLICA_STORE_INVALID;
  if (store->integrity_failed) return AUTH_REPLICA_STORE_INTEGRITY;

  uint8_t mac_key[32];
  derive_mac_key(root, mac_key);

  auth_replica_header_t best;
  memzero(&best, sizeof(best));
  uint8_t selected = AUTH_REPLICA_NONE;
  bool divergent_tie = false;

  for (uint8_t replica = 0; replica < AUTH_REPLICA_COUNT; replica++) {
    store->authenticated[replica] = false;
    if (store->state[replica] != AUTH_REPLICA_STATE_STRUCTURAL &&
        store->state[replica] != AUTH_REPLICA_STATE_DEGRADED)
      continue;
    // Cleared before the call, because the `continue` below skips the memzero
    // at the end of the loop body. authenticate_one() already clears its output
    // on a failed decode or a failed tag, but not when the header read itself
    // fails, so this is the one gap left.
    auth_replica_header_t header;
    memzero(&header, sizeof(header));
    bool degraded = false;
    if (!authenticate_one(store->io, replica, mac_key, &header, &degraded))
      continue;
    store->authenticated[replica] = true;
    if (degraded) store->state[replica] = AUTH_REPLICA_STATE_DEGRADED;

    if (selected == AUTH_REPLICA_NONE || header.generation > best.generation) {
      best = header;
      selected = replica;
    } else if (header.generation == best.generation) {
      // Identical authenticated contents produce an identical tag, because
      // the tag covers the whole snapshot under the same key. A differing
      // tag at the same generation means two divergent authenticated states
      // exist, which must never be silently resolved.
      if (memcmp(header.tag, best.tag, AUTH_REPLICA_TAG_SIZE) != 0)
        divergent_tie = true;
    }
    memzero(&header, sizeof(header));
  }

  memzero(mac_key, sizeof(mac_key));

  if (divergent_tie) {
    store->integrity_failed = true;
    store->selected = AUTH_REPLICA_NONE;
    store->generation = 0;
    memzero(&best, sizeof(best));
    return AUTH_REPLICA_STORE_INTEGRITY;
  }
  if (selected == AUTH_REPLICA_NONE) {
    store->selected = AUTH_REPLICA_NONE;
    store->generation = 0;
    return AUTH_REPLICA_STORE_NO_SOURCE;
  }
  store->selected = selected;
  store->generation = best.generation;
  memzero(&best, sizeof(best));
  return AUTH_REPLICA_STORE_OK;
}

// ---------------------------------------------------------------------------
// Authenticated reads
// ---------------------------------------------------------------------------

// Re-authenticates the selected replica before releasing any of its bytes, so
// that damage occurring after selection cannot be served as trusted data.
static auth_replica_store_result reauthenticate_selected(
    auth_replica_store *store, const uint8_t root[32]) {
  if (store->integrity_failed) return AUTH_REPLICA_STORE_INTEGRITY;
  if (store->selected == AUTH_REPLICA_NONE) return AUTH_REPLICA_STORE_NO_SOURCE;
  uint8_t mac_key[32];
  derive_mac_key(root, mac_key);
  // Cleared before the call as well as after. authenticate_one() returns early
  // without writing its output when the header read itself fails, so reading
  // generation below would otherwise read an uninitialized object -- harmless
  // in practice because `ok` is tested first, but undefined all the same.
  auth_replica_header_t header;
  memzero(&header, sizeof(header));
  bool ok =
      authenticate_one(store->io, store->selected, mac_key, &header, NULL);
  uint64_t generation = header.generation;
  memzero(mac_key, sizeof(mac_key));
  memzero(&header, sizeof(header));
  if (!ok || generation != store->generation)
    return AUTH_REPLICA_STORE_NO_SOURCE;
  return AUTH_REPLICA_STORE_OK;
}

auth_replica_store_result auth_replica_read_root(
    auth_replica_store *store, const uint8_t root[32],
    uint8_t out[AUTH_REPLICA_ROOT_LENGTH]) {
  if (!store || !store->io || !root || !out) return AUTH_REPLICA_STORE_INVALID;
  memzero(out, AUTH_REPLICA_ROOT_LENGTH);
  auth_replica_store_result result = reauthenticate_selected(store, root);
  if (result != AUTH_REPLICA_STORE_OK) return result;
  uint8_t region[AUTH_REPLICA_ROOT_REGION_SIZE];
  if (read_at(store->io, store->selected, ROOT_REGION_OFFSET, region,
              sizeof(region)) == READ_FAILED) {
    memzero(region, sizeof(region));
    return AUTH_REPLICA_STORE_IO;
  }
  memcpy(out, region, AUTH_REPLICA_ROOT_LENGTH);
  memzero(region, sizeof(region));
  return AUTH_REPLICA_STORE_OK;
}

auth_replica_store_result auth_replica_read_slot(auth_replica_store *store,
                                                 const uint8_t root[32],
                                                 uint8_t index,
                                                 auth_replica_slot_t *out) {
  if (!store || !store->io || !root || !out || index >= AUTH_REPLICA_SLOT_COUNT)
    return AUTH_REPLICA_STORE_INVALID;
  memzero(out, sizeof(*out));
  auth_replica_store_result result = reauthenticate_selected(store, root);
  if (result != AUTH_REPLICA_STORE_OK) return result;
  uint8_t region[AUTH_REPLICA_SLOT_SIZE];
  if (read_at(store->io, store->selected, SLOT_OFFSET(index), region,
              sizeof(region)) == READ_FAILED) {
    memzero(region, sizeof(region));
    return AUTH_REPLICA_STORE_IO;
  }
  auth_replica_format_result decoded =
      auth_replica_slot_decode(region, index, out);
  memzero(region, sizeof(region));
  if (decoded != AUTH_REPLICA_OK) return AUTH_REPLICA_STORE_INTEGRITY;
  return out->present ? AUTH_REPLICA_STORE_OK : AUTH_REPLICA_STORE_ABSENT;
}

auth_replica_store_result auth_replica_walk_slots(
    auth_replica_store *store, const uint8_t root[32],
    auth_replica_slot_visitor visitor, void *context) {
  if (!store || !store->io || !root || !visitor)
    return AUTH_REPLICA_STORE_INVALID;
  auth_replica_store_result result = reauthenticate_selected(store, root);
  if (result != AUTH_REPLICA_STORE_OK) return result;
  uint8_t region[AUTH_REPLICA_SLOT_SIZE];
  auth_replica_slot_t slot;
  memzero(region, sizeof(region));
  memzero(&slot, sizeof(slot));
  for (uint8_t index = 0; index < AUTH_REPLICA_SLOT_COUNT; index++) {
    memzero(&slot, sizeof(slot));
    if (read_at(store->io, store->selected, SLOT_OFFSET(index), region,
                sizeof(region)) == READ_FAILED) {
      result = AUTH_REPLICA_STORE_IO;
      break;
    }
    auth_replica_format_result decoded =
        auth_replica_slot_decode(region, index, &slot);
    auth_replica_store_result status =
        decoded != AUTH_REPLICA_OK ? AUTH_REPLICA_STORE_INTEGRITY
                                   : (slot.present ? AUTH_REPLICA_STORE_OK
                                                   : AUTH_REPLICA_STORE_ABSENT);
    if (!visitor(context, index, status, &slot)) break;
  }
  memzero(region, sizeof(region));
  memzero(&slot, sizeof(slot));
  return result;
}

// ---------------------------------------------------------------------------
// Transactions
// ---------------------------------------------------------------------------

typedef enum {
  MUTATE_NONE,      // repair: reproduce the source verbatim
  MUTATE_ROOT,      // replace the root envelope
  MUTATE_SLOT_SET,  // write/replace one slot
  MUTATE_SLOT_DEL,  // clear one slot
} mutation_kind;

typedef struct {
  mutation_kind kind;
  const uint8_t *envelope;
  uint8_t index;
  const uint8_t *record;
  uint16_t record_len;
} mutation;

// Chooses a destination that is never the source: prefer an unusable or
// unauthenticated replica, otherwise the lowest claimed generation. This
// both protects the source and rotates wear across all three areas.
static uint8_t choose_destination(const auth_replica_store *store,
                                  uint8_t source) {
  uint8_t best = AUTH_REPLICA_NONE;
  // Pass 1: anything not currently holding an authenticated snapshot.
  for (uint8_t replica = 0; replica < AUTH_REPLICA_COUNT; replica++) {
    if (replica == source) continue;
    if (!store->authenticated[replica]) return replica;
  }
  // Pass 2: the oldest authenticated non-source replica.
  for (uint8_t replica = 0; replica < AUTH_REPLICA_COUNT; replica++) {
    if (replica == source) continue;
    if (best == AUTH_REPLICA_NONE ||
        store->claimed_generation[replica] < store->claimed_generation[best])
      best = replica;
  }
  return best;
}

#define AUTH_REPLICA_CLAIM_PAGE                           \
  ((AUTH_REPLICA_CLAIM_OFFSET / AUTH_REPLICA_PAGE_SIZE) * \
   AUTH_REPLICA_PAGE_SIZE)

// Erases the destination and marks it as ours.
//
// The page holding the claim slot is erased first and the claim is written
// immediately, before the remaining pages are erased. Ordering matters: an
// interrupted page erase can leave indeterminate bytes, so if the bulk erase
// ran first there would be a seven-page-wide window in which a power cut left
// a garbage-filled, header-less, unclaimed area. The conservative migration
// rule would then classify our own scratch space as foreign data and refuse to
// touch the device. Claiming first shrinks that window to the single erase of
// the claim page itself.
static bool erase_and_claim_destination(const auth_replica_io *io,
                                        uint8_t replica) {
  if (!io->erase_page(io->context, replica, AUTH_REPLICA_CLAIM_PAGE))
    return false;
  if (!write_claim(io, replica)) return false;
  for (uint32_t offset = 0; offset < AUTH_REPLICA_AREA_SIZE;
       offset += AUTH_REPLICA_PAGE_SIZE) {
    if (offset == AUTH_REPLICA_CLAIM_PAGE) continue;  // already erased
    if (!io->erase_page(io->context, replica, offset)) return false;
  }
  return true;
}

// Wipe reuses the exact same erase-and-claim sequence. Leaving the ownership
// claim behind is deliberate: it is what keeps a wipe interrupted on its very
// last page erase from looking like foreign data.
//
// At that moment every replica header is already gone, so there is no valid
// snapshot left to prove the device is ours, yet indeterminate bytes remain.
// Without a claim the conservative migration rule would refuse the device and a
// freshly wiped authenticator could not be provisioned again without an
// explicit reformat. A wiped area is not "factory blank", it is "ours and
// empty", and the claim records exactly that.
//
// The claim asserts nothing about validity and cannot resurrect wiped data: the
// claim page is erased before the claim is written, which destroys the tail of
// the authenticated body and makes the old snapshot unauthenticatable
// immediately.

static bool write_region(const auth_replica_io *io, uint8_t replica,
                         uint32_t offset, const uint8_t *data, uint32_t len) {
  for (uint32_t written = 0; written < len; written += AUTH_REPLICA_LINE_SIZE) {
    if (!io->write_line(io->context, replica, offset + written, data + written))
      return false;
  }
  return true;
}

// Produces the new body region by region: writes it to the destination while
// accumulating the canonical SHA-256 body digest, the presence bitmap, and
// the present-slot count. The source is only ever read.
static auth_replica_store_result stream_body(
    auth_replica_store *store, uint8_t source, uint8_t destination,
    const mutation *change, uint8_t digest_out[32], uint8_t bitmap_out[16],
    uint16_t *present_out) {
  const auth_replica_io *io = store->io;
  SHA256_CTX sha;
  sha256_Init(&sha);
  memzero(bitmap_out, AUTH_REPLICA_BITMAP_SIZE);
  *present_out = 0;

  uint8_t region[AUTH_REPLICA_SLOT_SIZE];

  // Root region.
  memzero(region, AUTH_REPLICA_ROOT_REGION_SIZE);
  if (change->kind == MUTATE_ROOT) {
    memcpy(region, change->envelope, AUTH_REPLICA_ROOT_LENGTH);
  } else if (source != AUTH_REPLICA_NONE) {
    if (read_at(io, source, ROOT_REGION_OFFSET, region,
                AUTH_REPLICA_ROOT_REGION_SIZE) == READ_FAILED) {
      memzero(region, sizeof(region));
      return AUTH_REPLICA_STORE_IO;
    }
    // Canonicalize the two trailing pad bytes; a source that had them set
    // could not have authenticated in the first place.
    memzero(region + AUTH_REPLICA_ROOT_LENGTH,
            AUTH_REPLICA_ROOT_REGION_SIZE - AUTH_REPLICA_ROOT_LENGTH);
  }
  if (!write_region(io, destination, ROOT_REGION_OFFSET, region,
                    AUTH_REPLICA_ROOT_REGION_SIZE)) {
    memzero(region, sizeof(region));
    return AUTH_REPLICA_STORE_IO;
  }
  sha256_Update(&sha, region, AUTH_REPLICA_ROOT_REGION_SIZE);

  // Slot regions, in increasing physical order.
  for (uint8_t index = 0; index < AUTH_REPLICA_SLOT_COUNT; index++) {
    auth_replica_slot_t slot;
    memzero(&slot, sizeof(slot));
    bool have_slot = false;

    if (change->kind == MUTATE_SLOT_SET && change->index == index) {
      // Bounded here as well as in auth_replica_commit_slot(), which is the
      // only producer of this mutation today. A memcpy into a stack buffer in
      // the secure kernel should not rest on a check two frames up, and every
      // other branch in this function validates what it is about to use.
      if (change->record_len == 0 ||
          change->record_len > AUTH_REPLICA_SLOT_RECORD_MAX) {
        memzero(&slot, sizeof(slot));
        memzero(region, sizeof(region));
        return AUTH_REPLICA_STORE_INVALID;
      }
      slot.present = true;
      slot.record_len = change->record_len;
      memcpy(slot.record, change->record, change->record_len);
      have_slot = true;
    } else if (change->kind == MUTATE_SLOT_DEL && change->index == index) {
      have_slot = false;  // canonical empty
    } else if (source != AUTH_REPLICA_NONE) {
      if (read_at(io, source, SLOT_OFFSET(index), region, sizeof(region)) ==
          READ_FAILED) {
        memzero(&slot, sizeof(slot));
        memzero(region, sizeof(region));
        return AUTH_REPLICA_STORE_IO;
      }
      if (auth_replica_slot_decode(region, index, &slot) != AUTH_REPLICA_OK) {
        memzero(&slot, sizeof(slot));
        memzero(region, sizeof(region));
        return AUTH_REPLICA_STORE_INTEGRITY;
      }
      have_slot = slot.present;
    }

    slot.present = have_slot;
    if (auth_replica_slot_encode(region, index, &slot) != AUTH_REPLICA_OK) {
      memzero(&slot, sizeof(slot));
      memzero(region, sizeof(region));
      return AUTH_REPLICA_STORE_INVALID;
    }
    if (have_slot) {
      bitmap_out[index / 8] |= (uint8_t)(1u << (index % 8));
      (*present_out)++;
    }
    memzero(&slot, sizeof(slot));

    if (!write_region(io, destination, SLOT_OFFSET(index), region,
                      AUTH_REPLICA_SLOT_SIZE)) {
      memzero(region, sizeof(region));
      return AUTH_REPLICA_STORE_IO;
    }
    sha256_Update(&sha, region, AUTH_REPLICA_SLOT_SIZE);
  }

  sha256_Final(&sha, digest_out);
  memzero(region, sizeof(region));
  return AUTH_REPLICA_STORE_OK;
}

// Reads the destination body back and computes the snapshot MAC over the
// supplied header head plus those read-back bytes, confirming the digest the
// header claims is the digest the flash actually holds.
static auth_replica_store_result mac_from_readback(
    auth_replica_store *store, uint8_t destination,
    const uint8_t header_head[AUTH_REPLICA_HEADER_MAC_SIZE],
    const uint8_t mac_key[32], const uint8_t expected_digest[32],
    uint8_t tag_out[32]) {
  auth_replica_mac_ctx_t mac;
  auth_replica_mac_init(&mac, mac_key);
  auth_replica_mac_update(&mac, header_head, AUTH_REPLICA_HEADER_MAC_SIZE);
  SHA256_CTX sha;
  sha256_Init(&sha);

  uint8_t region[AUTH_REPLICA_SLOT_SIZE];
  bool failed = false;
  uint32_t offset = ROOT_REGION_OFFSET;
  uint32_t remaining = AUTH_REPLICA_BODY_SIZE;
  while (remaining && !failed) {
    uint32_t chunk = remaining < sizeof(region) ? remaining : sizeof(region);
    if (read_at(store->io, destination, offset, region, chunk) == READ_FAILED) {
      failed = true;
      break;
    }
    auth_replica_mac_update(&mac, region, chunk);
    sha256_Update(&sha, region, chunk);
    offset += chunk;
    remaining -= chunk;
  }

  uint8_t digest[32] = {0};
  auth_replica_mac_final(&mac, tag_out);
  sha256_Final(&sha, digest);
  bool digest_ok = !failed && auth_replica_verify_tag(
                                  digest, expected_digest) == AUTH_REPLICA_OK;
  memzero(digest, sizeof(digest));
  memzero(region, sizeof(region));
  if (!digest_ok) {
    memzero(tag_out, 32);
    return failed ? AUTH_REPLICA_STORE_IO : AUTH_REPLICA_STORE_INTEGRITY;
  }
  return AUTH_REPLICA_STORE_OK;
}

// Shared copy-on-write transaction. `provisioning` allows a NONE source.
static auth_replica_store_result commit(
    auth_replica_store *store, const uint8_t root[32], const mutation *change,
    const uint8_t nonce[16], bool provisioning, bool same_generation) {
  if (!store || !store->io || !root) return AUTH_REPLICA_STORE_INVALID;
  // `nonce` is unused (and may be NULL) when inheriting for a repair.
  if (!nonce && !same_generation) return AUTH_REPLICA_STORE_INVALID;
  if (store->integrity_failed) return AUTH_REPLICA_STORE_INTEGRITY;

  uint8_t source = store->selected;
  uint64_t generation;

  if (provisioning) {
    if (source != AUTH_REPLICA_NONE) return AUTH_REPLICA_STORE_INVALID;
    for (uint8_t replica = 0; replica < AUTH_REPLICA_COUNT; replica++) {
      // A torn area is our own abandoned scratch space, so a provisioning
      // attempt interrupted by a power cut stays retryable.
      if (store->state[replica] != AUTH_REPLICA_STATE_BLANK &&
          store->state[replica] != AUTH_REPLICA_STATE_TORN)
        return AUTH_REPLICA_STORE_MIGRATION;
    }
    generation = 1;
  } else {
    if (source == AUTH_REPLICA_NONE) return AUTH_REPLICA_STORE_NO_SOURCE;
    // Refuse before touching flash, so a capped device still reads and wipes.
    if (same_generation) {
      generation = store->generation;
    } else {
      if (store->generation >= AUTH_REPLICA_MAX_GENERATION ||
          store->generation == UINT64_MAX)
        return AUTH_REPLICA_STORE_LIMIT;
      generation = store->generation + 1;
    }
    // Prove the source is still authentic before deriving a new state.
    auth_replica_store_result fresh = reauthenticate_selected(store, root);
    if (fresh != AUTH_REPLICA_STORE_OK) return fresh;
  }

  // A repair must reproduce the source exactly, nonce included, so that the
  // duplicate is an identical -- not a divergent -- same-generation snapshot.
  uint8_t effective_nonce[AUTH_REPLICA_NONCE_SIZE];
  if (same_generation) {
    uint8_t header_bytes[AUTH_REPLICA_HEADER_SIZE];
    auth_replica_header_t source_header;
    if (read_at(store->io, source, 0, header_bytes, sizeof(header_bytes)) ==
        READ_FAILED)
      return AUTH_REPLICA_STORE_IO;
    if (auth_replica_header_decode(header_bytes, &source_header) !=
        AUTH_REPLICA_OK)
      return AUTH_REPLICA_STORE_INTEGRITY;
    memcpy(effective_nonce, source_header.nonce, AUTH_REPLICA_NONCE_SIZE);
    memzero(&source_header, sizeof(source_header));
  } else {
    memcpy(effective_nonce, nonce, AUTH_REPLICA_NONCE_SIZE);
  }

  uint8_t destination = choose_destination(store, source);
  if (destination == AUTH_REPLICA_NONE || destination == source)
    return AUTH_REPLICA_STORE_IO;

  if (!erase_and_claim_destination(store->io, destination))
    return AUTH_REPLICA_STORE_IO;

  uint8_t digest[32] = {0}, bitmap[AUTH_REPLICA_BITMAP_SIZE] = {0};
  uint16_t present = 0;
  auth_replica_store_result result =
      stream_body(store, source, destination, change, digest, bitmap, &present);
  if (result != AUTH_REPLICA_STORE_OK) return result;

  auth_replica_header_t header;
  memzero(&header, sizeof(header));
  header.generation = generation;
  memcpy(header.nonce, effective_nonce, AUTH_REPLICA_NONCE_SIZE);
  memcpy(header.bitmap, bitmap, AUTH_REPLICA_BITMAP_SIZE);
  header.present_count = present;
  memcpy(header.body_digest, digest, AUTH_REPLICA_DIGEST_SIZE);

  uint8_t header_bytes[AUTH_REPLICA_HEADER_SIZE];
  if (auth_replica_header_encode(header_bytes, &header) != AUTH_REPLICA_OK) {
    memzero(&header, sizeof(header));
    return AUTH_REPLICA_STORE_INVALID;
  }

  uint8_t mac_key[32];
  derive_mac_key(root, mac_key);
  uint8_t tag[32] = {0};
  result =
      mac_from_readback(store, destination, header_bytes, mac_key, digest, tag);
  if (result != AUTH_REPLICA_STORE_OK) {
    memzero(mac_key, sizeof(mac_key));
    memzero(&header, sizeof(header));
    return result;
  }

  memcpy(header.tag, tag, AUTH_REPLICA_TAG_SIZE);
  if (auth_replica_header_encode(header_bytes, &header) != AUTH_REPLICA_OK) {
    memzero(mac_key, sizeof(mac_key));
    memzero(&header, sizeof(header));
    return AUTH_REPLICA_STORE_INVALID;
  }
  memzero(tag, sizeof(tag));

  // Header last: until these lines land and authenticate, the destination is
  // not a snapshot at all.
  if (!write_region(store->io, destination, 0, header_bytes,
                    AUTH_REPLICA_HEADER_SIZE)) {
    memzero(mac_key, sizeof(mac_key));
    memzero(&header, sizeof(header));
    return AUTH_REPLICA_STORE_IO;
  }

  // Independent full re-read and authentication before moving selection.
  auth_replica_header_t confirmed;
  bool degraded = false;
  bool authentic =
      authenticate_one(store->io, destination, mac_key, &confirmed, &degraded);
  memzero(mac_key, sizeof(mac_key));
  memzero(&header, sizeof(header));
  if (!authentic || confirmed.generation != generation) {
    memzero(&confirmed, sizeof(confirmed));
    return AUTH_REPLICA_STORE_INTEGRITY;
  }
  memzero(&confirmed, sizeof(confirmed));

  store->state[destination] =
      degraded ? AUTH_REPLICA_STATE_DEGRADED : AUTH_REPLICA_STATE_STRUCTURAL;
  store->claimed_generation[destination] = generation;
  store->authenticated[destination] = true;
  store->selected = destination;
  store->generation = generation;
  return AUTH_REPLICA_STORE_OK;
}

auth_replica_store_result auth_replica_provision(
    auth_replica_store *store, const uint8_t root[32],
    const uint8_t envelope[AUTH_REPLICA_ROOT_LENGTH],
    const uint8_t nonce[AUTH_REPLICA_NONCE_SIZE]) {
  if (!envelope) return AUTH_REPLICA_STORE_INVALID;
  mutation change = {.kind = MUTATE_ROOT, .envelope = envelope};
  return commit(store, root, &change, nonce, true, false);
}

auth_replica_store_result auth_replica_commit_root(
    auth_replica_store *store, const uint8_t root[32],
    const uint8_t envelope[AUTH_REPLICA_ROOT_LENGTH],
    const uint8_t nonce[AUTH_REPLICA_NONCE_SIZE]) {
  if (!envelope) return AUTH_REPLICA_STORE_INVALID;
  mutation change = {.kind = MUTATE_ROOT, .envelope = envelope};
  return commit(store, root, &change, nonce, false, false);
}

auth_replica_store_result auth_replica_commit_slot(
    auth_replica_store *store, const uint8_t root[32], uint8_t index,
    const uint8_t *record, uint16_t record_len,
    const uint8_t nonce[AUTH_REPLICA_NONCE_SIZE]) {
  if (!record || index >= AUTH_REPLICA_SLOT_COUNT || record_len == 0 ||
      record_len > AUTH_REPLICA_SLOT_RECORD_MAX)
    return AUTH_REPLICA_STORE_INVALID;
  mutation change = {.kind = MUTATE_SLOT_SET,
                     .index = index,
                     .record = record,
                     .record_len = record_len};
  return commit(store, root, &change, nonce, false, false);
}

auth_replica_store_result auth_replica_delete_slot(
    auth_replica_store *store, const uint8_t root[32], uint8_t index,
    const uint8_t nonce[AUTH_REPLICA_NONCE_SIZE]) {
  if (index >= AUTH_REPLICA_SLOT_COUNT) return AUTH_REPLICA_STORE_INVALID;
  mutation change = {.kind = MUTATE_SLOT_DEL, .index = index};
  return commit(store, root, &change, nonce, false, false);
}

auth_replica_store_result auth_replica_repair_one(auth_replica_store *store,
                                                  const uint8_t root[32]) {
  if (!store || !store->io) return AUTH_REPLICA_STORE_INVALID;
  if (store->integrity_failed) return AUTH_REPLICA_STORE_INTEGRITY;
  if (store->selected == AUTH_REPLICA_NONE) return AUTH_REPLICA_STORE_NO_SOURCE;
  // Nothing to do when every replica already holds the selected generation.
  bool needed = false;
  for (uint8_t replica = 0; replica < AUTH_REPLICA_COUNT; replica++) {
    if (replica == store->selected) continue;
    if (!store->authenticated[replica] ||
        store->claimed_generation[replica] != store->generation)
      needed = true;
  }
  if (!needed) return AUTH_REPLICA_STORE_OK;
  mutation change = {.kind = MUTATE_NONE};
  // Repair reproduces the selected snapshot at the same generation, so it
  // consumes no generation budget and cannot be blocked by the wear cap.
  uint8_t previous = store->selected;
  uint64_t generation = store->generation;
  auth_replica_store_result result =
      commit(store, root, &change, NULL, false, true);
  if (result == AUTH_REPLICA_STORE_OK) {
    // Both copies are now valid at the same generation with identical
    // contents; keep the original as selected for stability.
    store->selected = previous;
    store->generation = generation;
  }
  return result;
}

auth_replica_store_result auth_replica_wipe(auth_replica_store *store) {
  if (!store || !store->io) return AUTH_REPLICA_STORE_INVALID;
  bool ok = true;
  for (uint8_t replica = 0; replica < AUTH_REPLICA_COUNT; replica++) {
    if (!erase_and_claim_destination(store->io, replica)) ok = false;
  }
  store->selected = AUTH_REPLICA_NONE;
  store->generation = 0;
  store->integrity_failed = false;
  for (uint8_t replica = 0; replica < AUTH_REPLICA_COUNT; replica++) {
    // Empty and owned by us, not factory blank: the claim marker remains.
    store->state[replica] = AUTH_REPLICA_STATE_TORN;
    store->claimed_generation[replica] = 0;
    store->authenticated[replica] = false;
  }
  return ok ? AUTH_REPLICA_STORE_OK : AUTH_REPLICA_STORE_IO;
}
