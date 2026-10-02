#include "replica_format.h"

#include <string.h>

#include "consteq.h"
#include "memzero.h"

// ---------------------------------------------------------------------------
// Compile-time proof that the fixed layout matches the plan's locked wire
// format and that one replica proves out to hold exactly 100 slots with the
// existing 448-byte metadata / 556-byte record allowance, inside one 64 KiB
// area. If any of these ever fail, the format changed and every constant
// touching it (including AUTH_RESIDENT_METADATA_MAX) must be re-reviewed
// together, not adjusted individually.
// ---------------------------------------------------------------------------

_Static_assert(AUTH_REPLICA_MAGIC_SIZE == 8, "magic is 8 bytes");
_Static_assert(AUTH_REPLICA_HEADER_SIZE == 160, "header is 160 bytes");
_Static_assert(AUTH_REPLICA_HEADER_MAC_SIZE == 128,
              "tag occupies the last 32 of 160 header bytes");
_Static_assert(AUTH_REPLICA_ROOT_LENGTH == 62, "root envelope is 62 bytes");
_Static_assert(AUTH_REPLICA_ROOT_REGION_SIZE == 64,
              "root region is root envelope plus 2 padding bytes");
_Static_assert(AUTH_REPLICA_SLOT_COUNT == 100, "vault holds 100 resident slots");
_Static_assert(AUTH_REPLICA_SLOT_RECORD_MAX == 556,
              "slot record cap matches AUTH_RESIDENT_ID_MAX + 40");
_Static_assert(AUTH_REPLICA_SLOT_HEADER_SIZE + AUTH_REPLICA_SLOT_RECORD_MAX <=
                  AUTH_REPLICA_SLOT_SIZE,
              "the largest record plus its slot header must fit in one slot");
_Static_assert(AUTH_REPLICA_SLOT_SIZE == 576, "one slot region is 576 bytes");
_Static_assert(AUTH_REPLICA_BODY_SIZE == 57664,
              "body is the root region plus 100 slot regions");
_Static_assert(AUTH_REPLICA_USED_SIZE == 57824,
              "used size is the header plus the body");
_Static_assert(AUTH_REPLICA_USED_SIZE <= AUTH_REPLICA_AREA_SIZE,
              "a replica must fit inside its 64 KiB area");
_Static_assert(AUTH_REPLICA_HEADROOM == 7712,
              "unused tail of the 64 KiB area");
_Static_assert(AUTH_REPLICA_MAX_GENERATION < 0xffffffffffffffffull,
              "the generation cap must leave UINT64_MAX unreachable");

const uint8_t AUTH_REPLICA_MAGIC[AUTH_REPLICA_MAGIC_SIZE] = {
    'T', 'S', 'A', 'U', 'T', 'H', 'R', '1'};

// ---------------------------------------------------------------------------
// Local little-endian byte packing. Deliberately explicit rather than a
// packed struct overlay: the wire format is authenticated, cross-toolchain,
// and long-lived, so its byte order and offsets must never depend on struct
// packing, padding, or host endianness.
// ---------------------------------------------------------------------------

static void put_u16(uint8_t *p, uint16_t value) {
  p[0] = (uint8_t)(value);
  p[1] = (uint8_t)(value >> 8);
}
static void put_u32(uint8_t *p, uint32_t value) {
  for (unsigned i = 0; i < 4; i++) p[i] = (uint8_t)(value >> (8 * i));
}
static void put_u64(uint8_t *p, uint64_t value) {
  for (unsigned i = 0; i < 8; i++) p[i] = (uint8_t)(value >> (8 * i));
}
static uint16_t get_u16(const uint8_t *p) {
  return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}
static uint32_t get_u32(const uint8_t *p) {
  uint32_t value = 0;
  for (unsigned i = 0; i < 4; i++) value |= (uint32_t)p[i] << (8 * i);
  return value;
}
static uint64_t get_u64(const uint8_t *p) {
  uint64_t value = 0;
  for (unsigned i = 0; i < 8; i++) value |= (uint64_t)p[i] << (8 * i);
  return value;
}

static bool all_zero(const uint8_t *p, size_t len) {
  uint8_t accumulator = 0;
  for (size_t i = 0; i < len; i++) accumulator |= p[i];
  return accumulator == 0;
}

// Counts set bits among the first AUTH_REPLICA_SLOT_COUNT bits of a
// AUTH_REPLICA_BITMAP_SIZE-byte little-endian bitmap and reports through
// `high_bits_zero` whether every bit at or beyond AUTH_REPLICA_SLOT_COUNT is
// clear. The bitmap is public metadata (it only says which slot positions
// are occupied), so this runs in variable time; nothing here is secret.
static uint16_t bitmap_popcount_low(const uint8_t bitmap[AUTH_REPLICA_BITMAP_SIZE],
                                    bool *high_bits_zero) {
  uint16_t count = 0;
  *high_bits_zero = true;
  for (unsigned byte = 0; byte < AUTH_REPLICA_BITMAP_SIZE; byte++) {
    for (unsigned bit = 0; bit < 8; bit++) {
      unsigned position = byte * 8 + bit;
      bool set = (bitmap[byte] >> bit) & 1u;
      if (!set) continue;
      if (position < AUTH_REPLICA_SLOT_COUNT)
        count++;
      else
        *high_bits_zero = false;
    }
  }
  return count;
}

// ---------------------------------------------------------------------------
// Header codec
// ---------------------------------------------------------------------------

auth_replica_format_result auth_replica_header_encode(
    uint8_t out[AUTH_REPLICA_HEADER_SIZE],
    const auth_replica_header_t *header) {
  if (!out || !header) return AUTH_REPLICA_BOUNDS;
  if (header->generation == 0) return AUTH_REPLICA_NONCANONICAL;
  bool high_bits_zero = true;
  uint16_t computed_count =
      bitmap_popcount_low(header->bitmap, &high_bits_zero);
  if (!high_bits_zero) return AUTH_REPLICA_NONCANONICAL;
  if (header->present_count != computed_count) return AUTH_REPLICA_BOUNDS;

  memset(out, 0, AUTH_REPLICA_HEADER_SIZE);
  memcpy(out, AUTH_REPLICA_MAGIC, AUTH_REPLICA_MAGIC_SIZE);
  put_u16(out + 8, AUTH_REPLICA_FORMAT_VERSION);
  put_u16(out + 10, AUTH_REPLICA_HEADER_SIZE);
  put_u32(out + 12, AUTH_REPLICA_USED_SIZE);
  put_u64(out + 16, header->generation);
  memcpy(out + 24, header->nonce, AUTH_REPLICA_NONCE_SIZE);
  put_u32(out + 40, AUTH_REPLICA_NAMESPACE);
  put_u32(out + 44, 0);  // flags: always zero in this format version.
  memcpy(out + 48, header->bitmap, AUTH_REPLICA_BITMAP_SIZE);
  put_u16(out + 64, AUTH_REPLICA_ROOT_LENGTH);
  put_u16(out + 66, header->present_count);
  put_u32(out + 68, AUTH_REPLICA_BODY_SIZE);
  memcpy(out + 72, header->body_digest, AUTH_REPLICA_DIGEST_SIZE);
  // out[104..127] stays zero (reserved) from the memset above.
  memcpy(out + 128, header->tag, AUTH_REPLICA_TAG_SIZE);
  return AUTH_REPLICA_OK;
}

auth_replica_format_result auth_replica_header_decode(
    const uint8_t in[AUTH_REPLICA_HEADER_SIZE], auth_replica_header_t *header) {
  if (!header) return AUTH_REPLICA_BOUNDS;
  memzero(header, sizeof(*header));
  if (!in) return AUTH_REPLICA_BOUNDS;

  if (memcmp(in, AUTH_REPLICA_MAGIC, AUTH_REPLICA_MAGIC_SIZE) != 0)
    return AUTH_REPLICA_VERSION;
  if (get_u16(in + 8) != AUTH_REPLICA_FORMAT_VERSION) return AUTH_REPLICA_VERSION;
  if (get_u16(in + 10) != AUTH_REPLICA_HEADER_SIZE) return AUTH_REPLICA_BOUNDS;
  if (get_u32(in + 12) != AUTH_REPLICA_USED_SIZE) return AUTH_REPLICA_BOUNDS;

  uint64_t generation = get_u64(in + 16);
  if (generation == 0) return AUTH_REPLICA_NONCANONICAL;

  if (get_u32(in + 40) != AUTH_REPLICA_NAMESPACE) return AUTH_REPLICA_BOUNDS;
  if (!all_zero(in + 44, 4)) return AUTH_REPLICA_NONCANONICAL;  // flags != 0

  uint8_t bitmap[AUTH_REPLICA_BITMAP_SIZE];
  memcpy(bitmap, in + 48, AUTH_REPLICA_BITMAP_SIZE);
  bool high_bits_zero = true;
  uint16_t computed_count = bitmap_popcount_low(bitmap, &high_bits_zero);
  if (!high_bits_zero) return AUTH_REPLICA_NONCANONICAL;

  if (get_u16(in + 64) != AUTH_REPLICA_ROOT_LENGTH) return AUTH_REPLICA_BOUNDS;
  uint16_t present_count = get_u16(in + 66);
  if (present_count != computed_count) return AUTH_REPLICA_NONCANONICAL;

  if (get_u32(in + 68) != AUTH_REPLICA_BODY_SIZE) return AUTH_REPLICA_BOUNDS;
  if (!all_zero(in + 104, 24)) return AUTH_REPLICA_NONCANONICAL;  // reserved

  header->generation = generation;
  memcpy(header->nonce, in + 24, AUTH_REPLICA_NONCE_SIZE);
  memcpy(header->bitmap, bitmap, AUTH_REPLICA_BITMAP_SIZE);
  header->present_count = present_count;
  memcpy(header->body_digest, in + 72, AUTH_REPLICA_DIGEST_SIZE);
  memcpy(header->tag, in + 128, AUTH_REPLICA_TAG_SIZE);
  return AUTH_REPLICA_OK;
}

// ---------------------------------------------------------------------------
// Slot codec
// ---------------------------------------------------------------------------

auth_replica_format_result auth_replica_slot_encode(
    uint8_t out[AUTH_REPLICA_SLOT_SIZE], uint8_t index,
    const auth_replica_slot_t *slot) {
  if (!out || !slot || index >= AUTH_REPLICA_SLOT_COUNT)
    return AUTH_REPLICA_BOUNDS;
  memset(out, 0, AUTH_REPLICA_SLOT_SIZE);
  if (!slot->present) return AUTH_REPLICA_OK;  // canonical: all-zero
  if (slot->record_len == 0 || slot->record_len > AUTH_REPLICA_SLOT_RECORD_MAX)
    return AUTH_REPLICA_BOUNDS;
  out[0] = 1;
  out[1] = index;
  put_u16(out + 2, slot->record_len);
  // out[4..15] stays zero (reserved) from the memset above.
  memcpy(out + AUTH_REPLICA_SLOT_HEADER_SIZE, slot->record, slot->record_len);
  // Remaining padding stays zero from the memset above.
  return AUTH_REPLICA_OK;
}

auth_replica_format_result auth_replica_slot_decode(
    const uint8_t in[AUTH_REPLICA_SLOT_SIZE], uint8_t index,
    auth_replica_slot_t *slot) {
  if (!slot) return AUTH_REPLICA_BOUNDS;
  memzero(slot, sizeof(*slot));
  if (!in || index >= AUTH_REPLICA_SLOT_COUNT) return AUTH_REPLICA_BOUNDS;

  if (in[0] == 0) {
    if (!all_zero(in, AUTH_REPLICA_SLOT_SIZE)) return AUTH_REPLICA_NONCANONICAL;
    slot->present = false;
    return AUTH_REPLICA_OK;
  }
  if (in[0] != 1) return AUTH_REPLICA_NONCANONICAL;
  if (in[1] != index) return AUTH_REPLICA_NONCANONICAL;
  if (!all_zero(in + 4, 12)) return AUTH_REPLICA_NONCANONICAL;  // reserved

  uint16_t record_len = get_u16(in + 2);
  if (record_len == 0 || record_len > AUTH_REPLICA_SLOT_RECORD_MAX)
    return AUTH_REPLICA_BOUNDS;

  size_t padding_offset = AUTH_REPLICA_SLOT_HEADER_SIZE + record_len;
  size_t padding_len = AUTH_REPLICA_SLOT_SIZE - padding_offset;
  if (!all_zero(in + padding_offset, padding_len))
    return AUTH_REPLICA_NONCANONICAL;

  slot->present = true;
  slot->record_len = record_len;
  memcpy(slot->record, in + AUTH_REPLICA_SLOT_HEADER_SIZE, record_len);
  return AUTH_REPLICA_OK;
}

// ---------------------------------------------------------------------------
// Streaming MAC
// ---------------------------------------------------------------------------

void auth_replica_mac_init(auth_replica_mac_ctx_t *mac, const uint8_t key[32]) {
  hmac_sha256_Init(&mac->ctx, key, 32);
}

void auth_replica_mac_update(auth_replica_mac_ctx_t *mac, const uint8_t *data,
                             size_t len) {
  hmac_sha256_Update(&mac->ctx, data, (uint32_t)len);
}

void auth_replica_mac_final(auth_replica_mac_ctx_t *mac, uint8_t tag[32]) {
  hmac_sha256_Final(&mac->ctx, tag);
  memzero(mac, sizeof(*mac));
}

auth_replica_format_result auth_replica_verify_tag(const uint8_t computed[32],
                                                   const uint8_t expected[32]) {
  if (!computed || !expected) return AUTH_REPLICA_BOUNDS;
  return consteq(computed, expected, 32) ? AUTH_REPLICA_OK
                                         : AUTH_REPLICA_AUTH_FAILED;
}
