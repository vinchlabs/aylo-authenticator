#include <assert.h>
#include <string.h>

#include "../replica_format.h"
#include "sha2.h"

// Fixed, independently-computed vector: HMAC-SHA256 key 01..20, nonce
// 30..3f, slot 0 present/max-size (556 bytes of 0x11), slot 99
// present/3-byte record {0x22,0x33,0x44}, all other slots absent,
// generation 1. Header/body bytes and the resulting tag were computed with
// Python's stdlib hmac/hashlib (never with the code under test) and are
// pinned here as ground truth.
static const uint8_t kKey[32] = {1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11,
                                 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                                 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
static const uint8_t kNonce[16] = {0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
                                   0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
                                   0x3c, 0x3d, 0x3e, 0x3f};
static const uint8_t kBitmap[16] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                    0x08, 0x00, 0x00, 0x00};
static const uint8_t kBodyDigest[32] = {
    0x39, 0x3e, 0x9a, 0xe7, 0x62, 0xf1, 0xdc, 0xb1, 0xde, 0x49, 0xb0,
    0xaa, 0x96, 0x17, 0xc7, 0xa3, 0x85, 0xe7, 0x17, 0x5d, 0x12, 0xbc,
    0xcd, 0xa1, 0xb9, 0x07, 0x0c, 0x80, 0x48, 0x0c, 0xca, 0x1a};
static const uint8_t kTag[32] = {
    0x5c, 0xae, 0xe8, 0x59, 0x7f, 0x11, 0x8f, 0xc2, 0x10, 0xf5, 0xe6,
    0x77, 0x71, 0xdb, 0xfe, 0x66, 0x96, 0x26, 0xcc, 0x85, 0x61, 0x5a,
    0x78, 0x62, 0x15, 0xd6, 0x18, 0xd9, 0xa4, 0x87, 0xd5, 0xd4};
static const uint8_t kRec99[3] = {0x22, 0x33, 0x44};

static uint8_t header_buf[AUTH_REPLICA_HEADER_SIZE];
static uint8_t slot_buf[AUTH_REPLICA_SLOT_SIZE];

// Recomputes the full-snapshot MAC over an already-encoded header (with its
// tag field excluded) plus 100 already-encoded slot buffers, and compares
// against `expected`. This exercises the streaming API exactly the way the
// replica manager does: header-head bytes first, then slots in
// physical order.
static void assert_mac_matches(const uint8_t header[AUTH_REPLICA_HEADER_SIZE],
                               const uint8_t body[AUTH_REPLICA_BODY_SIZE],
                               const uint8_t expected[32]) {
  auth_replica_mac_ctx_t mac;
  uint8_t computed[32];
  auth_replica_mac_init(&mac, kKey);
  auth_replica_mac_update(&mac, header, AUTH_REPLICA_HEADER_MAC_SIZE);
  auth_replica_mac_update(&mac, body, AUTH_REPLICA_BODY_SIZE);
  auth_replica_mac_final(&mac, computed);
  assert(auth_replica_verify_tag(computed, expected) == AUTH_REPLICA_OK);
}

static void build_reference_snapshot(uint8_t body[AUTH_REPLICA_BODY_SIZE]) {
  memset(body, 0, AUTH_REPLICA_BODY_SIZE);
  uint8_t root[AUTH_REPLICA_ROOT_REGION_SIZE];
  memset(root, 0xaa, AUTH_REPLICA_ROOT_LENGTH);
  memset(root + AUTH_REPLICA_ROOT_LENGTH, 0, 2);
  memcpy(body, root, AUTH_REPLICA_ROOT_REGION_SIZE);

  auth_replica_slot_t slot = {0};
  slot.present = true;
  slot.record_len = AUTH_REPLICA_SLOT_RECORD_MAX;
  memset(slot.record, 0x11, slot.record_len);
  assert(auth_replica_slot_encode(slot_buf, 0, &slot) == AUTH_REPLICA_OK);
  memcpy(body + AUTH_REPLICA_ROOT_REGION_SIZE, slot_buf, AUTH_REPLICA_SLOT_SIZE);

  slot.present = true;
  slot.record_len = sizeof(kRec99);
  memset(slot.record, 0, sizeof(slot.record));
  memcpy(slot.record, kRec99, sizeof(kRec99));
  assert(auth_replica_slot_encode(slot_buf, 99, &slot) == AUTH_REPLICA_OK);
  memcpy(body + AUTH_REPLICA_ROOT_REGION_SIZE + 99 * AUTH_REPLICA_SLOT_SIZE,
        slot_buf, AUTH_REPLICA_SLOT_SIZE);
}

static void test_exact_encoding_matches_independent_vector(void) {
  auth_replica_header_t header = {0};
  header.generation = 1;
  memcpy(header.nonce, kNonce, sizeof(kNonce));
  memcpy(header.bitmap, kBitmap, sizeof(kBitmap));
  header.present_count = 2;
  memcpy(header.body_digest, kBodyDigest, sizeof(kBodyDigest));
  memcpy(header.tag, kTag, sizeof(kTag));

  assert(auth_replica_header_encode(header_buf, &header) == AUTH_REPLICA_OK);

  uint8_t body[AUTH_REPLICA_BODY_SIZE];
  build_reference_snapshot(body);

  uint8_t computed_digest[32];
  sha256_Raw(body, AUTH_REPLICA_BODY_SIZE, computed_digest);
  assert(memcmp(computed_digest, kBodyDigest, 32) == 0);

  assert_mac_matches(header_buf, body, kTag);

  auth_replica_header_t decoded = {0};
  assert(auth_replica_header_decode(header_buf, &decoded) == AUTH_REPLICA_OK);
  assert(decoded.generation == 1);
  assert(memcmp(decoded.nonce, kNonce, 16) == 0);
  assert(memcmp(decoded.bitmap, kBitmap, 16) == 0);
  assert(decoded.present_count == 2);
  assert(memcmp(decoded.body_digest, kBodyDigest, 32) == 0);
  assert(memcmp(decoded.tag, kTag, 32) == 0);

  auth_replica_slot_t slot0 = {0};
  assert(auth_replica_slot_decode(body + AUTH_REPLICA_ROOT_REGION_SIZE, 0,
                                  &slot0) == AUTH_REPLICA_OK);
  assert(slot0.present);
  assert(slot0.record_len == AUTH_REPLICA_SLOT_RECORD_MAX);
  for (size_t i = 0; i < slot0.record_len; i++) assert(slot0.record[i] == 0x11);

  auth_replica_slot_t slot99 = {0};
  assert(auth_replica_slot_decode(
             body + AUTH_REPLICA_ROOT_REGION_SIZE + 99 * AUTH_REPLICA_SLOT_SIZE,
             99, &slot99) == AUTH_REPLICA_OK);
  assert(slot99.present);
  assert(slot99.record_len == sizeof(kRec99));
  assert(memcmp(slot99.record, kRec99, sizeof(kRec99)) == 0);

  auth_replica_slot_t slot1 = {0};
  assert(auth_replica_slot_decode(
             body + AUTH_REPLICA_ROOT_REGION_SIZE + 1 * AUTH_REPLICA_SLOT_SIZE,
             1, &slot1) == AUTH_REPLICA_OK);
  assert(!slot1.present);
  assert(slot1.record_len == 0);

  // Exact size and headroom accounting from the plan's locked layout.
  assert(AUTH_REPLICA_USED_SIZE == 57824);
  assert(AUTH_REPLICA_HEADROOM == 7712);
  assert(AUTH_REPLICA_USED_SIZE + AUTH_REPLICA_HEADROOM ==
        AUTH_REPLICA_AREA_SIZE);
}

static void test_absent_slot_is_all_zero_regardless_of_index(void) {
  auth_replica_slot_t slot = {0};
  slot.present = false;
  slot.record_len = 500;  // must be ignored when present == false
  memset(slot.record, 0x77, sizeof(slot.record));
  for (uint8_t index = 0; index < AUTH_REPLICA_SLOT_COUNT; index += 37) {
    memset(slot_buf, 0xff, sizeof(slot_buf));
    assert(auth_replica_slot_encode(slot_buf, index, &slot) == AUTH_REPLICA_OK);
    for (size_t i = 0; i < AUTH_REPLICA_SLOT_SIZE; i++)
      assert(slot_buf[i] == 0);
  }
}

static void test_header_encode_rejects_bad_present_count(void) {
  auth_replica_header_t header = {0};
  header.generation = 1;
  memcpy(header.bitmap, kBitmap, sizeof(kBitmap));  // 2 bits set
  header.present_count = 3;                        // wrong on purpose
  assert(auth_replica_header_encode(header_buf, &header) == AUTH_REPLICA_BOUNDS);
}

static void test_header_encode_rejects_high_bitmap_bits(void) {
  auth_replica_header_t header = {0};
  header.generation = 1;
  header.bitmap[15] = 0x80;  // bit 127, beyond the 100 valid slots
  header.present_count = 0;
  assert(auth_replica_header_encode(header_buf, &header) ==
        AUTH_REPLICA_NONCANONICAL);
}

static void test_header_encode_rejects_zero_generation(void) {
  auth_replica_header_t header = {0};
  header.generation = 0;
  assert(auth_replica_header_encode(header_buf, &header) ==
        AUTH_REPLICA_NONCANONICAL);
}

// --- Negative decode tests: every way a buffer can be malformed ------------

static void reset_reference_header(uint8_t out[AUTH_REPLICA_HEADER_SIZE]) {
  auth_replica_header_t header = {0};
  header.generation = 1;
  memcpy(header.nonce, kNonce, sizeof(kNonce));
  memcpy(header.bitmap, kBitmap, sizeof(kBitmap));
  header.present_count = 2;
  memcpy(header.body_digest, kBodyDigest, sizeof(kBodyDigest));
  memcpy(header.tag, kTag, sizeof(kTag));
  assert(auth_replica_header_encode(out, &header) == AUTH_REPLICA_OK);
}

static void assert_decode_fails_and_zeroizes(
    const uint8_t buf[AUTH_REPLICA_HEADER_SIZE],
    auth_replica_format_result expected) {
  auth_replica_header_t decoded;
  memset(&decoded, 0x5a, sizeof(decoded));  // poison, must be cleared on fail
  assert(auth_replica_header_decode(buf, &decoded) == expected);
  static const auth_replica_header_t zero = {0};
  assert(memcmp(&decoded, &zero, sizeof(zero)) == 0);
}

static void test_header_decode_rejects_every_tampered_field(void) {
  uint8_t buf[AUTH_REPLICA_HEADER_SIZE];

  // Magic byte flipped.
  reset_reference_header(buf);
  buf[0] ^= 0x01;
  assert_decode_fails_and_zeroizes(buf, AUTH_REPLICA_VERSION);

  // Version field wrong.
  reset_reference_header(buf);
  buf[8] = 2;
  assert_decode_fails_and_zeroizes(buf, AUTH_REPLICA_VERSION);

  // Header size field wrong.
  reset_reference_header(buf);
  buf[10] = 0;
  assert_decode_fails_and_zeroizes(buf, AUTH_REPLICA_BOUNDS);

  // Used size field wrong.
  reset_reference_header(buf);
  buf[12] ^= 0x01;
  assert_decode_fails_and_zeroizes(buf, AUTH_REPLICA_BOUNDS);

  // Generation == 0.
  reset_reference_header(buf);
  memset(buf + 16, 0, 8);
  assert_decode_fails_and_zeroizes(buf, AUTH_REPLICA_NONCANONICAL);

  // Namespace wrong.
  reset_reference_header(buf);
  buf[40] ^= 0x01;
  assert_decode_fails_and_zeroizes(buf, AUTH_REPLICA_BOUNDS);

  // Flags nonzero.
  reset_reference_header(buf);
  buf[44] = 0x01;
  assert_decode_fails_and_zeroizes(buf, AUTH_REPLICA_NONCANONICAL);

  // Bitmap set beyond slot 99 (bit 127, byte 15 top bit).
  reset_reference_header(buf);
  buf[63] |= 0x80;
  assert_decode_fails_and_zeroizes(buf, AUTH_REPLICA_NONCANONICAL);

  // Root length field wrong.
  reset_reference_header(buf);
  buf[64] = 63;
  assert_decode_fails_and_zeroizes(buf, AUTH_REPLICA_BOUNDS);

  // Present count mismatched with bitmap popcount.
  reset_reference_header(buf);
  buf[66] = 3;
  assert_decode_fails_and_zeroizes(buf, AUTH_REPLICA_NONCANONICAL);

  // Body length field wrong.
  reset_reference_header(buf);
  buf[68] ^= 0x01;
  assert_decode_fails_and_zeroizes(buf, AUTH_REPLICA_BOUNDS);

  // Reserved byte set (byte 104, first of the 24 reserved bytes).
  reset_reference_header(buf);
  buf[104] = 0x01;
  assert_decode_fails_and_zeroizes(buf, AUTH_REPLICA_NONCANONICAL);

  // Reserved byte set (byte 127, last of the 24 reserved bytes).
  reset_reference_header(buf);
  buf[127] = 0x01;
  assert_decode_fails_and_zeroizes(buf, AUTH_REPLICA_NONCANONICAL);

  // Digest or tag altered: these decode successfully (they are opaque
  // 32-byte fields to this codec) but must no longer match the independent
  // vector, proving the codec does not silently "fix" tampered auth fields.
  reset_reference_header(buf);
  buf[72] ^= 0x01;  // body_digest byte
  auth_replica_header_t decoded = {0};
  assert(auth_replica_header_decode(buf, &decoded) == AUTH_REPLICA_OK);
  assert(memcmp(decoded.body_digest, kBodyDigest, 32) != 0);

  reset_reference_header(buf);
  buf[128] ^= 0x01;  // tag byte
  memset(&decoded, 0, sizeof(decoded));
  assert(auth_replica_header_decode(buf, &decoded) == AUTH_REPLICA_OK);
  assert(memcmp(decoded.tag, kTag, 32) != 0);
  assert(auth_replica_verify_tag(decoded.tag, kTag) == AUTH_REPLICA_AUTH_FAILED);

  // Truncated buffer (NULL) is rejected without dereferencing.
  memset(&decoded, 0x5a, sizeof(decoded));
  assert(auth_replica_header_decode(NULL, &decoded) == AUTH_REPLICA_BOUNDS);
  static const auth_replica_header_t zero = {0};
  assert(memcmp(&decoded, &zero, sizeof(zero)) == 0);
}

static void test_slot_decode_rejects_every_tampered_field(void) {
  auth_replica_slot_t slot = {0};
  slot.present = true;
  slot.record_len = 10;
  memset(slot.record, 0x42, 10);

  uint8_t buf[AUTH_REPLICA_SLOT_SIZE];
  assert(auth_replica_slot_encode(buf, 5, &slot) == AUTH_REPLICA_OK);

  auth_replica_slot_t decoded;

  // Baseline: decodes fine at the correct index.
  memset(&decoded, 0x5a, sizeof(decoded));
  assert(auth_replica_slot_decode(buf, 5, &decoded) == AUTH_REPLICA_OK);
  assert(decoded.present && decoded.record_len == 10);

  // Slot index does not match physical position.
  memset(&decoded, 0x5a, sizeof(decoded));
  assert(auth_replica_slot_decode(buf, 6, &decoded) == AUTH_REPLICA_NONCANONICAL);
  static const auth_replica_slot_t zero_slot = {0};
  assert(memcmp(&decoded, &zero_slot, sizeof(zero_slot)) == 0);

  // Record length 0 is invalid for a present slot.
  {
    uint8_t bad[AUTH_REPLICA_SLOT_SIZE];
    memcpy(bad, buf, sizeof(bad));
    bad[2] = 0;
    bad[3] = 0;
    memset(&decoded, 0x5a, sizeof(decoded));
    assert(auth_replica_slot_decode(bad, 5, &decoded) == AUTH_REPLICA_BOUNDS);
    assert(memcmp(&decoded, &zero_slot, sizeof(zero_slot)) == 0);
  }

  // Record length one past the maximum (557) is rejected.
  {
    slot.record_len = AUTH_REPLICA_SLOT_RECORD_MAX;
    memset(slot.record, 0x55, slot.record_len);
    uint8_t maxed[AUTH_REPLICA_SLOT_SIZE];
    assert(auth_replica_slot_encode(maxed, 7, &slot) == AUTH_REPLICA_OK);
    maxed[2] = (uint8_t)(557);
    maxed[3] = (uint8_t)(557 >> 8);
    memset(&decoded, 0x5a, sizeof(decoded));
    assert(auth_replica_slot_decode(maxed, 7, &decoded) == AUTH_REPLICA_BOUNDS);
    assert(memcmp(&decoded, &zero_slot, sizeof(zero_slot)) == 0);
  }

  // Reserved byte in the slot header set.
  {
    uint8_t bad[AUTH_REPLICA_SLOT_SIZE];
    memcpy(bad, buf, sizeof(bad));
    bad[4] = 0x01;
    memset(&decoded, 0x5a, sizeof(decoded));
    assert(auth_replica_slot_decode(bad, 5, &decoded) == AUTH_REPLICA_NONCANONICAL);
    assert(memcmp(&decoded, &zero_slot, sizeof(zero_slot)) == 0);
  }

  // Present byte itself is neither 0 nor 1.
  {
    uint8_t bad[AUTH_REPLICA_SLOT_SIZE];
    memcpy(bad, buf, sizeof(bad));
    bad[0] = 2;
    memset(&decoded, 0x5a, sizeof(decoded));
    assert(auth_replica_slot_decode(bad, 5, &decoded) == AUTH_REPLICA_NONCANONICAL);
    assert(memcmp(&decoded, &zero_slot, sizeof(zero_slot)) == 0);
  }

  // Nonzero padding after the record (byte just past record_len).
  {
    uint8_t bad[AUTH_REPLICA_SLOT_SIZE];
    memcpy(bad, buf, sizeof(bad));
    bad[AUTH_REPLICA_SLOT_HEADER_SIZE + 10] = 0x01;  // first padding byte
    memset(&decoded, 0x5a, sizeof(decoded));
    assert(auth_replica_slot_decode(bad, 5, &decoded) == AUTH_REPLICA_NONCANONICAL);
    assert(memcmp(&decoded, &zero_slot, sizeof(zero_slot)) == 0);
  }

  // Nonzero padding at the very last byte of the slot.
  {
    uint8_t bad[AUTH_REPLICA_SLOT_SIZE];
    memcpy(bad, buf, sizeof(bad));
    bad[AUTH_REPLICA_SLOT_SIZE - 1] = 0x01;
    memset(&decoded, 0x5a, sizeof(decoded));
    assert(auth_replica_slot_decode(bad, 5, &decoded) == AUTH_REPLICA_NONCANONICAL);
    assert(memcmp(&decoded, &zero_slot, sizeof(zero_slot)) == 0);
  }

  // Absent slot (present == 0) with one stray nonzero byte elsewhere.
  {
    uint8_t bad[AUTH_REPLICA_SLOT_SIZE];
    memset(bad, 0, sizeof(bad));
    bad[300] = 0x01;
    memset(&decoded, 0x5a, sizeof(decoded));
    assert(auth_replica_slot_decode(bad, 9, &decoded) == AUTH_REPLICA_NONCANONICAL);
    assert(memcmp(&decoded, &zero_slot, sizeof(zero_slot)) == 0);
  }

  // Out-of-range index (>= 100) is rejected regardless of buffer contents.
  {
    memset(&decoded, 0x5a, sizeof(decoded));
    assert(auth_replica_slot_decode(buf, 100, &decoded) == AUTH_REPLICA_BOUNDS);
    assert(memcmp(&decoded, &zero_slot, sizeof(zero_slot)) == 0);
  }

  // NULL buffer is rejected without dereferencing.
  {
    memset(&decoded, 0x5a, sizeof(decoded));
    assert(auth_replica_slot_decode(NULL, 5, &decoded) == AUTH_REPLICA_BOUNDS);
    assert(memcmp(&decoded, &zero_slot, sizeof(zero_slot)) == 0);
  }
}

static void test_slot_encode_rejects_invalid_record_length(void) {
  auth_replica_slot_t slot = {0};
  slot.present = true;
  slot.record_len = 0;
  uint8_t buf[AUTH_REPLICA_SLOT_SIZE];
  assert(auth_replica_slot_encode(buf, 0, &slot) == AUTH_REPLICA_BOUNDS);

  slot.record_len = AUTH_REPLICA_SLOT_RECORD_MAX + 1;
  assert(auth_replica_slot_encode(buf, 0, &slot) == AUTH_REPLICA_BOUNDS);
}

static void test_slot_encode_rejects_out_of_range_index(void) {
  auth_replica_slot_t slot = {0};
  uint8_t buf[AUTH_REPLICA_SLOT_SIZE];
  assert(auth_replica_slot_encode(buf, AUTH_REPLICA_SLOT_COUNT, &slot) ==
        AUTH_REPLICA_BOUNDS);
}

static void test_verify_tag_is_exact_and_order_independent_in_failure(void) {
  uint8_t a[32], b[32];
  memset(a, 0x11, 32);
  memset(b, 0x11, 32);
  assert(auth_replica_verify_tag(a, b) == AUTH_REPLICA_OK);
  b[31] ^= 0x01;
  assert(auth_replica_verify_tag(a, b) == AUTH_REPLICA_AUTH_FAILED);
  assert(auth_replica_verify_tag(b, a) == AUTH_REPLICA_AUTH_FAILED);
  assert(auth_replica_verify_tag(NULL, a) == AUTH_REPLICA_BOUNDS);
  assert(auth_replica_verify_tag(a, NULL) == AUTH_REPLICA_BOUNDS);
}

int main(void) {
  test_exact_encoding_matches_independent_vector();
  test_absent_slot_is_all_zero_regardless_of_index();
  test_header_encode_rejects_bad_present_count();
  test_header_encode_rejects_high_bitmap_bits();
  test_header_encode_rejects_zero_generation();
  test_header_decode_rejects_every_tampered_field();
  test_slot_decode_rejects_every_tampered_field();
  test_slot_encode_rejects_invalid_record_length();
  test_slot_encode_rejects_out_of_range_index();
  test_verify_tag_is_exact_and_order_independent_in_failure();
  return 0;
}
