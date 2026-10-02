#pragma once
// Canonical, authenticated on-flash snapshot format for the triple-replica
// power-loss recovery vault. This module is a
// pure codec: it has no knowledge of flash, PIN, root secrets, or OPTIGA. It
// only packs/unpacks fixed-width little-endian bytes and provides a thin
// streaming HMAC-SHA256 wrapper. Authentication (matching a computed tag
// against the decoded one) and body-digest recomputation are composed by the
// caller (the replica manager) using the primitives below; this file
// never treats a structurally valid buffer as trusted.
//
// Wire layout (all offsets in bytes, all multi-byte integers little-endian):
//
//   Header (AUTH_REPLICA_HEADER_SIZE == 160 bytes):
//     0..7    magic "TSAUTHR1"
//     8..9    format version (== AUTH_REPLICA_FORMAT_VERSION)
//     10..11  header size (== AUTH_REPLICA_HEADER_SIZE)
//     12..15  used size (== AUTH_REPLICA_USED_SIZE)
//     16..23  generation (u64)
//     24..39  snapshot nonce (16 bytes)
//     40..43  namespace (== AUTH_REPLICA_NAMESPACE)
//     44..47  flags (must be 0)
//     48..63  100-slot presence bitmap (16 bytes, LSB-first, bits 100..127
//             unused and must be 0)
//     64..65  root length (== AUTH_REPLICA_ROOT_LENGTH)
//     66..67  present-slot count (must equal popcount(bitmap))
//     68..71  body length (== AUTH_REPLICA_BODY_SIZE)
//     72..103 canonical body digest (SHA-256 over the body, 32 bytes)
//     104..127 reserved, must be 0
//     128..159 snapshot HMAC-SHA256 tag (32 bytes)
//
//     The tag authenticates bytes 0..127 of the header (see
//     AUTH_REPLICA_HEADER_MAC_SIZE) followed by the complete body.
//
//   Root region (AUTH_REPLICA_ROOT_REGION_SIZE == 64 bytes): the 62-byte
//   wrapped root envelope (AUTH_RECORD_SIZE) followed by 2 zero bytes.
//
//   100 slot regions (AUTH_REPLICA_SLOT_SIZE == 576 bytes each):
//     0       present (0 or 1)
//     1       slot index (must equal the slot's physical position)
//     2..3    record length (u16, 1..AUTH_REPLICA_SLOT_RECORD_MAX)
//     4..15   reserved, must be 0
//     16..    record bytes (record_len bytes), then zero padding to the end
//             of the 560-byte body
//     An absent slot (present == 0) is entirely zero, including the index
//     byte: presence, not physical position, is what makes a slot canonical.
//
// AUTH_REPLICA_USED_SIZE bytes of each 65536-byte area are occupied; the
// remaining AUTH_REPLICA_HEADROOM bytes are never written by this format.

#include <sec/authenticator.h>  // AUTH_RESIDENT_ID_MAX, AUTH_RESIDENT_METADATA_MAX
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "authenticator_backend.h"  // AUTH_RECORD_SIZE
#include "hmac.h"

// ---------------------------------------------------------------------------
// Format constants. Every numeric value here is pinned by a _Static_assert
// in replica_format.c; nothing in this header is expected to change without
// a new format version.
// ---------------------------------------------------------------------------

#define AUTH_REPLICA_FORMAT_VERSION 1u

#define AUTH_REPLICA_MAGIC_SIZE 8
extern const uint8_t AUTH_REPLICA_MAGIC[AUTH_REPLICA_MAGIC_SIZE];

#define AUTH_REPLICA_HEADER_SIZE 160u
// Bytes 0..127: everything the tag authenticates except the tag itself.
#define AUTH_REPLICA_HEADER_MAC_SIZE 128u

#define AUTH_REPLICA_NONCE_SIZE 16
#define AUTH_REPLICA_BITMAP_SIZE 16
#define AUTH_REPLICA_DIGEST_SIZE 32
#define AUTH_REPLICA_TAG_SIZE 32

#define AUTH_REPLICA_NAMESPACE 0x0000003fu

#define AUTH_REPLICA_ROOT_REGION_SIZE 64u
#define AUTH_REPLICA_ROOT_LENGTH AUTH_RECORD_SIZE  // 62

#define AUTH_REPLICA_SLOT_COUNT 100u
#define AUTH_REPLICA_SLOT_HEADER_SIZE 16u
#define AUTH_REPLICA_SLOT_BODY_SIZE 560u
#define AUTH_REPLICA_SLOT_SIZE \
  (AUTH_REPLICA_SLOT_HEADER_SIZE + AUTH_REPLICA_SLOT_BODY_SIZE)  // 576
// Maximum meaningful record bytes inside one slot body: existing resident
// id/binding aggregate cap, unrelated to and independent of this codec.
#define AUTH_REPLICA_SLOT_RECORD_MAX (AUTH_RESIDENT_ID_MAX + 40)  // 556

#define AUTH_REPLICA_BODY_SIZE                                        \
  (AUTH_REPLICA_ROOT_REGION_SIZE +                                     \
   AUTH_REPLICA_SLOT_COUNT * AUTH_REPLICA_SLOT_SIZE)  // 57664
#define AUTH_REPLICA_USED_SIZE \
  (AUTH_REPLICA_HEADER_SIZE + AUTH_REPLICA_BODY_SIZE)  // 57824

#define AUTH_REPLICA_AREA_SIZE 65536u
#define AUTH_REPLICA_HEADROOM \
  (AUTH_REPLICA_AREA_SIZE - AUTH_REPLICA_USED_SIZE)  // 7712

// Conservative erase-cycle ceiling, shared with the replica manager. It lives
// beside the wire-format constants because the generation counter it bounds is
// a wire-format field. This codec only pins the value; enforcing a wear policy
// is the manager's job.
#define AUTH_REPLICA_MAX_GENERATION 12000ull

// ---------------------------------------------------------------------------
// Result codes
// ---------------------------------------------------------------------------

typedef enum {
  AUTH_REPLICA_OK = 0,
  // Magic or version byte does not identify a snapshot of this format.
  AUTH_REPLICA_VERSION,
  // A fixed-size/length field does not equal its required constant, or a
  // count/index is outside its valid range.
  AUTH_REPLICA_BOUNDS,
  // A reserved/padding byte is nonzero, or a self-consistency invariant
  // (bitmap vs. present_count, slot index vs. physical position, absent
  // slot not fully zero) does not hold.
  AUTH_REPLICA_NONCANONICAL,
  // A supplied MAC did not match the recomputed one.
  AUTH_REPLICA_AUTH_FAILED,
} auth_replica_format_result;

// ---------------------------------------------------------------------------
// In-memory decoded representations. These are plain structs used only to
// pass already-unpacked values between the codec and its caller; they are
// never memcpy'd onto or from the wire buffer directly.
// ---------------------------------------------------------------------------

typedef struct {
  uint64_t generation;
  uint8_t nonce[AUTH_REPLICA_NONCE_SIZE];
  uint8_t bitmap[AUTH_REPLICA_BITMAP_SIZE];
  uint16_t present_count;
  uint8_t body_digest[AUTH_REPLICA_DIGEST_SIZE];
  uint8_t tag[AUTH_REPLICA_TAG_SIZE];
} auth_replica_header_t;

typedef struct {
  bool present;
  uint16_t record_len;
  uint8_t record[AUTH_REPLICA_SLOT_RECORD_MAX];
} auth_replica_slot_t;

// ---------------------------------------------------------------------------
// Header codec
// ---------------------------------------------------------------------------

// Encodes `header` into the fixed AUTH_REPLICA_HEADER_SIZE-byte buffer
// `out`. Fails with AUTH_REPLICA_BOUNDS if present_count > slot count or
// doesn't match popcount(bitmap), or if any bit above slot 99 is set;
// AUTH_REPLICA_NONCANONICAL if generation == 0.
auth_replica_format_result auth_replica_header_encode(
    uint8_t out[AUTH_REPLICA_HEADER_SIZE], const auth_replica_header_t *header);

// Decodes and structurally validates `in` into `header`. Only checks fields
// this codec can judge without the body (magic/version/fixed sizes/
// namespace/flags/reserved bytes/bitmap-vs-count/generation != 0). Does not
// and cannot verify the tag or body digest: that requires the body, which
// the caller streams separately via auth_replica_mac_update(). On any
// failure, `*header` is fully zeroized and the function returns a nonzero
// result.
auth_replica_format_result auth_replica_header_decode(
    const uint8_t in[AUTH_REPLICA_HEADER_SIZE], auth_replica_header_t *header);

// ---------------------------------------------------------------------------
// Slot codec
// ---------------------------------------------------------------------------

// Encodes one slot at physical position `index` (0..99) into the fixed
// AUTH_REPLICA_SLOT_SIZE-byte buffer `out`. If slot->present is false, the
// entire output is zero regardless of `index` or slot->record_len. If true,
// requires 1 <= slot->record_len <= AUTH_REPLICA_SLOT_RECORD_MAX.
auth_replica_format_result auth_replica_slot_encode(
    uint8_t out[AUTH_REPLICA_SLOT_SIZE], uint8_t index,
    const auth_replica_slot_t *slot);

// Decodes and structurally validates the slot in `in`, which must occupy
// physical position `index` (0..99). Rejects a present slot whose encoded
// index byte does not equal `index`, a record length of 0 or greater than
// AUTH_REPLICA_SLOT_RECORD_MAX, a nonzero reserved byte, nonzero padding
// after the record, or (for an absent slot) any nonzero byte anywhere in
// the 576-byte region. On any failure, `*slot` is fully zeroized.
auth_replica_format_result auth_replica_slot_decode(
    const uint8_t in[AUTH_REPLICA_SLOT_SIZE], uint8_t index,
    auth_replica_slot_t *slot);

// ---------------------------------------------------------------------------
// Streaming snapshot MAC (HMAC-SHA256), keyed by a caller-derived 32-byte
// key. This module performs no key derivation: the caller is responsible
// for deriving the key (e.g. via HKDF from the vault root) before calling
// auth_replica_mac_init(). To authenticate a full snapshot, the caller
// feeds, in order: the first AUTH_REPLICA_HEADER_MAC_SIZE bytes of the
// encoded header (the tag field itself is excluded, not zeroed-in-place),
// then the AUTH_REPLICA_ROOT_REGION_SIZE-byte root region, then each of the
// 100 AUTH_REPLICA_SLOT_SIZE-byte slot regions in physical order.
// ---------------------------------------------------------------------------

typedef struct {
  HMAC_SHA256_CTX ctx;
} auth_replica_mac_ctx_t;

void auth_replica_mac_init(auth_replica_mac_ctx_t *mac,
                           const uint8_t key[32]);
void auth_replica_mac_update(auth_replica_mac_ctx_t *mac, const uint8_t *data,
                             size_t len);
// Writes the final 32-byte tag to `tag` and zeroizes `*mac`.
void auth_replica_mac_final(auth_replica_mac_ctx_t *mac, uint8_t tag[32]);

// Constant-time comparison of two 32-byte authenticated values. Used by the
// caller both to compare a freshly computed SHA-256 body digest against the
// header's decoded body_digest, and to compare a freshly computed
// auth_replica_mac_final() tag against the header's decoded tag. This is the
// only producer of AUTH_REPLICA_AUTH_FAILED in this module: header/slot
// decode can prove a buffer is *canonical*, never that it is *authentic*.
auth_replica_format_result auth_replica_verify_tag(const uint8_t computed[32],
                                                   const uint8_t expected[32]);
