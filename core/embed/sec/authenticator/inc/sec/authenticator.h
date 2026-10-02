#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
  AUTH_OK = 0,
  AUTH_UNPROVISIONED,
  AUTH_INVALID_ARGUMENT,
  AUTH_PIN_INVALID,
  AUTH_PIN_AUTH_BLOCKED,
  AUTH_PIN_BLOCKED,
  AUTH_DENIED,
  AUTH_ERROR,
  AUTH_LIMIT_EXCEEDED,
  // The storage areas hold data that is not this authenticator's: legacy
  // wallet/NORCOW records, another application's records, or an unrecognized
  // layout. Nothing has been read, erased, or rewritten. Converting such a
  // device requires a separately approved destructive reformat.
  //
  // Appended deliberately: these values cross the MicroPython boundary as
  // plain integers, so existing ones must keep their numbering.
  AUTH_MIGRATION_REQUIRED,
  // A well-formed PIN that this authenticator's policy refuses, currently only
  // one shorter than AUTH_MIN_PIN_CODE_POINTS. Distinct from
  // AUTH_INVALID_ARGUMENT so the application can answer CTAP's
  // PIN_POLICY_VIOLATION instead of a generic parameter error: the platform can
  // fix a short PIN by asking for a longer one, and cannot fix a malformed
  // request at all.
  AUTH_PIN_POLICY,
  // Every resident slot holds a credential. Appended for the same reason as the
  // two above: these values cross the MicroPython boundary as plain integers.
  //
  // Distinct from AUTH_LIMIT_EXCEEDED, which says this one record is too large
  // for a slot. A smaller record would fit that; nothing fits a full store, and
  // CTAP has separate codes because a platform acts differently on each.
  AUTH_STORE_FULL,
} auth_result;

// Minimum PIN length in code points, not bytes. CTAP's floor is four; this
// project's is eight, chosen alongside the eight-attempt destruction limit --
// a short PIN plus a small attempt budget is a guessable PIN.
#define AUTH_MIN_PIN_CODE_POINTS 8

typedef struct {
  auth_result state;
  uint8_t retries;
  uint8_t consecutive;
} auth_status;

auth_result auth_vault_init(void);
auth_status auth_vault_status(void);
auth_result auth_vault_provision(const uint8_t *pin, size_t pin_len);
auth_result auth_vault_change_pin(const uint8_t *old_pin, size_t old_len,
                                  const uint8_t *new_pin, size_t new_len);
// Public P-256 key only. Private key and protocol ECDH/KDF stay native.
auth_result auth_vault_key_agreement(uint8_t *public_key, size_t len);
// Recovers the CTAP pinUvAuth hash from platform ciphertext and, if it
// verifies, issues an encrypted pinUvAuthToken.
//
// `pin_hash_enc` is LEFT(SHA-256(pin), 16) encrypted under the shared secret:
// 16 bytes on protocol 1, which uses a zero IV, and 32 on protocol 2, which
// prepends a random one. It arrives encrypted rather than in the clear because
// the shared secret is derived here and nowhere else; a caller that could
// decrypt it would, by construction, be a caller holding both the secret and
// the user's PIN hash.
auth_result auth_vault_issue_token(const uint8_t *pin_hash_enc,
                                   size_t pin_hash_enc_len, uint8_t protocol,
                                   uint8_t permissions, const uint8_t *rp,
                                   size_t rp_len, const uint8_t *peer_key,
                                   size_t peer_len, uint8_t *encrypted,
                                   size_t capacity, size_t *written);
// Sets the first PIN from what CTAP setPIN delivers: the UTF-8 PIN zero-padded
// to 64 bytes and encrypted under the shared secret, so 64 bytes on protocol 1
// and 80 on protocol 2, plus `param`, the MAC CTAP computes over that
// ciphertext under the shared secret -- 16 bytes on protocol 1, 32 on
// protocol 2.
//
// The MAC is verified before anything is decrypted, so a caller who does not
// hold the shared secret never causes a PIN to be recovered. Then the padding,
// the encoding and the length are validated and LEFT(SHA-256(pin), 16) is
// provisioned.
//
// Refuses when a PIN already exists. Replacing one is not supported here or in
// auth_vault_change_pin(); the supported transition is an explicit wipe.
auth_result auth_vault_set_pin(uint8_t protocol, const uint8_t *new_pin_enc,
                               size_t new_pin_enc_len, const uint8_t *param,
                               size_t param_len, const uint8_t *peer_key,
                               size_t peer_len);
auth_result auth_vault_check_auth(uint8_t protocol, const uint8_t *message,
                                  size_t message_len, const uint8_t *param,
                                  size_t param_len, uint8_t permissions,
                                  const uint8_t *rp, size_t rp_len);
auth_result auth_vault_disconnect(void);
// Erase transient keys/token while preserving the reconnect-only soft block.
auth_result auth_vault_clear_session(void);
auth_result auth_vault_wipe(void);

#define AUTH_CREDENTIAL_ID_MAX 704
#define AUTH_METADATA_MAX 640
#define AUTH_COSE_MAX 77
#define AUTH_RESIDENT_CAPACITY 100
// Passed as the index to auth_resident_set to mean "choose a free slot".
//
// Why the vault chooses rather than the caller. The caller used to look for a
// free slot by being turned down for the taken ones, which cannot work: a
// refusal leaves through the vault's fail-closed exit, which invalidates the
// session, so the search got exactly one attempt and a device with ninety-nine
// free slots reported that it was full. Only the vault can see every slot -- a
// session bound to one relying party is deliberately told nothing about
// another's -- so only the vault can pick. It does not report which slot it
// used, because nothing above needs to know.
#define AUTH_RESIDENT_ANY AUTH_RESIDENT_CAPACITY
// Resident format v1 aggregate cap: 448 metadata + 68 envelope = 516 ID bytes.
// Nonresident credentials retain the individual protocol field bounds above.
#define AUTH_RESIDENT_METADATA_MAX 448
#define AUTH_RESIDENT_ID_MAX (AUTH_RESIDENT_METADATA_MAX + 68)
// Authenticated public outputs only. Never contains seed/scalar/hmac key.
typedef struct {
  uint8_t id[AUTH_CREDENTIAL_ID_MAX], metadata[AUTH_METADATA_MAX];
  uint8_t cose[AUTH_COSE_MAX], rp[32];
  size_t id_len, metadata_len, cose_len;
  int32_t algorithm;
} auth_credential_public;
auth_result auth_credential_create(const uint8_t rp[32], int32_t algorithm,
                                   const uint8_t *metadata, size_t metadata_len,
                                   auth_credential_public *out);
auth_result auth_credential_open(const uint8_t *id, size_t id_len,
                                 const uint8_t rp[32],
                                 auth_credential_public *out);
// Signs `message` with the credential's own key. CTAP asks a credential for a
// signature in exactly two places, and the vault cannot tell them apart by their
// bytes: the assertion a relying party asked for, and the self-attestation that
// proves a newly created credential came from this device. So the caller names
// which it is doing, and each is authorized by the permission CTAP gives that
// operation -- ga for an assertion, mc for an attestation. Naming the operation
// is no more trust than naming the credential and the relying party, which the
// caller already does.
auth_result auth_credential_sign(const uint8_t *id, size_t id_len,
                                 const uint8_t rp[32], int32_t algorithm,
                                 const uint8_t *message, size_t message_len,
                                 bool attesting, uint8_t signature[72],
                                 size_t *written);
auth_result auth_credential_hmac_secret(const uint8_t *id, size_t id_len,
                                        const uint8_t rp[32],
                                        const uint8_t *salts, size_t salts_len,
                                        uint8_t out[64]);
auth_result auth_resident_get(uint8_t index, auth_credential_public *out);
auth_result auth_resident_set(uint8_t index, const uint8_t *id, size_t id_len,
                              const uint8_t rp[32]);
auth_result auth_resident_delete(uint8_t index);

// Presented once per slot, in index order, by the walking reads that the
// storage layers below expose. `status` is AUTH_OK with a decoded record, or
// AUTH_UNPROVISIONED for a canonically empty slot, or a failure -- in which
// case `record` is NULL. Returning false ends the walk.
//
// Declared here, in the vocabulary header every storage layer already includes,
// so the same signature serves the replica manager, the record layer, the store
// adapter and the backend without any of them inventing its own.
typedef bool (*auth_slot_visitor)(void *context, uint8_t index,
                                  auth_result status, const uint8_t *record,
                                  uint16_t length);

// Reports which slots hold a record, in one authenticated pass.
//
// `rp` is an optional filter: NULL reports every slot this session is allowed
// to see, and a 32-byte relying-party hash reports only that party's slots. The
// filter exists so a discovery never has to ask about slots it has no business
// knowing, and so the answer stays AUTH_RESIDENT_CAPACITY bytes rather than a
// hundred records.
//
// `out[i]` is 1 for a slot holding a record this session may see and 0
// otherwise. A slot whose bytes do not decode fails the whole call: corruption
// must not be reported as an empty slot. The credential envelope inside a
// record is deliberately NOT opened -- occupancy and relying-party binding come
// from the record itself, which the snapshot MAC authenticates, so opening it
// would buy nothing and cost a scalar multiplication per slot.
auth_result auth_resident_scan(const uint8_t rp[32],
                               uint8_t out[AUTH_RESIDENT_CAPACITY]);
