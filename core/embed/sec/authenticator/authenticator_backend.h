#pragma once
#include <sec/authenticator.h>
#include <stdbool.h>

#define AUTH_RECORD_SIZE 62
// Number of root-envelope candidates a backend may return. Equal to the replica
// count, asserted in each backend rather than by including the replica headers
// here: replica_format.h consumes AUTH_RECORD_SIZE from this file, so including
// it back would be circular.
#define AUTH_BACKEND_ROOT_CANDIDATES 3
// Backend is private to the native vault; none of these methods are bindings.
bool auth_backend_init(void);
// Root-envelope discovery. A power cut during a root commit can leave replicas
// carrying different envelopes -- they differ only in the AEAD nonce, not in
// the secret -- so the vault is handed every deduplicated candidate rather than
// "the" envelope. `*count` is 0 when the device is unprovisioned.
auth_result auth_backend_root_candidates(
    uint8_t out[AUTH_BACKEND_ROOT_CANDIDATES][AUTH_RECORD_SIZE],
    uint8_t *count);
// Recovers the root from those candidates under the PIN-derived `kek` and
// selects the stored snapshot. The KEK goes in and only the root comes out; no
// root-derived key is retained past the call.
auth_result auth_backend_unlock(const uint8_t kek[32], uint8_t root_out[32]);
// Stores a re-wrapped root envelope. `root` is the in-session root, needed
// because the envelope lands inside an authenticated snapshot.
bool auth_backend_write(const uint8_t root[32],
                        const uint8_t record[AUTH_RECORD_SIZE]);
bool auth_backend_wipe(void);
bool auth_backend_random(uint8_t *out, size_t len);
bool auth_backend_remaining(uint8_t *remaining);
auth_result auth_backend_set_pin(const uint8_t verifier[32],
                                 uint8_t output[32]);
auth_result auth_backend_verify_pin(const uint8_t verifier[32],
                                    uint8_t output[32]);
bool auth_backend_zeroized(const void *buffer, size_t len);
// Kernel-private fixed resident record access; no generic storage syscall.
//
// The `bool commit` parameter these used to carry is gone. It selected between
// a record and the separate 40-byte tag that authenticated it and marked it
// committed; the snapshot MAC now does both for the whole vault at once. In
// exchange every call takes the in-session root, which is what the snapshot MAC
// is keyed from.
#define AUTH_RESIDENT_RECORD_MAX (AUTH_RESIDENT_ID_MAX + 40)
auth_result auth_backend_slot_read(const uint8_t root[32], uint8_t index,
                                   uint8_t *out, uint16_t capacity,
                                   uint16_t *length);
bool auth_backend_slot_write(const uint8_t root[32], uint8_t index,
                             const uint8_t *record, uint16_t length);
bool auth_backend_slot_delete(const uint8_t root[32], uint8_t index);
auth_result auth_backend_slot_capacity(uint8_t index, uint16_t id_len);
// Presents every slot to `visitor`, authenticating the stored snapshot once for
// the whole walk rather than once per slot. This is the difference between an
// enumerating command costing one snapshot authentication and a hundred.
auth_result auth_backend_slot_walk(const uint8_t root[32],
                                   auth_slot_visitor visitor, void *context);
