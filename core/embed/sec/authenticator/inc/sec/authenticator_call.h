#pragma once
#include <sec/authenticator.h>
#include <stdbool.h>

// Application-owned request descriptors: secure verifier snapshots once.
typedef struct {
  // `pin` is the CTAP pinUvAuth hash encrypted under the shared secret, so its
  // length follows the protocol: 16 bytes for 1, 32 for 2 with its leading IV.
  // It never crosses this boundary in the clear -- only the vault can decrypt
  // it.
  const uint8_t *pin, *rp, *peer;
  size_t pin_len, rp_len, peer_len;
  uint8_t protocol, permissions;
  uint8_t *encrypted;
  size_t capacity, *written;
} auth_token_request;
// Setting the first PIN. `new_pin` is the UTF-8 PIN zero-padded to 64 bytes and
// encrypted under the shared secret: 64 bytes on protocol 1, 80 on protocol 2.
// There is no output, so no writable range and nothing to check for aliasing.
typedef struct {
  // `param` is CTAP's MAC over `new_pin`, computed under the shared secret: 16
  // bytes on protocol 1, 32 on protocol 2.
  const uint8_t *new_pin, *param, *peer;
  size_t new_pin_len, param_len, peer_len;
  uint8_t protocol;
} auth_set_pin_request;
typedef struct {
  const uint8_t *message, *param, *rp;
  size_t message_len, param_len, rp_len;
  uint8_t protocol, permissions;
} auth_mac_request;

typedef bool (*auth_read_probe)(const void *, size_t);
typedef bool (*auth_write_probe)(void *, size_t);
auth_result auth_call_provision(const uint8_t *pin, size_t len,
                                auth_read_probe read);
auth_result auth_call_change(const uint8_t *old_pin, size_t old_len,
                             const uint8_t *new_pin, size_t new_len,
                             auth_read_probe read);
auth_result auth_call_public(uint8_t *out, size_t len, auth_write_probe write);
auth_result auth_call_status(auth_status *out, auth_write_probe write);
auth_result auth_call_issue(const auth_token_request *request,
                            auth_read_probe read, auth_write_probe write);
auth_result auth_call_set_pin(const auth_set_pin_request *request,
                              auth_read_probe read);
auth_result auth_call_check(const auth_mac_request *request,
                            auth_read_probe read);

typedef struct {
  const uint8_t *rp, *metadata;
  size_t metadata_len;
  int32_t algorithm;
  auth_credential_public *out;
} auth_create_request;
typedef struct {
  const uint8_t *rp, *id;
  size_t id_len;
  auth_credential_public *out;
} auth_open_request;
typedef struct {
  const uint8_t *rp, *id, *message;
  size_t id_len, message_len;
  int32_t algorithm;
  // Which of CTAP's two credential signatures this is. Carried in the request
  // rather than as a second syscall, because it changes which permission the
  // vault requires and nothing else.
  bool attesting;
  uint8_t *out;
  size_t *written;
} auth_sign_request;
typedef struct {
  const uint8_t *rp, *id, *salts;
  size_t id_len, salts_len;
  uint8_t *out;
} auth_hmac_request;
auth_result auth_call_credential_create(const auth_create_request *,
                                        auth_read_probe, auth_write_probe);
auth_result auth_call_credential_open(const auth_open_request *,
                                      auth_read_probe, auth_write_probe);
auth_result auth_call_credential_sign(const auth_sign_request *,
                                      auth_read_probe, auth_write_probe);
auth_result auth_call_credential_hmac(const auth_hmac_request *,
                                      auth_read_probe, auth_write_probe);
auth_result auth_call_resident_get(uint8_t, auth_credential_public *,
                                   auth_write_probe);
auth_result auth_call_resident_set(uint8_t, const auth_open_request *,
                                   auth_read_probe);
auth_result auth_call_resident_delete(uint8_t);
auth_result auth_call_resident_scan(const uint8_t *rp, uint8_t *out,
                                    auth_read_probe read,
                                    auth_write_probe write);
