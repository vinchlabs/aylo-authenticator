#include <assert.h>
#include <sec/authenticator_call.h>
#include <stdint.h>
#include <string.h>
#include "ecdsa.h"
#include "nist256p1.h"
#include "sha2.h"
static void credential_calls(void);
static void set_pin_calls(void);
#include "test_backend.h"
#include "test_pin_protocol_host.h"

static struct {
  const void *address;
  size_t len;
} ranges[20];
static size_t range_count;
static bool allowed(const void *address, size_t len) {
  uintptr_t start = (uintptr_t)address;
  if (!address || start > UINTPTR_MAX - len) return false;
  for (size_t i = 0; i < range_count; i++) {
    uintptr_t lower = (uintptr_t)ranges[i].address;
    if (start >= lower && len <= ranges[i].len &&
        start - lower <= ranges[i].len - len)
      return true;
  }
  return false;
}
static bool writable(void *address, size_t len) {
  return allowed(address, len);
}
static void grant(const void *address, size_t len) {
  ranges[range_count].address = address;
  ranges[range_count++].len = len;
}
void test_authenticator_call(void) {
  uint8_t pin[16] = {1}, rp[32] = {2}, peer[65] = {4}, encrypted[48] = {0};
  size_t written = 123;
  auth_token_request request = {.pin = pin,
                                .pin_len = 16,
                                .rp = rp,
                                .rp_len = 32,
                                .peer = peer,
                                .peer_len = 65,
                                .protocol = 1,
                                .permissions = 2,
                                .encrypted = encrypted,
                                .capacity = 48,
                                .written = &written};
  auth_test_reset();
  assert(auth_vault_init() == AUTH_OK);
  range_count = 0;
  assert(auth_call_provision((void *)1, 16, allowed) == AUTH_INVALID_ARGUMENT);
  grant(pin, 16);
  assert(auth_call_provision(pin, SIZE_MAX, allowed) == AUTH_INVALID_ARGUMENT);
  assert(auth_call_provision(pin, 16, allowed) == AUTH_OK);
  grant(&request, sizeof(request));
  grant(rp, 32);
  grant(peer, 65);
  grant(encrypted, 48);
  grant(&written, sizeof(written));
  // No ephemeral agreement => cannot issue, even with valid memory ranges.
  assert(auth_call_issue(&request, allowed, writable) == AUTH_DENIED);
  assert(written == 0);
  request.encrypted = pin;
  grant(pin, 48);
  assert(auth_call_issue(&request, allowed, writable) == AUTH_INVALID_ARGUMENT);
  request.encrypted = encrypted;
  request.written = (size_t *)encrypted;
  assert(auth_call_issue(&request, allowed, writable) == AUTH_INVALID_ARGUMENT);
  request.written = &written;
  request.pin = (void *)(UINTPTR_MAX - 2);
  assert(auth_call_issue(&request, allowed, writable) == AUTH_INVALID_ARGUMENT);
  request.pin = pin;
  request.peer_len = SIZE_MAX;
  assert(auth_call_issue(&request, allowed, writable) == AUTH_INVALID_ARGUMENT);
  assert(auth_call_public((void *)1, 65, writable) == AUTH_INVALID_ARGUMENT);
  assert(auth_call_status((void *)1, writable) == AUTH_INVALID_ARGUMENT);
  auth_mac_request mac = {.message = (void *)1, .message_len = 7};
  grant(&mac, sizeof(mac));
  assert(auth_call_check(&mac, allowed) == AUTH_INVALID_ARGUMENT);
  assert(auth_test_transients_zero());
  uint8_t host_private[32] = {0}, public_key[65] = {0}, hash_enc[16] = {0};
  host_private[31] = 1;
  assert(ecdsa_get_public_key65(&nist256p1, host_private, peer) == 0);
  grant(public_key, sizeof(public_key));
  request.peer_len = 65;
  assert(auth_call_public(public_key, 65, writable) == AUTH_OK);
  // The token path takes the PIN hash encrypted under the shared secret, so the
  // fixture plays the platform from here on: same secret, derived from its own
  // private key and the public key the vault just handed back.
  pin_protocol_host_encrypt(host_private, public_key, 1, pin, 16, 0, hash_enc);
  request.pin = hash_enc;
  request.pin_len = sizeof(hash_enc);
  grant(hash_enc, sizeof(hash_enc));
  assert(auth_call_issue(&request, allowed, writable) == AUTH_OK);
  assert(written == 32);
  for (size_t i = written; i < sizeof(encrypted); i++)
    assert(encrypted[i] == 0);
  request.encrypted = (uint8_t *)&request;
  assert(auth_call_issue(&request, allowed, writable) == AUTH_INVALID_ARGUMENT);
  assert(auth_test_transients_zero());
  range_count = 0;
  auth_credential_public credential;
  uint8_t metadata[21] = {1, 1, 3, 0, 11, 1, 0, 0, 0};
  uint8_t id[89] = {0}, signature[72], salts[64] = {0};
  auth_create_request create = {.rp = rp,
                                .metadata = metadata,
                                .metadata_len = 21,
                                .algorithm = -7,
                                .out = &credential};
  auth_open_request open = {
      .rp = rp, .id = id, .id_len = 89, .out = &credential};
  auth_sign_request sign = {.rp = rp,
                            .id = id,
                            .id_len = 89,
                            .message = metadata,
                            .message_len = 21,
                            .algorithm = -7,
                            .out = signature,
                            .written = &written};
  auth_hmac_request hmac = {.rp = rp,
                            .id = id,
                            .id_len = 89,
                            .salts = salts,
                            .salts_len = 64,
                            .out = signature};
  assert(auth_call_credential_create((void *)1, allowed, writable) ==
         AUTH_INVALID_ARGUMENT);
  grant(&create, sizeof(create));
  grant(&open, sizeof(open));
  grant(&sign, sizeof(sign));
  grant(&hmac, sizeof(hmac));
  grant(rp, 32);
  grant(metadata, 21);
  grant(id, 89);
  grant(&credential, sizeof(credential));
  grant(signature, 72);
  grant(&written, sizeof(written));
  create.out = (auth_credential_public *)metadata;
  assert(auth_call_credential_create(&create, allowed, writable) ==
         AUTH_INVALID_ARGUMENT);
  create.out = &credential;
  create.metadata_len = SIZE_MAX;
  assert(auth_call_credential_create(&create, allowed, writable) ==
         AUTH_INVALID_ARGUMENT);
  open.id = (void *)(UINTPTR_MAX - 1);
  assert(auth_call_credential_open(&open, allowed, writable) ==
         AUTH_INVALID_ARGUMENT);
  sign.written = (size_t *)signature;
  assert(auth_call_credential_sign(&sign, allowed, writable) ==
         AUTH_INVALID_ARGUMENT);
  hmac.out = (uint8_t *)&hmac;
  assert(auth_call_credential_hmac(&hmac, allowed, writable) ==
         AUTH_INVALID_ARGUMENT);
  assert(auth_call_resident_get(100, &credential, writable) ==
         AUTH_INVALID_ARGUMENT);
  assert(auth_call_resident_set(100, &open, allowed) == AUTH_INVALID_ARGUMENT);
  assert(auth_call_resident_delete(100) == AUTH_INVALID_ARGUMENT);
  assert(auth_test_transients_zero());
  set_pin_calls();
  credential_calls();
}

// The setPIN marshalling. What matters at this boundary is not the PIN rules --
// those are the vault's and tested there -- but that a descriptor coming from
// unprivileged memory cannot make this layer read outside what it was granted.
static void set_pin_calls(void) {
  uint8_t host_private[32] = {0}, public_key[65] = {0}, peer[65] = {0};
  uint8_t padded[64] = {0}, blob[80] = {0}, mac[32] = {0};
  host_private[31] = 1;
  assert(ecdsa_get_public_key65(&nist256p1, host_private, peer) == 0);
  memcpy(padded, "12345678", 8);

  auth_test_reset();
  assert(auth_vault_init() == AUTH_OK);
  range_count = 0;
  auth_set_pin_request request = {.new_pin = blob,
                                  .new_pin_len = 64,
                                  .param = mac,
                                  .param_len = 16,
                                  .peer = peer,
                                  .peer_len = 65,
                                  .protocol = 1};

  // An ungranted descriptor is refused before anything is read through it.
  assert(auth_call_set_pin(&request, allowed) == AUTH_INVALID_ARGUMENT);

  grant(&request, sizeof(request));
  grant(blob, sizeof(blob));
  grant(mac, sizeof(mac));
  grant(peer, 65);
  grant(public_key, sizeof(public_key));
  assert(auth_call_public(public_key, 65, writable) == AUTH_OK);
  pin_protocol_host_encrypt(host_private, public_key, 1, padded, 64, 0, blob);
  pin_protocol_host_mac(host_private, public_key, 1, blob, 64, mac);
  assert(auth_call_set_pin(&request, allowed) == AUTH_OK);
  assert(auth_vault_status().state == AUTH_OK);

  // The length each protocol pins is enforced here too, so a descriptor cannot
  // ask this layer to copy 80 bytes out of a 64-byte grant, or the reverse.
  auth_test_reset();
  assert(auth_vault_init() == AUTH_OK);
  range_count = 0;
  grant(&request, sizeof(request));
  grant(blob, sizeof(blob));
  grant(mac, sizeof(mac));
  grant(peer, 65);
  grant(public_key, sizeof(public_key));
  assert(auth_call_public(public_key, 65, writable) == AUTH_OK);
  request.new_pin_len = 80;
  assert(auth_call_set_pin(&request, allowed) == AUTH_INVALID_ARGUMENT);
  request.protocol = 2;
  request.new_pin_len = 64;
  assert(auth_call_set_pin(&request, allowed) == AUTH_INVALID_ARGUMENT);
  request.protocol = 3;
  request.new_pin_len = 64;
  assert(auth_call_set_pin(&request, allowed) == AUTH_INVALID_ARGUMENT);
  request.protocol = 1;
  request.peer_len = SIZE_MAX;
  assert(auth_call_set_pin(&request, allowed) == AUTH_INVALID_ARGUMENT);
  request.peer_len = 65;
  request.new_pin = (void *)(UINTPTR_MAX - 2);
  assert(auth_call_set_pin(&request, allowed) == AUTH_INVALID_ARGUMENT);
  request.new_pin = blob;

  // Protocol 2 carries its IV, so 80 granted bytes are read and accepted.
  //
  // Key agreement has to be redone first: every refusal above went through this
  // layer's invalid() path, which clears the session, so the shared secret
  // those rejections were measured against is deliberately gone.
  request.protocol = 2;
  request.new_pin_len = 80;
  request.param_len = 32;
  assert(auth_call_public(public_key, 65, writable) == AUTH_OK);
  pin_protocol_host_encrypt(host_private, public_key, 2, padded, 64, 0x30,
                            blob);
  pin_protocol_host_mac(host_private, public_key, 2, blob, 80, mac);
  assert(auth_call_set_pin(&request, allowed) == AUTH_OK);
  assert(auth_test_transients_zero());
}

static void credential_calls(void) {
  struct {
    auth_create_request create;
    auth_open_request open;
    auth_sign_request sign;
    auth_hmac_request hmac;
    auth_credential_public credential, opened;
    uint8_t rp[32], metadata[21], signature[72], salts[64];
    size_t written;
  } value = {0};
  const uint8_t metadata[] = {1,   1,   3,   0,   11,  1,   0,
                              0,   0,   'e', 'x', 'a', 'm', 'p',
                              'l', 'e', '.', 'c', 'o', 'm', 7};
  memcpy(value.metadata, metadata, sizeof(metadata));
  sha256_Raw(metadata + 9, 11, value.rp);
  uint8_t pin[16] = {1}, scalar[32] = {0}, peer[65], public[65], encrypted[48];
  uint8_t hash_enc[16] = {0};
  size_t written;
  scalar[31] = 1;
  auth_test_reset();
  assert(auth_vault_init() == AUTH_OK);
  assert(auth_vault_provision(pin, 16) == AUTH_OK);
  assert(ecdsa_get_public_key65(&nist256p1, scalar, peer) == 0);
  assert(auth_vault_key_agreement(public, 65) == AUTH_OK);
  pin_protocol_host_encrypt(scalar, public, 1, pin, 16, 0, hash_enc);
  assert(auth_vault_issue_token(hash_enc, sizeof(hash_enc), 1, 1, value.rp, 32,
                                peer, 65, encrypted, 48, &written) == AUTH_OK);
  range_count = 0;
  grant(&value, sizeof(value));
  value.create = (auth_create_request){.rp = value.rp,
                                       .metadata = value.metadata,
                                       .metadata_len = 21,
                                       .algorithm = -7,
                                       .out = &value.credential};
  assert(auth_call_credential_create(&value.create, allowed, writable) ==
         AUTH_OK);
  assert(value.credential.id_len == 89);
  value.open = (auth_open_request){.rp = value.rp,
                                   .id = value.credential.id,
                                   .id_len = value.credential.id_len,
                                   .out = &value.opened};
  value.open.out = NULL;
  assert(auth_call_resident_set(0, &value.open, allowed) == AUTH_OK);
  assert(auth_vault_key_agreement(public, 65) == AUTH_OK);
  pin_protocol_host_encrypt(scalar, public, 1, pin, 16, 0, hash_enc);
  assert(auth_vault_issue_token(hash_enc, sizeof(hash_enc), 1, 2, value.rp, 32,
                                peer, 65, encrypted, 48, &written) == AUTH_OK);
  value.open.out = &value.opened;
  assert(auth_call_resident_get(0, &value.opened, writable) == AUTH_OK);
  assert(auth_call_credential_open(&value.open, allowed, writable) == AUTH_OK);
  assert(memcmp(value.opened.cose, value.credential.cose, 77) == 0);
  value.sign = (auth_sign_request){.rp = value.rp,
                                   .id = value.credential.id,
                                   .id_len = 89,
                                   .message = value.metadata,
                                   .message_len = 21,
                                   .algorithm = -7,
                                   .out = value.signature,
                                   .written = &value.written};
  assert(auth_call_credential_sign(&value.sign, allowed, writable) == AUTH_OK &&
         value.written <= 72 && value.written >= 8);
  value.hmac = (auth_hmac_request){.rp = value.rp,
                                   .id = value.credential.id,
                                   .id_len = 89,
                                   .salts = value.salts,
                                   .salts_len = 64,
                                   .out = value.signature};
  assert(auth_call_credential_hmac(&value.hmac, allowed, writable) == AUTH_OK);
  assert(memcmp(value.signature, value.signature + 32, 32) == 0);
  value.open.out = NULL;
  assert(auth_call_resident_set(1, &value.open, allowed) == AUTH_DENIED);
  assert(auth_vault_key_agreement(public, 65) == AUTH_OK);
  pin_protocol_host_encrypt(scalar, public, 1, pin, 16, 0, hash_enc);
  assert(auth_vault_issue_token(hash_enc, sizeof(hash_enc), 1, 4, NULL, 0, peer,
                                65, encrypted, 48, &written) == AUTH_OK);
  assert(auth_call_resident_get(0, &value.opened, writable) == AUTH_OK);
  assert(auth_call_resident_delete(0) == AUTH_OK);
  // Every destination is writable here; these exercise actual overlap guards.
  value.create.out = (auth_credential_public *)&value.create;
  assert(auth_call_credential_create(&value.create, allowed, writable) ==
         AUTH_INVALID_ARGUMENT);
  value.open.out = (auth_credential_public *)value.credential.id;
  assert(auth_call_credential_open(&value.open, allowed, writable) ==
         AUTH_INVALID_ARGUMENT);
  value.hmac.out = value.salts;
  assert(auth_call_credential_hmac(&value.hmac, allowed, writable) ==
         AUTH_INVALID_ARGUMENT);
  value.sign.out = value.metadata;
  assert(auth_call_credential_sign(&value.sign, allowed, writable) ==
         AUTH_INVALID_ARGUMENT);
  assert(auth_test_transients_zero());
}
