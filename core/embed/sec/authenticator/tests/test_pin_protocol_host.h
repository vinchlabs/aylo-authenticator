#pragma once
// The platform half of CTAP ClientPIN, for tests.
//
// auth_vault_issue_token() takes the PIN hash encrypted under the pinUvAuth
// shared secret, because the shared secret is derived inside the vault and
// nowhere else. Tests therefore have to play the platform: derive the same
// secret from their own private key and the public key the vault handed back,
// then encrypt.
//
// Written out here rather than shared with the vault's implementation on
// purpose. Agreement between two independent derivations is evidence; agreement
// between one implementation and itself is not.

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "aes/aes.h"
#include "ecdsa.h"
#include "hmac.h"
#include "memzero.h"
#include "nist256p1.h"
#include "sha2.h"

// Derives the protocol's AES key into `key`. Protocol 1 uses SHA-256 over the
// shared X coordinate; protocol 2 uses one-block HKDF-SHA256 with CTAP's label.
static inline void pin_protocol_host_key(const uint8_t host_private[32],
                                         const uint8_t vault_public[65],
                                         uint8_t protocol, uint8_t key[32]) {
  uint8_t point[65] = {0}, prk[32] = {0};
  assert(vault_public[0] == 4);
  assert(ecdh_multiply(&nist256p1, host_private, vault_public, point) == 0);
  if (protocol == 1) {
    sha256_Raw(point + 1, 32, key);
  } else {
    hmac_sha256(prk, 32, point + 1, 32, prk);
    hmac_sha256(prk, 32, (const uint8_t *)"CTAP2 AES key\x01", 14, key);
  }
  memzero(point, sizeof(point));
  memzero(prk, sizeof(prk));
}

// Encrypts `plain_len` bytes for the vault and returns the ciphertext length.
// Protocol 1 encrypts under a zero IV; protocol 2 prepends one, derived from
// `iv_seed` so that a failing vector can be reproduced rather than re-rolled.
static inline size_t pin_protocol_host_encrypt(const uint8_t host_private[32],
                                               const uint8_t vault_public[65],
                                               uint8_t protocol,
                                               const uint8_t *plain,
                                               size_t plain_len,
                                               uint8_t iv_seed, uint8_t *out) {
  uint8_t key[32] = {0}, iv[16] = {0};
  aes_encrypt_ctx ctx = {0};
  pin_protocol_host_key(host_private, vault_public, protocol, key);
  if (protocol == 2) {
    for (size_t i = 0; i < 16; i++) iv[i] = (uint8_t)(iv_seed + i);
    memcpy(out, iv, 16);
  }
  assert(aes_encrypt_key256(key, &ctx) == 0);
  assert(aes_cbc_encrypt(plain, out + (protocol == 2 ? 16 : 0), (int)plain_len,
                         iv, &ctx) == 0);
  memzero(key, sizeof(key));
  memzero(iv, sizeof(iv));
  memzero(&ctx, sizeof(ctx));
  return plain_len + (protocol == 2 ? 16 : 0);
}

// CTAP's authenticate(): protocol 1 keys with the same value it
// encrypts with and truncates to 16 bytes, protocol 2 has a separate
// HMAC key and keeps all 32. Returns the MAC length.
static inline size_t pin_protocol_host_mac(const uint8_t host_private[32],
                                           const uint8_t vault_public[65],
                                           uint8_t protocol,
                                           const uint8_t *message, size_t len,
                                           uint8_t out[32]) {
  uint8_t point[65] = {0}, prk[32] = {0}, key[32] = {0};
  assert(vault_public[0] == 4);
  assert(ecdh_multiply(&nist256p1, host_private, vault_public, point) == 0);
  if (protocol == 1) {
    sha256_Raw(point + 1, 32, key);
  } else {
    hmac_sha256(prk, 32, point + 1, 32, prk);
    hmac_sha256(prk, 32, (const uint8_t *)"CTAP2 HMAC key\x01", 15, key);
  }
  hmac_sha256(key, 32, message, (uint32_t)len, out);
  memzero(point, sizeof(point));
  memzero(prk, sizeof(prk));
  memzero(key, sizeof(key));
  return protocol == 2 ? 32 : 16;
}
