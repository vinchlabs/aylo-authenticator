#include <assert.h>
#include <sec/authenticator.h>
#include <stdio.h>
#include <string.h>
#include "aes/aes.h"
#include "ecdsa.h"
#include "hmac.h"
#include "memzero.h"
#include "nist256p1.h"
#include "sha2.h"
#include "test_backend.h"
#include "test_pin_protocol_host.h"

static const uint8_t pin[16] = {1};
static const uint8_t wrong[16] = {2};
static const uint8_t rp[32] = {3};
static const uint8_t other_rp[32] = {4};
static uint8_t host_private[32] = {0};
static uint8_t peer[65], pub[65], encrypted[48], token[32];
static size_t written;

static uint8_t hex_digit(char c) { return c <= '9' ? c - '0' : c - 'a' + 10; }
static void expect_hex(const uint8_t *value, const char *hex, size_t len) {
  for (size_t i = 0; i < len; i++)
    assert(value[i] ==
           (hex_digit(hex[2 * i]) << 4 | hex_digit(hex[2 * i + 1])));
}

static void fresh(void) {
  auth_test_reset();
  assert(auth_vault_init() == AUTH_OK);
}

// Mirrors the platform half of ClientPIN: LEFT(SHA-256(pin), 16) encrypted
// under the shared secret. Protocol 1 encrypts under a zero IV, protocol 2
// prepends one -- fixed here rather than random so a failing vector is
// reproducible. Returns the ciphertext length the vault expects for that
// protocol.
//
// Derived independently of the vault, from the host private key and the public
// key the vault handed back, so agreement between the two is evidence rather
// than a shared implementation.
static size_t encrypt_pin_hash(const uint8_t hash[16], uint8_t protocol,
                               uint8_t out[32]) {
  const size_t length = protocol == 2 ? 32 : 16;
  if (pub[0] != 4) {
    // No key agreement is in flight, so there is no shared secret to encrypt
    // under. Hand over a well-formed but meaningless blob and let the vault
    // refuse on its own terms; asserting here would abort the tests that
    // deliberately exercise a faulted or unestablished session.
    memset(out, 0xee, length);
    return length;
  }
  uint8_t point[65] = {0}, prk[32] = {0}, key[32] = {0}, iv[16] = {0};
  aes_encrypt_ctx ctx = {0};
  assert(ecdh_multiply(&nist256p1, host_private, pub, point) == 0);
  if (protocol == 1) {
    sha256_Raw(point + 1, 32, key);
  } else {
    hmac_sha256(prk, 32, point + 1, 32, prk);
    hmac_sha256(prk, 32, (const uint8_t *)"CTAP2 AES key\x01", 14, key);
    for (size_t i = 0; i < 16; i++) iv[i] = (uint8_t)(0xa0 + i);
    memcpy(out, iv, 16);
  }
  assert(aes_encrypt_key256(key, &ctx) == 0);
  assert(aes_cbc_encrypt(hash, out + (protocol == 2 ? 16 : 0), 16, iv, &ctx) ==
         0);
  memzero(point, sizeof(point));
  memzero(prk, sizeof(prk));
  memzero(key, sizeof(key));
  memzero(iv, sizeof(iv));
  memzero(&ctx, sizeof(ctx));
  return length;
}

static auth_result issue(const uint8_t *hash, uint8_t protocol) {
  uint8_t blob[32] = {0};
  const size_t length = encrypt_pin_hash(hash, protocol, blob);
  const auth_result result =
      auth_vault_issue_token(blob, length, protocol, 2, rp, 32, peer, 65,
                             encrypted, sizeof(encrypted), &written);
  memzero(blob, sizeof(blob));
  return result;
}

// Host-side reference uses the public boundary, never reads native token/root.
static void decrypt_token(uint8_t protocol) {
  uint8_t point[65] = {0}, shared[32] = {0}, key[32] = {0}, iv[16] = {0};
  aes_decrypt_ctx ctx = {0};
  assert(ecdh_multiply(&nist256p1, host_private, pub, point) == 0);
  if (protocol == 1) {
    sha256_Raw(point + 1, 32, key);
  } else {
    hmac_sha256(shared, 32, point + 1, 32, shared);
    hmac_sha256(shared, 32, (const uint8_t *)"CTAP2 AES key\x01", 14, key);
    memcpy(iv, encrypted, 16);
  }
  assert(aes_decrypt_key256(key, &ctx) == 0);
  assert(aes_cbc_decrypt(encrypted + (protocol == 2 ? 16 : 0), token, 32, iv,
                         &ctx) == 0);
  memzero(point, sizeof(point));
  memzero(shared, sizeof(shared));
  memzero(key, sizeof(key));
  memzero(iv, sizeof(iv));
  memzero(&ctx, sizeof(ctx));
}

static void mac(uint8_t out[32]) {
  hmac_sha256(token, 32, (const uint8_t *)"message", 7, out);
}

static void establish(void) {
  assert(auth_vault_key_agreement(pub, 65) == AUTH_OK);
}

static void lifecycle(void) {
  fresh();
  assert(auth_vault_status().state == AUTH_UNPROVISIONED);
  assert(auth_vault_provision(NULL, 0) == AUTH_INVALID_ARGUMENT);
  assert(auth_vault_provision(pin, 15) == AUTH_INVALID_ARGUMENT);
  assert(auth_vault_provision(pin, 16) == AUTH_OK);
  assert(auth_vault_status().state == AUTH_OK);
  assert(auth_vault_status().retries == 8);
  assert(auth_test_rng_bytes() == 44);  // 32 root + 12 nonce
  // Independently generated Python hashlib/cryptography vectors.
  expect_hex(auth_test_verifier(),
             "81ff869d87bf0c81aa97c28571cb5e588b8dfff37c4a71f9c3602fbf6f5ac5aa",
             32);
  expect_hex(
      auth_test_record(),
      "a1012122232425262728292a2b2c9142c674f02846ad8819271baabe67c3cc8cbe220"
      "64815f4216c87e06067990de33871c5c59c1fa34592b31637160f76",
      62);
  // Neither record plaintext nor domain-separated verifier equals input PIN.
  assert(memcmp(auth_test_verifier(), pin, 16) != 0);
  assert(auth_vault_provision(pin, 16) == AUTH_DENIED);
  establish();
  assert(issue(pin, 1) == AUTH_OK && written == 32);
  expect_hex(encrypted,
             "04f5cce4a60164a32278b3211918b6a24bf6dd13b4908fc6492acab8bac62941",
             32);
  decrypt_token(1);
  uint8_t first[32], param[32];
  memcpy(first, token, 32);
  mac(param);
  assert(auth_vault_check_auth(1, (const uint8_t *)"message", 7, param, 16, 2,
                               rp, 32) == AUTH_OK);
  assert(auth_vault_check_auth(1, (const uint8_t *)"message", 7, param, 16, 1,
                               rp, 32) == AUTH_DENIED);
  assert(auth_test_transients_zero());
  establish();
  assert(issue(pin, 2) == AUTH_OK && written == 48);
  expect_hex(encrypted,
             "adaeafb0b1b2b3b4b5b6b7b8b9babbbc071fc1ecf6e23f2dd70d9e4125cf8b32"
             "d542de01910602df26010b1ffb1f67f4",
             48);
  decrypt_token(2);
  assert(memcmp(first, token, 32) != 0);
  mac(param);
  assert(auth_vault_check_auth(2, (const uint8_t *)"message", 7, param, 32, 2,
                               rp, 32) == AUTH_OK);
  assert(auth_vault_disconnect() == AUTH_OK);
  assert(auth_test_transients_zero());
  assert(auth_test_zeroize_checks() > 0);
  assert(auth_vault_check_auth(2, (const uint8_t *)"message", 7, param, 32, 2,
                               rp, 32) == AUTH_DENIED);
  // PIN change is gated: the old PIN still works and the new one never does.
  assert(auth_vault_change_pin(pin, 16, wrong, 16) == AUTH_DENIED);
  establish();
  assert(issue(wrong, 1) == AUTH_PIN_INVALID);
  establish();
  assert(issue(pin, 1) == AUTH_OK);
  assert(auth_vault_wipe() == AUTH_OK);
  assert(auth_vault_status().state == AUTH_UNPROVISIONED);
  assert(auth_test_transients_zero());
}

// The PIN-change gate must be observably inert: no flash write, no OPTIGA
// state change, no retry consumed, and no disturbance to a live authorized
// session. Anything less would make a denied call a usable attack surface --
// repeatedly "failing" a PIN change could otherwise burn the retry counter
// down to a wipe.
static void pin_change_is_gated_without_side_effects(void) {
  fresh();
  assert(auth_vault_provision(pin, 16) == AUTH_OK);

  // Capture the full observable state: root envelope, retry counter, and a
  // live session with a usable token.
  uint8_t record_before[62];
  memcpy(record_before, auth_test_record(), sizeof(record_before));
  uint8_t verifier_before[32];
  memcpy(verifier_before, auth_test_verifier(), sizeof(verifier_before));
  const uint8_t retries_before = auth_vault_status().retries;
  assert(retries_before == 8);

  establish();
  assert(issue(pin, 1) == AUTH_OK);
  decrypt_token(1);
  uint8_t param[32];
  mac(param);
  // The session is live and authorized right now.
  assert(auth_vault_check_auth(1, (const uint8_t *)"message", 7, param, 16, 2,
                               rp, 32) == AUTH_OK);

  // Every shape of call is denied, including malformed ones: the gate returns
  // before it would even validate arguments.
  assert(auth_vault_change_pin(pin, 16, wrong, 16) == AUTH_DENIED);
  assert(auth_vault_change_pin(NULL, 0, NULL, 0) == AUTH_DENIED);
  assert(auth_vault_change_pin(pin, 15, wrong, 16) == AUTH_DENIED);
  assert(auth_vault_change_pin(wrong, 16, pin, 16) == AUTH_DENIED);

  // Flash and secure-element state are byte-for-byte unchanged, and no retry
  // was consumed even by the call that supplied a wrong old PIN.
  assert(memcmp(record_before, auth_test_record(), sizeof(record_before)) == 0);
  assert(memcmp(verifier_before, auth_test_verifier(),
                sizeof(verifier_before)) == 0);
  assert(auth_vault_status().retries == retries_before);
  assert(auth_vault_status().state == AUTH_OK);

  // The previously authorized session still works: the gate did not invalidate
  // it. This is why the implementation avoids finish(), which invalidates on
  // any non-OK result.
  assert(auth_vault_check_auth(1, (const uint8_t *)"message", 7, param, 16, 2,
                               rp, 32) == AUTH_OK);

  // The supported transition is still available: wipe, then provision fresh
  // with a different PIN.
  assert(auth_vault_wipe() == AUTH_OK);
  assert(auth_vault_status().state == AUTH_UNPROVISIONED);
  assert(auth_vault_provision(wrong, 16) == AUTH_OK);
  establish();
  assert(issue(wrong, 1) == AUTH_OK);
  // The session above is deliberately live, so tear it down before asserting
  // that no secret material is left behind.
  assert(auth_vault_disconnect() == AUTH_OK);
  assert(auth_test_transients_zero());
}

static void independent_denials(void) {
  fresh();
  assert(auth_vault_provision(pin, 16) == AUTH_OK);
  for (uint8_t protocol = 1; protocol <= 2; protocol++) {
    for (unsigned condition = 0; condition < 4; condition++) {
      establish();
      assert(issue(pin, protocol) == AUTH_OK);
      decrypt_token(protocol);
      uint8_t param[32];
      mac(param);
      size_t len = protocol == 1 ? 16 : 32;
      // Prove the fresh token is valid immediately before each negative case.
      assert(auth_vault_check_auth(protocol, (const uint8_t *)"message", 7,
                                   param, len, 2, rp, 32) == AUTH_OK);
      if (condition == 2) param[len - 1] ^= 1;
      const uint8_t *check_rp = condition == 0 ? other_rp : rp;
      size_t rp_len = condition == 1 ? 0 : 32;
      if (!rp_len) check_rp = NULL;
      uint8_t permissions = condition == 3 ? 1 : 2;
      assert(auth_vault_check_auth(protocol, (const uint8_t *)"message", 7,
                                   param, len, permissions, check_rp,
                                   rp_len) == AUTH_DENIED);
      assert(auth_test_transients_zero());
      mac(param);
      assert(auth_vault_check_auth(protocol, (const uint8_t *)"message", 7,
                                   param, len, 2, rp, 32) == AUTH_DENIED);
      assert(auth_test_transients_zero());
      memzero(param, sizeof(param));
    }
  }
  memzero(token, sizeof(token));
}

static void retries(void) {
  fresh();
  assert(auth_vault_provision(pin, 16) == AUTH_OK);
  for (int i = 1; i <= 8; i++) {
    establish();
    auth_result want = i == 8       ? AUTH_PIN_BLOCKED
                       : i % 3 == 0 ? AUTH_PIN_AUTH_BLOCKED
                                    : AUTH_PIN_INVALID;
    assert(issue(wrong, 1) == want);
    assert(written == 0);
    for (size_t j = 0; j < sizeof(encrypted); j++) assert(encrypted[j] == 0);
    if (i % 3 == 0) {
      assert(issue(pin, 1) == AUTH_PIN_AUTH_BLOCKED);
      assert(auth_vault_disconnect() == AUTH_OK);
      assert(auth_vault_init() == AUTH_OK);
      assert(auth_vault_status().retries == 8 - i);
    }
  }
  assert(auth_vault_status().state == AUTH_UNPROVISIONED);
  assert(auth_test_transients_zero());
  fresh();
  assert(auth_vault_provision(pin, 16) == AUTH_OK);
  establish();
  assert(issue(wrong, 1) == AUTH_PIN_INVALID);
  establish();
  assert(issue(pin, 1) == AUTH_OK);
  assert(auth_vault_status().retries == 8 &&
         auth_vault_status().consecutive == 0);
}

static void failures(void) {
  fresh();
  assert(auth_vault_provision(pin, 16) == AUTH_OK);
  for (size_t i = 0; i < 3; i++) {
    establish();
    assert(issue(wrong, 1) != AUTH_OK);
  }
  auth_test_exhaust();
  auth_status exhausted = auth_vault_status();
  assert(exhausted.state == AUTH_UNPROVISIONED && exhausted.retries == 0 &&
         exhausted.consecutive == 0);
  // A crash between the eighth failed attempt and wipe cannot preserve a root.
  fresh();
  assert(auth_vault_provision(pin, 16) == AUTH_OK);
  auth_test_exhaust();
  assert(auth_vault_disconnect() == AUTH_OK);
  assert(auth_vault_status().state == AUTH_UNPROVISIONED);
  assert(auth_test_transients_zero());
  const auth_test_failure provision_failures[] = {
      TEST_RNG,   TEST_PIN_INIT,    TEST_PIN_SET, TEST_COUNTER,
      TEST_WRITE, TEST_INTERRUPTED, TEST_ZEROIZE};
  for (size_t i = 0;
       i < sizeof(provision_failures) / sizeof(provision_failures[0]); i++) {
    fresh();
    auth_test_fail(provision_failures[i]);
    assert(auth_vault_provision(pin, 16) == AUTH_ERROR);
    assert(auth_vault_key_agreement(pub, 65) == AUTH_ERROR);
    assert(issue(pin, 1) != AUTH_OK);
    assert(written == 0 && auth_test_transients_zero());
  }
  const auth_test_failure issue_failures[] = {
      TEST_RNG, TEST_PIN_VERIFY, TEST_COUNTER, TEST_READ, TEST_ZEROIZE};
  for (size_t i = 0; i < sizeof(issue_failures) / sizeof(issue_failures[0]);
       i++) {
    fresh();
    assert(auth_vault_provision(pin, 16) == AUTH_OK);
    establish();
    auth_test_fail(issue_failures[i]);
    assert(issue(pin, 1) == AUTH_ERROR);
    assert(written == 0 && auth_test_transients_zero());
  }
  // Every authenticated field, version and tag fails closed on corruption.
  for (size_t offset = 0; offset < 62; offset++) {
    fresh();
    assert(auth_vault_provision(pin, 16) == AUTH_OK);
    auth_test_corrupt(offset);
    establish();
    assert(issue(pin, 1) == AUTH_ERROR);
    assert(written == 0 && auth_test_transients_zero());
  }
  // PIN change is gated, so no injected backend failure can reach it and the
  // vault must survive every one of them completely untouched. Previously each
  // of these drove the vault into a wiped/error state by design.
  const auth_test_failure change_failures[] = {TEST_RNG, TEST_PIN_SET,
                                               TEST_WRITE, TEST_INTERRUPTED};
  for (size_t i = 0; i < sizeof(change_failures) / sizeof(change_failures[0]);
       i++) {
    fresh();
    assert(auth_vault_provision(pin, 16) == AUTH_OK);
    auth_test_fail(change_failures[i]);
    assert(auth_vault_change_pin(pin, 16, wrong, 16) == AUTH_DENIED);
    assert(auth_vault_disconnect() == AUTH_OK);
    // Still provisioned: the gate never reached the backend at all.
    assert(auth_vault_status().state == AUTH_OK);
    assert(auth_test_transients_zero());
  }
  fresh();
  assert(auth_vault_provision(pin, 16) == AUTH_OK);
  establish();
  auth_test_fail(TEST_ERASE);
  assert(auth_vault_wipe() == AUTH_ERROR);
  assert(auth_vault_status().state == AUTH_ERROR);
  assert(auth_vault_provision(pin, 16) == AUTH_ERROR);
  assert(issue(pin, 1) == AUTH_ERROR && written == 0);
  assert(auth_test_transients_zero());
}

static void lengths(void) {
  fresh();
  assert(auth_vault_provision(pin, 16) == AUTH_OK);
  establish();
  assert(auth_vault_key_agreement(pub, 64) == AUTH_INVALID_ARGUMENT);
  // These reject on the arguments themselves, before any decryption, so the
  // plaintext hash below stands in for ciphertext of the same length.
  assert(auth_vault_issue_token(pin, 15, 1, 2, rp, 32, peer, 65, encrypted, 48,
                                &written) == AUTH_INVALID_ARGUMENT);
  assert(auth_vault_issue_token(pin, 16, 3, 2, rp, 32, peer, 65, encrypted, 48,
                                &written) == AUTH_INVALID_ARGUMENT);
  assert(auth_vault_issue_token(pin, 16, 1, 0, rp, 32, peer, 65, encrypted, 48,
                                &written) == AUTH_INVALID_ARGUMENT);
  assert(auth_vault_issue_token(pin, 16, 1, 2, rp, 31, peer, 65, encrypted, 48,
                                &written) == AUTH_INVALID_ARGUMENT);
  assert(auth_vault_issue_token(pin, 16, 1, 2, rp, 32, peer, 64, encrypted, 48,
                                &written) == AUTH_INVALID_ARGUMENT);
  // Each protocol pins its own ciphertext length: 16 bytes for protocol 1 with
  // its zero IV, 32 for protocol 2 with a prepended one. Offering the other
  // protocol's length is rejected rather than silently reinterpreted.
  uint8_t blob[32] = {0};
  assert(auth_vault_issue_token(blob, 16, 2, 2, rp, 32, peer, 65, encrypted, 48,
                                &written) == AUTH_INVALID_ARGUMENT);
  assert(auth_vault_issue_token(blob, 32, 1, 2, rp, 32, peer, 65, encrypted, 48,
                                &written) == AUTH_INVALID_ARGUMENT);
  // A correct length still cannot squeeze protocol 2's IV plus token into 47.
  assert(auth_vault_issue_token(blob, 32, 2, 2, rp, 32, peer, 65, encrypted, 47,
                                &written) == AUTH_INVALID_ARGUMENT);
  uint8_t invalid_peer[65] = {4};
  establish();
  assert(auth_vault_issue_token(pin, 16, 1, 2, rp, 32, invalid_peer, 65,
                                encrypted, 48,
                                &written) == AUTH_INVALID_ARGUMENT);
  assert(auth_vault_status().retries == 8);
}

// The PIN arrives from the platform as a 64-byte zero-padded UTF-8 string under
// the shared secret. Everything the vault has to judge about it -- padding,
// encoding, length -- it must judge after decrypting, so each case here is a
// real ciphertext rather than a shortcut.
static size_t encrypt_new_pin(const uint8_t padded[64], uint8_t protocol,
                              uint8_t out[80]) {
  uint8_t point[65] = {0}, prk[32] = {0}, key[32] = {0}, iv[16] = {0};
  aes_encrypt_ctx ctx = {0};
  assert(pub[0] == 4);
  assert(ecdh_multiply(&nist256p1, host_private, pub, point) == 0);
  if (protocol == 1) {
    sha256_Raw(point + 1, 32, key);
  } else {
    hmac_sha256(prk, 32, point + 1, 32, prk);
    hmac_sha256(prk, 32, (const uint8_t *)"CTAP2 AES key\x01", 14, key);
    for (size_t i = 0; i < 16; i++) iv[i] = (uint8_t)(0x50 + i);
    memcpy(out, iv, 16);
  }
  assert(aes_encrypt_key256(key, &ctx) == 0);
  assert(aes_cbc_encrypt(padded, out + (protocol == 2 ? 16 : 0), 64, iv,
                         &ctx) == 0);
  memzero(point, sizeof(point));
  memzero(prk, sizeof(prk));
  memzero(key, sizeof(key));
  memzero(iv, sizeof(iv));
  memzero(&ctx, sizeof(ctx));
  return protocol == 2 ? 80 : 64;
}

static auth_result set_pin(const uint8_t padded[64], uint8_t protocol) {
  uint8_t blob[80] = {0}, mac[32] = {0};
  const size_t length = encrypt_new_pin(padded, protocol, blob);
  const size_t mac_len =
      pin_protocol_host_mac(host_private, pub, protocol, blob, length, mac);
  const auth_result result =
      auth_vault_set_pin(protocol, blob, length, mac, mac_len, peer, 65);
  memzero(blob, sizeof(blob));
  memzero(mac, sizeof(mac));
  return result;
}

static void pad_pin(uint8_t padded[64], const char *text) {
  memzero(padded, 64);
  memcpy(padded, text, strlen(text));
}

static void set_pin_from_platform(void) {
  uint8_t padded[64] = {0};

  // A PIN shorter than the policy floor is refused with a code the platform can
  // act on, distinct from a malformed request it cannot.
  fresh();
  establish();
  pad_pin(padded, "1234567");
  assert(set_pin(padded, 1) == AUTH_PIN_POLICY);
  assert(auth_vault_status().state == AUTH_UNPROVISIONED);

  // Exactly at the floor, on both protocols, and the PIN that results is the
  // one the vault will later verify: issuing a token with LEFT(SHA-256(pin),
  // 16) succeeds, and with anything else it does not.
  for (uint8_t protocol = 1; protocol <= 2; protocol++) {
    fresh();
    establish();
    pad_pin(padded, "12345678");
    assert(set_pin(padded, protocol) == AUTH_OK);
    assert(auth_vault_status().state == AUTH_OK);
    uint8_t digest[32] = {0}, hash[16] = {0};
    sha256_Raw((const uint8_t *)"12345678", 8, digest);
    memcpy(hash, digest, 16);
    establish();
    assert(issue(hash, protocol) == AUTH_OK);
    establish();
    assert(issue(wrong, protocol) == AUTH_PIN_INVALID);
  }

  // A second setPIN is refused: replacing a PIN is an explicit wipe followed by
  // a fresh one, never an overwrite.
  fresh();
  establish();
  pad_pin(padded, "12345678");
  assert(set_pin(padded, 1) == AUTH_OK);
  establish();
  pad_pin(padded, "87654321");
  assert(set_pin(padded, 1) == AUTH_DENIED);

  // Padding that is not padding. A non-zero byte after the string means the
  // platform sent something else, and guessing which part it meant is not the
  // vault's job.
  fresh();
  establish();
  pad_pin(padded, "12345678");
  padded[40] = 'x';
  assert(set_pin(padded, 1) == AUTH_INVALID_ARGUMENT);

  // Filling all 64 bytes leaves no padding, so a truncated PIN and a complete
  // one would be indistinguishable.
  fresh();
  establish();
  memset(padded, 'a', 64);
  assert(set_pin(padded, 1) == AUTH_INVALID_ARGUMENT);

  // Malformed UTF-8 in its several shapes: a lone continuation byte, a
  // truncated sequence, an overlong encoding of '/', and a UTF-16 surrogate
  // half. Each decodes differently across implementations, so none is a PIN.
  static const char *malformed[] = {"1234567\x80", "1234567\xc3",
                                    "1234567\xc0\xaf", "1234567\xed\xa0\x80"};
  for (size_t i = 0; i < sizeof(malformed) / sizeof(malformed[0]); i++) {
    fresh();
    establish();
    pad_pin(padded, malformed[i]);
    assert(set_pin(padded, 1) == AUTH_INVALID_ARGUMENT);
    assert(auth_vault_status().state == AUTH_UNPROVISIONED);
  }

  // Eight code points that are not eight bytes: the floor counts characters, so
  // a multi-byte PIN at the floor is accepted.
  fresh();
  establish();
  pad_pin(padded,
          "\xc3\xa1\xc3\xa1\xc3\xa1\xc3\xa1\xc3\xa1\xc3\xa1\xc3\xa1"
          "\xc3\xa1");
  assert(set_pin(padded, 1) == AUTH_OK);

  // Seven code points in fourteen bytes is still short, and length in bytes
  // must not be mistaken for length in characters.
  fresh();
  establish();
  pad_pin(padded, "\xc3\xa1\xc3\xa1\xc3\xa1\xc3\xa1\xc3\xa1\xc3\xa1\xc3\xa1");
  assert(set_pin(padded, 1) == AUTH_PIN_POLICY);

  // Arguments, before any decryption.
  fresh();
  establish();
  uint8_t blob[80] = {0}, mac[32] = {0};
  assert(auth_vault_set_pin(1, blob, 80, mac, 16, peer, 65) ==
         AUTH_INVALID_ARGUMENT);
  assert(auth_vault_set_pin(2, blob, 64, mac, 32, peer, 65) ==
         AUTH_INVALID_ARGUMENT);
  assert(auth_vault_set_pin(3, blob, 64, mac, 16, peer, 65) ==
         AUTH_INVALID_ARGUMENT);
  assert(auth_vault_set_pin(1, blob, 64, mac, 32, peer, 65) ==
         AUTH_INVALID_ARGUMENT);
  assert(auth_vault_set_pin(2, blob, 80, mac, 16, peer, 65) ==
         AUTH_INVALID_ARGUMENT);
  assert(auth_vault_set_pin(1, blob, 64, mac, 16, peer, 64) ==
         AUTH_INVALID_ARGUMENT);
  assert(auth_vault_set_pin(1, NULL, 64, mac, 16, peer, 65) ==
         AUTH_INVALID_ARGUMENT);
  assert(auth_vault_set_pin(1, blob, 64, NULL, 16, peer, 65) ==
         AUTH_INVALID_ARGUMENT);
  uint8_t bad_peer[65] = {4};
  establish();
  assert(auth_vault_set_pin(1, blob, 64, mac, 16, bad_peer, 65) ==
         AUTH_INVALID_ARGUMENT);

  // A MAC that does not match is refused before the PIN is decrypted, so a
  // caller who did not do the key agreement cannot set a PIN even on a blank
  // device.
  fresh();
  establish();
  pad_pin(padded, "12345678");
  {
    uint8_t good[80] = {0}, wrong[32] = {0};
    const size_t glen = encrypt_new_pin(padded, 1, good);
    pin_protocol_host_mac(host_private, pub, 1, good, glen, wrong);
    wrong[0] ^= 1;
    assert(auth_vault_set_pin(1, good, glen, wrong, 16, peer, 65) ==
           AUTH_DENIED);
    assert(auth_vault_status().state == AUTH_UNPROVISIONED);
  }

  // Without a key agreement there is no shared secret, so there is nothing to
  // decrypt and nothing to set.
  fresh();
  assert(auth_vault_set_pin(1, blob, 64, mac, 16, peer, 65) == AUTH_DENIED);
  assert(auth_test_transients_zero());
}

void test_authenticator(void) {
  host_private[31] = 1;
  assert(ecdsa_get_public_key65(&nist256p1, host_private, peer) == 0);
  lifecycle();
  pin_change_is_gated_without_side_effects();
  independent_denials();
  retries();
  failures();
  lengths();
  set_pin_from_platform();
  puts("native authenticator lifecycle/retries/failures/lengths/set-pin: PASS");
}
