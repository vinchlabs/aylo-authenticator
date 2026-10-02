#include <sec/authenticator.h>
#include <string.h>
#include "aes/aes.h"
#include "authenticator_backend.h"
#include "chacha20poly1305/rfc7539.h"
#include "consteq.h"
#include "ecdsa.h"
#include "ed25519-donna/ed25519.h"
#include "hmac.h"
#include "memzero.h"
#include "nist256p1.h"
#include "replica_records.h"
#include "sha2.h"

static struct {
  uint8_t private_key[32], token[32], rp[32], root[32];
  uint8_t protocol, permissions, consecutive;
  bool agreement, issued, bound, initialized, fault;
} session;

// Single fixed native work area. Cleared at every API return.
static struct {
  uint8_t root[32], verifier[32], output[32], kek[32], point[65];
  uint8_t prk[32], aes_key[32], digest[32], iv[16], record[AUTH_RECORD_SIZE];
  // The CTAP pinUvAuth hash, recovered from platform ciphertext. It is the one
  // secret the platform sends us rather than one we derive, and it exists here
  // only between the decrypt and the OPTIGA verification.
  uint8_t pin_hash[16];
  // Protocol 2 authenticates with a key separate from the one it encrypts with;
  // protocol 1 uses the same value for both. Kept apart from aes_key either way
  // so the two purposes never share a buffer.
  uint8_t hmac_key[32];
  // The 64-byte zero-padded UTF-8 PIN, likewise recovered from ciphertext and
  // needed only long enough to be measured, validated and hashed.
  uint8_t pin_padded[64];
  // Up to three deduplicated root envelopes. Ciphertext, not secrets, but the
  // whole struct is zeroized by finish() regardless.
  uint8_t candidates[AUTH_BACKEND_ROOT_CANDIDATES][AUTH_RECORD_SIZE];
  aes_encrypt_ctx aes;
  aes_decrypt_ctx aes_dec;
  chacha20poly1305_ctx aead;
} scratch;

static void credential_invalidate(void);
static void invalidate(void) {
  credential_invalidate();
  memzero(session.private_key, sizeof(session.private_key));
  memzero(session.token, sizeof(session.token));
  memzero(session.rp, sizeof(session.rp));
  memzero(session.root, sizeof(session.root));
  session.agreement = session.issued = session.bound = false;
  session.permissions = session.protocol = 0;
}

static auth_result finish(auth_result result) {
  memzero(&scratch, sizeof(scratch));
  bool clean = auth_backend_zeroized(&scratch, sizeof(scratch));
  if (!clean || result != AUTH_OK) invalidate();
  if (!clean || result == AUTH_ERROR) {
    session.fault = true;
    result = AUTH_ERROR;
  }
  return result;
}

// HKDF-SHA256, one 32-byte block; fixed versioned labels are not public APIs.
static void hkdf(const uint8_t *input, size_t len, const char *label,
                 uint8_t out[32]) {
  uint8_t salt[32] = {0}, prk[32] = {0};
  HMAC_SHA256_CTX ctx = {0};
  const uint8_t one = 1;
  hmac_sha256(salt, sizeof(salt), input, len, prk);
  hmac_sha256_Init(&ctx, prk, sizeof(prk));
  hmac_sha256_Update(&ctx, (const uint8_t *)label, strlen(label));
  hmac_sha256_Update(&ctx, &one, 1);
  hmac_sha256_Final(&ctx, out);
  memzero(salt, sizeof(salt));
  memzero(prk, sizeof(prk));
  memzero(&ctx, sizeof(ctx));
}

static void pin_expand(const uint8_t pin[16]) {
  hkdf(pin, 16, "trezor authenticator PIN v1", scratch.verifier);
}

static bool wrap(void) {
  scratch.record[0] = 0xa1;
  scratch.record[1] = 1;
  if (!auth_backend_random(scratch.record + 2, 12)) return false;
  hkdf(scratch.output, 32, "trezor authenticator root KEK v1", scratch.kek);
  rfc7539_init(&scratch.aead, scratch.kek, scratch.record + 2);
  rfc7539_auth(&scratch.aead, scratch.record, 2);
  chacha20poly1305_encrypt(&scratch.aead, scratch.root, scratch.record + 14,
                           32);
  rfc7539_finish(&scratch.aead, 2, 32, scratch.record + 46);
  // The root is passed alongside the envelope because the envelope lands inside
  // an authenticated snapshot keyed from it.
  return auth_backend_write(scratch.root, scratch.record);
}

// True when the device holds a root envelope at all. Replaces the old
// "auth_backend_read() succeeded" test: after a torn root commit there can be
// up to three distinct envelopes, so presence is a count rather than a read.
static auth_result stored_present(uint8_t *count_out) {
  uint8_t count = 0;
  auth_result result = auth_backend_root_candidates(scratch.candidates, &count);
  if (count_out) *count_out = count;
  if (result != AUTH_OK) return result;
  return count ? AUTH_OK : AUTH_UNPROVISIONED;
}

static auth_result unwrap(const uint8_t *pin) {
  if (session.fault || !session.initialized) return AUTH_ERROR;
  if (session.consecutive >= 3) return AUTH_PIN_AUTH_BLOCKED;
  auth_result result = stored_present(NULL);
  if (result != AUTH_OK) return result;
  uint8_t rem = 0;
  if (!auth_backend_remaining(&rem) || rem > 8) return AUTH_ERROR;
  if (rem == 0) {
    return auth_vault_wipe() == AUTH_OK ? AUTH_PIN_BLOCKED : AUTH_ERROR;
  }
  pin_expand(pin);
  result = auth_backend_verify_pin(scratch.verifier, scratch.output);
  if (result == AUTH_PIN_INVALID || result == AUTH_PIN_BLOCKED) {
    session.consecutive++;
    if (!auth_backend_remaining(&rem) || rem > 8) return AUTH_ERROR;
    if (rem == 0 || result == AUTH_PIN_BLOCKED) {
      return auth_vault_wipe() == AUTH_OK ? AUTH_PIN_BLOCKED : AUTH_ERROR;
    }
    return session.consecutive == 3 ? AUTH_PIN_AUTH_BLOCKED : AUTH_PIN_INVALID;
  }
  if (result != AUTH_OK || !auth_backend_remaining(&rem) || rem != 8)
    return AUTH_ERROR;
  hkdf(scratch.output, 32, "trezor authenticator root KEK v1", scratch.kek);
  // The envelope parsing and the AEAD used to live here. They now live in one
  // place behind the backend, because the answer is no longer "open the
  // envelope": every candidate that opens under this KEK must yield the same
  // root, and that root must authenticate a stored snapshot before it counts.
  result = auth_backend_unlock(scratch.kek, scratch.root);
  if (result != AUTH_OK) {
    // The PIN was accepted by the secure element to get here, so a failure now
    // is a damaged or unreadable vault, never a retry.
    memzero(scratch.root, sizeof(scratch.root));
    return result;
  }
  session.consecutive = 0;
  return AUTH_OK;
}

auth_result auth_vault_init(void) {
  // Soft reinitialization cannot bypass the reconnect-only soft block.
  invalidate();
  if (!auth_backend_init()) return finish(AUTH_ERROR);
  session.initialized = true;
  session.fault = false;
  auth_result stored = stored_present(NULL);
  if (stored == AUTH_OK) {
    uint8_t rem = 0;
    if (!auth_backend_remaining(&rem) || rem > 8) return finish(AUTH_ERROR);
    if (rem == 0) return auth_vault_wipe();
  } else if (stored == AUTH_MIGRATION_REQUIRED) {
    // Surfaced rather than resolved: nothing has been read, erased, or written.
    return finish(AUTH_MIGRATION_REQUIRED);
  } else if (stored != AUTH_UNPROVISIONED)
    return finish(AUTH_ERROR);
  return finish(AUTH_OK);
}

auth_status auth_vault_status(void) {
  auth_status status = {.state = AUTH_ERROR,
                        .consecutive = session.consecutive};
  if (!session.initialized) auth_vault_init();
  // A latched failure still permits idempotent backend cleanup, never issuance.
  auth_result stored = stored_present(NULL);
  if (!session.fault) {
    status.state = stored;
    if (status.state == AUTH_OK) {
      // The first candidate's shape is a cheap sanity check; authenticity is
      // the unlock path's job, not this one's.
      if (!auth_backend_remaining(&status.retries) || status.retries > 8 ||
          scratch.candidates[0][0] != 0xa1 || scratch.candidates[0][1] != 1)
        status.state = AUTH_ERROR;
      else if (status.retries == 0) {
        status.state =
            auth_vault_wipe() == AUTH_OK ? AUTH_UNPROVISIONED : AUTH_ERROR;
      } else if (session.consecutive >= 3)
        status.state = AUTH_PIN_AUTH_BLOCKED;
    }
  }
  memzero(&scratch, sizeof(scratch));
  if (!auth_backend_zeroized(&scratch, sizeof(scratch)) ||
      status.state == AUTH_ERROR) {
    invalidate();
    session.fault = true;
    status.state = AUTH_ERROR;
  }
  status.consecutive = session.consecutive;
  return status;
}

auth_result auth_vault_provision(const uint8_t *pin, size_t len) {
  invalidate();
  if (!pin || len != 16) return finish(AUTH_INVALID_ARGUMENT);
  if (!session.initialized) auth_vault_init();
  if (session.fault) return finish(AUTH_ERROR);
  auth_result result = stored_present(NULL);
  if (result == AUTH_OK) return finish(AUTH_DENIED);
  // Migration-required and unreadable media both land here and must not be
  // provisioned over. Only a genuinely unprovisioned device continues.
  if (result != AUTH_UNPROVISIONED) return finish(result);
  pin_expand(pin);
  if (!auth_backend_random(scratch.root, 32) ||
      auth_backend_set_pin(scratch.verifier, scratch.output) != AUTH_OK ||
      !wrap()) {
    auth_backend_wipe();
    return finish(AUTH_ERROR);
  }
  session.consecutive = 0;
  return finish(AUTH_OK);
}

// Changing an existing PIN is intentionally unavailable in this release.
//
// The operation is not power-safe and cannot be made power-safe by replicating
// flash. The sequence it requires is:
//
//   1. verify the old PIN, which consumes an OPTIGA retry;
//   2. re-provision the OPTIGA PIN secret so only the NEW PIN unlocks it;
//   3. re-encrypt the root envelope under the new PIN-derived KEK and store it.
//
// Steps 2 and 3 live on different pieces of hardware and cannot be made a
// single transaction. A power loss between them leaves the secure element
// accepting only the new PIN while every stored envelope -- in all three
// replicas, since they are copies of the same bytes -- is still sealed under
// the old KEK. The root is then permanently unrecoverable and every credential
// is lost. Triple replication does not help: the replicas are identical, so
// they are all wrong together.
//
// The previous implementation "handled" that by calling auth_backend_wipe() on
// failure, i.e. deliberately destroying the vault. A real power cut never
// reaches that path at all, so the device was simply left bricked with its
// credentials gone.
//
// This returns AUTH_DENIED unconditionally and performs no work whatsoever: no
// argument validation, no lazy auth_vault_init(), no invalidate(), and no
// finish() (finish() invalidates the session for any non-OK result, which would
// itself be an observable side effect). Flash, OPTIGA state, the retry counter,
// and any live authorized session are therefore provably untouched.
//
// The supported transition remains an explicit wipe followed by fresh
// provisioning. A power-safe rekey needs a separate design built on a stable
// hardware-sealed vault key or an equivalent second hardware transaction slot.
auth_result auth_vault_change_pin(const uint8_t *old_pin, size_t old_len,
                                  const uint8_t *new_pin, size_t new_len) {
  (void)old_pin;
  (void)old_len;
  (void)new_pin;
  (void)new_len;
  return AUTH_DENIED;
}

auth_result auth_vault_key_agreement(uint8_t *public_key, size_t len) {
  invalidate();
  if (!public_key || len != 65) return finish(AUTH_INVALID_ARGUMENT);
  memzero(public_key, len);
  if (!session.initialized) auth_vault_init();
  if (session.fault) return finish(AUTH_ERROR);
  for (size_t attempt = 0; attempt < 8; attempt++) {
    if (!auth_backend_random(session.private_key, 32))
      return finish(AUTH_ERROR);
    if (ecdsa_get_public_key65(&nist256p1, session.private_key, public_key) ==
        0) {
      session.agreement = true;
      auth_result result = finish(AUTH_OK);
      if (result != AUTH_OK) memzero(public_key, len);
      return result;
    }
  }
  memzero(public_key, len);
  return finish(AUTH_ERROR);
}

// Derives the pinUvAuth shared-secret AES key from an ECDH point the caller has
// already computed into scratch.point, and recovers `plain_len` bytes of
// platform ciphertext into `out`.
//
// Protocol 1 keys with SHA-256 over the shared X coordinate and encrypts under
// a zero IV; protocol 2 keys with HKDF and prepends a random IV. Both leave the
// CBC chaining block in scratch.iv, so a caller that goes on to encrypt must
// clear it rather than inherit it.
static bool recover_from_platform(uint8_t protocol, const uint8_t *ciphertext,
                                  size_t plain_len, uint8_t *out) {
  if (protocol == 1)
    sha256_Raw(scratch.point + 1, 32, scratch.aes_key);
  else
    hkdf(scratch.point + 1, 32, "CTAP2 AES key", scratch.aes_key);
  if (aes_decrypt_key256(scratch.aes_key, &scratch.aes_dec) != 0) return false;
  memzero(scratch.iv, sizeof(scratch.iv));
  if (protocol == 2) memcpy(scratch.iv, ciphertext, 16);
  return aes_cbc_decrypt(ciphertext + (protocol == 2 ? 16 : 0), out,
                         (int)plain_len, scratch.iv, &scratch.aes_dec) == 0;
}

auth_result auth_vault_issue_token(const uint8_t *pin_hash_enc,
                                   size_t pin_hash_enc_len, uint8_t protocol,
                                   uint8_t permissions, const uint8_t *rp,
                                   size_t rp_len, const uint8_t *peer,
                                   size_t peer_len, uint8_t *encrypted,
                                   size_t capacity, size_t *written) {
  if (written) *written = 0;
  if (encrypted && capacity <= 48) memzero(encrypted, capacity);
  // The PIN hash arrives encrypted under the shared secret: 16 bytes for
  // protocol 1, which uses a zero IV, and 32 for protocol 2, which prepends a
  // random one.
  if (!written || !encrypted || !pin_hash_enc ||
      pin_hash_enc_len != (protocol == 2 ? 32u : 16u) ||
      (protocol != 1 && protocol != 2) || !permissions ||
      (permissions & ~0x3f) || (rp_len != 0 && rp_len != 32) ||
      (rp_len && !rp) || ((permissions & 3) && rp_len != 32) || !peer ||
      peer_len != 65 || capacity < (protocol == 2 ? 48 : 32) || capacity > 48)
    return finish(AUTH_INVALID_ARGUMENT);
  if (session.fault) return finish(AUTH_ERROR);
  if (session.consecutive >= 3) return finish(AUTH_PIN_AUTH_BLOCKED);
  if (!session.agreement) return finish(AUTH_DENIED);
  if (peer[0] != 4 ||
      ecdh_multiply(&nist256p1, session.private_key, peer, scratch.point) != 0)
    return finish(AUTH_INVALID_ARGUMENT);
  // Recovered here because this is the only place that holds the shared secret.
  // Decrypting in the application would put both the secret and the PIN hash in
  // unprivileged memory, which is the whole thing this boundary exists to stop.
  if (!recover_from_platform(protocol, pin_hash_enc, 16, scratch.pin_hash))
    return finish(AUTH_ERROR);
  auth_result result = unwrap(scratch.pin_hash);
  if (result != AUTH_OK) return finish(result);
  // Random token is independent of root and PIN; plaintext never leaves native.
  if (!auth_backend_random(session.token, 32)) return finish(AUTH_ERROR);
  // The decrypt above left its chaining block behind, and protocol 1 encrypts
  // under a zero IV, so this must be cleared rather than reused.
  memzero(scratch.iv, sizeof(scratch.iv));
  if (protocol == 2 && !auth_backend_random(scratch.iv, 16))
    return finish(AUTH_ERROR);
  if (aes_encrypt_key256(scratch.aes_key, &scratch.aes) != 0)
    return finish(AUTH_ERROR);
  if (protocol == 2) memcpy(encrypted, scratch.iv, 16);
  if (aes_cbc_encrypt(session.token, encrypted + (protocol == 2 ? 16 : 0), 32,
                      scratch.iv, &scratch.aes) != 0)
    return finish(AUTH_ERROR);
  memzero(session.private_key, 32);
  session.agreement = false;
  session.protocol = protocol;
  session.permissions = permissions;
  session.bound = rp_len != 0;
  if (rp_len) memcpy(session.rp, rp, 32);
  session.issued = true;
  memcpy(session.root, scratch.root, 32);
  result = finish(AUTH_OK);
  if (result == AUTH_OK)
    *written = protocol == 2 ? 48 : 32;
  else
    memzero(encrypted, capacity);
  return result;
}

// Validates UTF-8 and returns the code-point count, or -1 when malformed.
//
// Strict on purpose. Overlong forms, surrogates and scalars above U+10FFFF are
// rejected rather than normalised, because a PIN that the platform and the
// authenticator decode differently is a PIN whose length neither agrees on.
static int utf8_code_points(const uint8_t *text, size_t len) {
  static const uint32_t minimum[4] = {0, 0x80, 0x800, 0x10000};
  size_t index = 0;
  int count = 0;
  while (index < len) {
    const uint8_t first = text[index];
    size_t extra;
    uint32_t value;
    if (first < 0x80) {
      extra = 0;
      value = first;
    } else if ((first & 0xe0) == 0xc0) {
      extra = 1;
      value = first & 0x1fu;
    } else if ((first & 0xf0) == 0xe0) {
      extra = 2;
      value = first & 0x0fu;
    } else if ((first & 0xf8) == 0xf0) {
      extra = 3;
      value = first & 0x07u;
    } else {
      // A continuation byte in leading position, or a five-byte form.
      return -1;
    }
    if (extra > len - index - 1) return -1;
    for (size_t i = 1; i <= extra; i++) {
      const uint8_t next = text[index + i];
      if ((next & 0xc0) != 0x80) return -1;
      value = (value << 6) | (next & 0x3fu);
    }
    if (value < minimum[extra] || value > 0x10ffffu ||
        (value >= 0xd800u && value <= 0xdfffu))
      return -1;
    index += extra + 1;
    count++;
  }
  return count;
}

auth_result auth_vault_set_pin(uint8_t protocol, const uint8_t *new_pin_enc,
                               size_t new_pin_enc_len, const uint8_t *param,
                               size_t param_len, const uint8_t *peer,
                               size_t peer_len) {
  // CTAP setPIN sends the PIN zero-padded to 64 bytes and encrypted under the
  // shared secret: 64 bytes on protocol 1, 80 on protocol 2 with its IV. The
  // MAC is 16 bytes on protocol 1 and 32 on protocol 2.
  if ((protocol != 1 && protocol != 2) || !new_pin_enc ||
      new_pin_enc_len != (protocol == 2 ? 80u : 64u) || !param ||
      param_len != (protocol == 2 ? 32u : 16u) || !peer || peer_len != 65)
    return finish(AUTH_INVALID_ARGUMENT);
  if (session.fault) return finish(AUTH_ERROR);
  if (!session.agreement) return finish(AUTH_DENIED);
  if (peer[0] != 4 ||
      ecdh_multiply(&nist256p1, session.private_key, peer, scratch.point) != 0)
    return finish(AUTH_INVALID_ARGUMENT);

  // CTAP binds the request to the shared secret with a MAC over the ciphertext,
  // and it is checked before anything is decrypted: a caller who does not hold
  // the secret is refused without the PIN ever being recovered.
  //
  // Protocol 1 authenticates with the same key it encrypts with and compares
  // the leading 16 bytes; protocol 2 has a separate HMAC key and compares
  // all 32. The truncation falls out of param_len, the way check_auth() does
  // it.
  if (protocol == 1)
    sha256_Raw(scratch.point + 1, 32, scratch.hmac_key);
  else
    hkdf(scratch.point + 1, 32, "CTAP2 HMAC key", scratch.hmac_key);
  hmac_sha256(scratch.hmac_key, 32, new_pin_enc, new_pin_enc_len,
              scratch.digest);
  if (!consteq(scratch.digest, param, param_len)) return finish(AUTH_DENIED);

  if (!recover_from_platform(protocol, new_pin_enc, 64, scratch.pin_padded))
    return finish(AUTH_ERROR);

  size_t length = 0;
  while (length < sizeof(scratch.pin_padded) && scratch.pin_padded[length] != 0)
    length++;
  // Everything past the string must be zero. A non-zero tail means the platform
  // sent something that is not a padded PIN, and guessing which part it meant
  // is not this code's job.
  for (size_t i = length; i < sizeof(scratch.pin_padded); i++)
    if (scratch.pin_padded[i] != 0) return finish(AUTH_INVALID_ARGUMENT);
  // 63 bytes, not 64: CTAP requires at least one padding byte, so a string
  // filling the whole buffer is indistinguishable from a truncated one.
  if (length > 63) return finish(AUTH_INVALID_ARGUMENT);
  const int code_points = utf8_code_points(scratch.pin_padded, length);
  if (code_points < 0) return finish(AUTH_INVALID_ARGUMENT);
  if (code_points < AUTH_MIN_PIN_CODE_POINTS) return finish(AUTH_PIN_POLICY);

  // The vault's PIN is LEFT(SHA-256(pin), 16), the same value CTAP hashes for
  // pinHashEnc, so provisioning and later verification agree by construction.
  //
  // Held in a local rather than in the work area, because
  // auth_vault_provision() may call auth_vault_init() on its way, and that
  // finishes a call -- which clears the work area out from under the argument
  // still being read. The one stack copy is cleared here since no finish() of
  // ours reaches it.
  uint8_t hash[16] = {0};
  sha256_Raw(scratch.pin_padded, length, scratch.digest);
  memcpy(hash, scratch.digest, sizeof(hash));
  auth_result result = auth_vault_provision(hash, sizeof(hash));
  memzero(hash, sizeof(hash));
  if (!auth_backend_zeroized(hash, sizeof(hash))) {
    auth_vault_clear_session();
    return AUTH_ERROR;
  }
  return result;
}

auth_result auth_vault_check_auth(uint8_t protocol, const uint8_t *message,
                                  size_t len, const uint8_t *param,
                                  size_t param_len, uint8_t permissions,
                                  const uint8_t *rp, size_t rp_len) {
  if ((protocol != 1 && protocol != 2) || !param ||
      param_len != (protocol == 1 ? 16 : 32) || (!message && len) ||
      len > 1024 || !permissions || (permissions & ~0x3f) ||
      (rp_len != 0 && rp_len != 32) || (rp_len && !rp))
    return finish(AUTH_INVALID_ARGUMENT);
  if (session.fault) return finish(AUTH_ERROR);
  if (!session.issued || protocol != session.protocol ||
      (session.permissions & permissions) != permissions ||
      (session.bound && (rp_len != 32 || !consteq(rp, session.rp, 32))))
    return finish(AUTH_DENIED);
  hmac_sha256(session.token, 32, message, len, scratch.digest);
  return finish(consteq(scratch.digest, param, param_len) ? AUTH_OK
                                                          : AUTH_DENIED);
}

auth_result auth_vault_disconnect(void) {
  credential_invalidate();
  memzero(&session, sizeof(session));
  return finish(AUTH_OK);
}

auth_result auth_vault_clear_session(void) {
  invalidate();
  return finish(AUTH_OK);
}

auth_result auth_vault_wipe(void) {
  invalidate();
  session.consecutive = 0;
  return finish(auth_backend_wipe() ? AUTH_OK : AUTH_ERROR);
}

// SLIP-0022-shaped envelope: version[4] || nonce[12] || ciphertext || tag[16].
// This version intentionally has no wallet compatibility or seed dependency.
static const uint8_t credential_version[4] = {0xf1, 0xd0, 3, 0};
static struct {
  uint8_t plain[AUTH_METADATA_MAX + 36], key[32], private_key[32],
      public_key[65];
  // `commit[40]` used to sit here, holding the per-record tag. The snapshot MAC
  // replaced it.
  uint8_t digest[32], signature[64], aad[36], data[AUTH_RESIDENT_RECORD_MAX];
  chacha20poly1305_ctx aead;
} credential_work;

static void credential_invalidate(void) {
  memzero(&credential_work, sizeof(credential_work));
}

static auth_result credential_finish(auth_result result) {
  memzero(&credential_work, sizeof(credential_work));
  if (!auth_backend_zeroized(&credential_work, sizeof(credential_work)))
    result = AUTH_ERROR;
  return finish(result);
}
static auth_result public_finish(auth_result result,
                                 auth_credential_public *out) {
  result = credential_finish(result);
  if (result != AUTH_OK && out) memzero(out, sizeof(*out));
  return result;
}
static bool authorized(uint8_t permission, const uint8_t *rp) {
  return session.initialized && !session.fault && session.issued &&
         (session.permissions & permission) == permission &&
         (!session.bound || (rp && consteq(session.rp, rp, 32)));
}
static bool metadata_valid(const uint8_t *m, size_t len, const uint8_t rp[32]) {
  if (!m || !rp || len < 10 || len > AUTH_METADATA_MAX || m[0] != 1 ||
      m[1] > 1 || m[2] != 3)
    return false;
  size_t rp_len = ((size_t)m[3] << 8) | m[4];
  if (!rp_len || rp_len > 253 || m[5] > 64 || m[6] > 100 || m[7] > 100 ||
      m[8] > 100 || len != 9 + rp_len + m[5] + m[6] + m[7] + m[8])
    return false;
  sha256_Raw(m + 9, rp_len, credential_work.digest);
  return consteq(credential_work.digest, rp, 32);
}
static bool credential_key(int32_t algorithm) {
  hkdf(credential_work.plain, 32,
       algorithm == -7 ? "trezor authenticator ES256 v1"
                       : "trezor authenticator Ed25519 v1",
       credential_work.private_key);
  // Invalid P-256 scalars fail closed. Probability is negligible; no modulo
  // bias.
  if (algorithm == -7)
    return ecdsa_get_public_key65(&nist256p1, credential_work.private_key,
                                  credential_work.public_key) == 0;
  if (algorithm != -8) return false;
  ed25519_publickey(credential_work.private_key, credential_work.public_key);
  return true;
}
static void credential_public(const uint8_t *id, size_t id_len,
                              const uint8_t rp[32],
                              auth_credential_public *out) {
  out->algorithm = credential_work.plain[32] == 7 ? -7 : -8;
  out->metadata_len =
      ((size_t)credential_work.plain[34] << 8) | credential_work.plain[35];
  memcpy(out->metadata, credential_work.plain + 36, out->metadata_len);
  if (out->id != id) memcpy(out->id, id, id_len);
  out->id_len = id_len;
  memcpy(out->rp, rp, 32);
  static const uint8_t es[] = {0xa5, 1, 2, 3, 0x26, 0x20, 1, 0x21, 0x58, 0x20};
  static const uint8_t ed[] = {0xa4, 1, 1, 3, 0x27, 0x20, 6, 0x21, 0x58, 0x20};
  if (out->algorithm == -7) {
    memcpy(out->cose, es, sizeof(es));
    memcpy(out->cose + 10, credential_work.public_key + 1, 32);
    out->cose[42] = 0x22;
    out->cose[43] = 0x58;
    out->cose[44] = 0x20;
    memcpy(out->cose + 45, credential_work.public_key + 33, 32);
    out->cose_len = 77;
  } else {
    memcpy(out->cose, ed, sizeof(ed));
    memcpy(out->cose + 10, credential_work.public_key, 32);
    out->cose_len = 42;
  }
}
// Decryption stays native; even public metadata is released only after tag
// check.
static auth_result credential_decode(const uint8_t *id, size_t len,
                                     const uint8_t rp[32]) {
  if (!id || !rp || len < 78 || len > AUTH_CREDENTIAL_ID_MAX ||
      !consteq(id, credential_version, 4))
    return AUTH_INVALID_ARGUMENT;
  size_t ciphertext_len = len - 32;
  if (ciphertext_len > sizeof(credential_work.plain))
    return AUTH_INVALID_ARGUMENT;
  hkdf(session.root, 32, "trezor authenticator credential envelope v1",
       credential_work.key);
  rfc7539_init(&credential_work.aead, credential_work.key, id + 4);
  memcpy(credential_work.aad, id, 4);
  memcpy(credential_work.aad + 4, rp, 32);
  rfc7539_auth(&credential_work.aead, credential_work.aad, 36);
  chacha20poly1305_decrypt(&credential_work.aead, id + 16,
                           credential_work.plain, ciphertext_len);
  rfc7539_finish(&credential_work.aead, 36, ciphertext_len,
                 credential_work.digest);
  if (!consteq(credential_work.digest, id + len - 16, 16)) return AUTH_DENIED;
  size_t metadata_len =
      ((size_t)credential_work.plain[34] << 8) | credential_work.plain[35];
  if (metadata_len + 36 != ciphertext_len || credential_work.plain[33] > 1 ||
      !metadata_valid(credential_work.plain + 36, metadata_len, rp) ||
      credential_work.plain[33] != credential_work.plain[37] ||
      !credential_key(credential_work.plain[32] == 7   ? -7
                      : credential_work.plain[32] == 8 ? -8
                                                       : 0))
    return AUTH_DENIED;
  return AUTH_OK;
}
auth_result auth_credential_create(const uint8_t rp[32], int32_t algorithm,
                                   const uint8_t *metadata, size_t len,
                                   auth_credential_public *out) {
  if (out) memzero(out, sizeof(*out));
  if (!out || (algorithm != -7 && algorithm != -8) ||
      !metadata_valid(metadata, len, rp))
    return public_finish(AUTH_INVALID_ARGUMENT, out);
  if (!authorized(1, rp)) return public_finish(AUTH_DENIED, out);
  if (!auth_backend_random(credential_work.plain, 32) ||
      !auth_backend_random(out->id + 4, 12) || !credential_key(algorithm))
    return public_finish(AUTH_ERROR, out);
  credential_work.plain[32] = -algorithm;
  credential_work.plain[33] = metadata[1];
  credential_work.plain[34] = len >> 8;
  credential_work.plain[35] = len;
  memcpy(credential_work.plain + 36, metadata, len);
  memcpy(out->id, credential_version, 4);
  hkdf(session.root, 32, "trezor authenticator credential envelope v1",
       credential_work.key);
  rfc7539_init(&credential_work.aead, credential_work.key, out->id + 4);
  memcpy(credential_work.aad, out->id, 4);
  memcpy(credential_work.aad + 4, rp, 32);
  rfc7539_auth(&credential_work.aead, credential_work.aad, 36);
  chacha20poly1305_encrypt(&credential_work.aead, credential_work.plain,
                           out->id + 16, len + 36);
  rfc7539_finish(&credential_work.aead, 36, len + 36, out->id + 52 + len);
  credential_public(out->id, len + 68, rp, out);
  return public_finish(AUTH_OK, out);
}
auth_result auth_credential_open(const uint8_t *id, size_t len,
                                 const uint8_t rp[32],
                                 auth_credential_public *out) {
  if (out) memzero(out, sizeof(*out));
  if (!out) return public_finish(AUTH_INVALID_ARGUMENT, out);
  if (!authorized(2, rp)) return public_finish(AUTH_DENIED, out);
  auth_result result = credential_decode(id, len, rp);
  if (result == AUTH_OK) credential_public(id, len, rp, out);
  return public_finish(result, out);
}
auth_result auth_credential_sign(const uint8_t *id, size_t len,
                                 const uint8_t rp[32], int32_t algorithm,
                                 const uint8_t *message, size_t message_len,
                                 bool attesting, uint8_t signature[72],
                                 size_t *written) {
  if (written) *written = 0;
  if (signature) memzero(signature, 72);
  if (!written || !signature || !message || !message_len ||
      message_len > 1024 || (algorithm != -7 && algorithm != -8))
    return credential_finish(AUTH_INVALID_ARGUMENT);
  // An attestation is authorized by the creation it belongs to, and only while
  // the session is bound to the relying party that is registering: a credential
  // attests to its own making, so the permission that made it is the permission
  // that signs for it. An assertion still requires ga, which is what keeps that
  // permission meaning what it says.
  bool permitted = attesting ? (session.bound && authorized(1, rp))
                             : authorized(2, rp);
  auth_result result =
      permitted ? credential_decode(id, len, rp) : AUTH_DENIED;
  if (result == AUTH_OK && credential_work.plain[32] != -algorithm)
    result = AUTH_DENIED;
  if (result == AUTH_OK) {
    if (algorithm == -7) {
      sha256_Raw(message, message_len, credential_work.digest);
      if (ecdsa_sign_digest(&nist256p1, credential_work.private_key,
                            credential_work.digest, credential_work.signature,
                            NULL, NULL) != 0)
        result = AUTH_ERROR;
      else
        *written = ecdsa_sig_to_der(credential_work.signature, signature);
    } else {
      ed25519_sign(message, message_len, credential_work.private_key,
                   signature);
      *written = 64;
    }
  }
  result = credential_finish(result);
  if (result != AUTH_OK) {
    memzero(signature, 72);
    *written = 0;
  }
  return result;
}
auth_result auth_credential_hmac_secret(const uint8_t *id, size_t len,
                                        const uint8_t rp[32],
                                        const uint8_t *salts, size_t salts_len,
                                        uint8_t out[64]) {
  if (out) memzero(out, 64);
  if (!out || !salts || (salts_len != 32 && salts_len != 64))
    return credential_finish(AUTH_INVALID_ARGUMENT);
  auth_result result =
      authorized(2, rp) ? credential_decode(id, len, rp) : AUTH_DENIED;
  if (result == AUTH_OK && !credential_work.plain[33]) result = AUTH_DENIED;
  if (result == AUTH_OK) {
    hkdf(credential_work.plain, 32, "trezor authenticator hmac-secret UV v1",
         credential_work.key);
    hmac_sha256(credential_work.key, 32, salts, 32, out);
    if (salts_len == 64)
      hmac_sha256(credential_work.key, 32, salts + 32, 32, out + 32);
  }
  result = credential_finish(result);
  if (result != AUTH_OK) memzero(out, 64);
  return result;
}

// Reads and validates one resident record.
//
// This used to read two records: the credential and a 40-byte tag whose HMAC,
// keyed from the root, both authenticated it and marked it committed. Neither
// is needed now -- the snapshot MAC authenticates every record in the vault at
// once, and authentication of a complete snapshot is the commit condition -- so
// what is left is the record's own structural validation, which the codec owns.
static auth_result resident_read(uint8_t index, uint16_t *length) {
  auth_result result =
      auth_backend_slot_read(session.root, index, credential_work.data,
                             sizeof(credential_work.data), length);
  if (result != AUTH_OK) return result;
  auth_record_view view;
  return auth_record_decode(credential_work.data, *length, index, &view);
}
auth_result auth_resident_get(uint8_t index, auth_credential_public *out) {
  if (out) memzero(out, sizeof(*out));
  if (!out || index >= 100) return public_finish(AUTH_INVALID_ARGUMENT, out);
  bool management = authorized(4, session.bound ? session.rp : NULL);
  bool assertion = session.bound && authorized(2, session.rp);
  if (!management && !assertion) return public_finish(AUTH_DENIED, out);
  uint16_t length = 0;
  auth_result result = resident_read(index, &length);
  if (result == AUTH_OK) {
    if (session.bound && !consteq(session.rp, credential_work.data + 8, 32))
      result = assertion ? AUTH_UNPROVISIONED : AUTH_DENIED;
    else
      result = credential_decode(credential_work.data + 40, length - 40,
                                 credential_work.data + 8);
    if (result == AUTH_OK)
      credential_public(credential_work.data + 40, length - 40,
                        credential_work.data + 8, out);
  }
  // Empty slot is an expected enumeration result; keep the authorized session.
  if (result == AUTH_UNPROVISIONED) {
    auth_result cleared = credential_finish(AUTH_OK);
    return cleared == AUTH_OK ? result : cleared;
  }
  return public_finish(result, out);
}

// Occupancy of every slot, gathered in one authenticated pass.
typedef struct {
  const uint8_t *filter;
  uint8_t *out;
  auth_result result;
} resident_map_t;

static bool resident_map_visit(void *context, uint8_t index, auth_result status,
                               const uint8_t *record, uint16_t length) {
  resident_map_t *scan = (resident_map_t *)context;
  // An empty slot leaves its zero in place; it is the expected answer, not a
  // failure.
  if (status == AUTH_UNPROVISIONED) return true;
  if (status != AUTH_OK) {
    scan->result = status;
    return false;
  }
  auth_record_view view;
  if (auth_record_decode(record, length, index, &view) != AUTH_OK) {
    // A record that does not decode is damage, and damage must not be reported
    // as an empty slot.
    scan->result = AUTH_ERROR;
    return false;
  }
  // A bound session sees only its own relying party's slots, which is exactly
  // what auth_resident_get answers for a foreign slot. The optional filter then
  // narrows further, so a discovery never learns of slots it did not ask about.
  if (session.bound && !consteq(session.rp, view.rp, 32)) return true;
  if (scan->filter != NULL && !consteq(scan->filter, view.rp, 32)) return true;
  scan->out[index] = 1;
  return true;
}

auth_result auth_resident_scan(const uint8_t rp[32],
                               uint8_t out[AUTH_RESIDENT_CAPACITY]) {
  if (out) memzero(out, AUTH_RESIDENT_CAPACITY);
  if (!out) return credential_finish(AUTH_INVALID_ARGUMENT);
  // The same gate auth_resident_get applies, for the same reason: occupancy is
  // information about stored credentials.
  bool management = authorized(4, session.bound ? session.rp : NULL);
  bool assertion = session.bound && authorized(2, session.rp);
  if (!management && !assertion) return credential_finish(AUTH_DENIED);
  resident_map_t scan = {.filter = rp, .out = out, .result = AUTH_OK};
  auth_result result =
      auth_backend_slot_walk(session.root, resident_map_visit, &scan);
  if (result == AUTH_OK) result = scan.result;
  // An unprovisioned vault is an answer, not an error: nothing is stored, so no
  // slot is occupied, and the zeroed map says precisely that.
  if (result == AUTH_UNPROVISIONED) result = AUTH_OK;
  if (result != AUTH_OK) memzero(out, AUTH_RESIDENT_CAPACITY);
  return credential_finish(result);
}

// CTAP's account ID, which is the user handle inside the authenticated
// metadata. NULL when the metadata is too short to hold one; nothing stored can
// be, because metadata_valid() checked the same arithmetic on the way in.
static const uint8_t *credential_account(const uint8_t *metadata, size_t len,
                                         uint8_t *account_len) {
  if (!metadata || !account_len || len < 10) return NULL;
  size_t rp_len = ((size_t)metadata[3] << 8) | metadata[4];
  if ((size_t)9 + rp_len + (size_t)metadata[5] > len) return NULL;
  *account_len = metadata[5];
  return metadata + 9 + rp_len;
}

// The account of whichever envelope credential_decode() last opened.
static const uint8_t *decoded_account(uint8_t *account_len) {
  size_t meta_len = ((size_t)credential_work.plain[34] << 8) |
                    credential_work.plain[35];
  if (meta_len > AUTH_METADATA_MAX) return NULL;
  return credential_account(credential_work.plain + 36, meta_len, account_len);
}

// What auth_resident_set needs from one pass over the vault: whether this
// credential id already lives in another slot, the generation of the record it
// is about to replace, and -- when the vault was asked to choose the slot --
// whether this relying party already has a record for this account.
typedef struct {
  const uint8_t *id;
  uint16_t len;
  uint8_t index;
  bool management;
  uint32_t generation;
  // First empty slot seen, or AUTH_RESIDENT_ANY while none has been.
  uint8_t chosen;
  // CTAP has one replacement that is not credential management: a credential for
  // a relying party and an account that both already exist replaces the record
  // that is there. Recognising it needs the account of the record being written,
  // and the account is copied in rather than pointed at because opening another
  // envelope overwrites the plaintext the decoder left behind. A user handle is
  // public -- every assertion hands it back -- so the copy holds no secret.
  const uint8_t *rp;
  const uint8_t *account;
  uint8_t account_len;
  bool account_known;
  // The slot holding that record, or AUTH_RESIDENT_ANY while none has been seen.
  uint8_t replacing;
  uint32_t replacing_generation;
  auth_result result;
} resident_set_t;

static bool resident_set_visit(void *context, uint8_t index, auth_result status,
                               const uint8_t *record, uint16_t length) {
  resident_set_t *scan = (resident_set_t *)context;
  if (status == AUTH_UNPROVISIONED) {
    // Remember the first free slot in case the caller asked the vault to
    // choose. The walk still runs to the end: the duplicate-identifier check
    // below has to see every slot, not just the ones before the first gap.
    if (scan->chosen == AUTH_RESIDENT_ANY) scan->chosen = index;
    return true;
  }
  if (status != AUTH_OK) {
    scan->result = status;
    return false;
  }
  if (index != scan->index && length == (uint16_t)(scan->len + 40) &&
      consteq(scan->id, record + 40, scan->len)) {
    scan->result = AUTH_DENIED;
    return false;
  }
  if (index == scan->index) {
    if (!scan->management || !authorized(4, record + 8)) {
      scan->result = AUTH_DENIED;
      return false;
    }
    auth_record_view existing;
    if (auth_record_decode(record, length, index, &existing) != AUTH_OK ||
        auth_record_next_generation(existing.generation, &scan->generation) !=
            AUTH_OK) {
      scan->result = AUTH_ERROR;
      return false;
    }
  }
  if (scan->account_known && scan->replacing == AUTH_RESIDENT_ANY &&
      consteq(record + 8, scan->rp, 32)) {
    // The same relying party, so the account decides. Opening the envelope is
    // the only way to read an account, and the envelope is authenticated: a
    // record that does not open is damage, not a slot to pass over quietly.
    if (credential_decode(record + 40, length - 40, record + 8) != AUTH_OK) {
      scan->result = AUTH_ERROR;
      return false;
    }
    uint8_t held_len = 0;
    const uint8_t *held = decoded_account(&held_len);
    if (held == NULL) {
      scan->result = AUTH_ERROR;
      return false;
    }
    if (held_len == scan->account_len &&
        consteq(held, scan->account, held_len)) {
      auth_record_view existing;
      if (auth_record_decode(record, length, index, &existing) != AUTH_OK ||
          auth_record_next_generation(existing.generation,
                                      &scan->replacing_generation) != AUTH_OK) {
        scan->result = AUTH_ERROR;
        return false;
      }
      scan->replacing = index;
    }
  }
  return true;
}

auth_result auth_resident_set(uint8_t index, const uint8_t *id, size_t len,
                              const uint8_t rp[32]) {
  if (index > AUTH_RESIDENT_ANY)
    return credential_finish(AUTH_INVALID_ARGUMENT);
  bool management = authorized(4, rp);
  bool creation = session.bound && authorized(1, rp);
  auth_result result =
      (management || creation) ? credential_decode(id, len, rp) : AUTH_DENIED;
  if (result != AUTH_OK) return credential_finish(result);
  if (len > AUTH_RESIDENT_ID_MAX) return credential_finish(AUTH_LIMIT_EXCEEDED);
  // Read the account out of the envelope the decode above opened, while it is
  // still there to read: the walk opens other envelopes over the same plaintext.
  // Only a caller that asked the vault to choose can be replacing anything; an
  // explicit index is credential management naming a slot, which is a different
  // operation with a different permission.
  uint8_t account[64];
  uint8_t account_len = 0;
  bool account_known = false;
  if (index == AUTH_RESIDENT_ANY) {
    const uint8_t *found = decoded_account(&account_len);
    if (found == NULL || account_len > sizeof(account))
      return credential_finish(AUTH_ERROR);
    memcpy(account, found, account_len);
    account_known = true;
  }
  // Reject identical credential IDs in other committed slots, and pick up the
  // generation of the record being replaced. Every existing record is
  // authenticated before it is looked at; corruption cannot silently become an
  // empty slot.
  //
  // This was a hundred calls to resident_read, and each one re-authenticated
  // the whole snapshot: a hundred full passes over 57,664 bytes to store one
  // credential, which is where makeCredential's seven seconds on the device
  // came from. The walk authenticates once and presents the same hundred
  // records.
  resident_set_t scan = {
      .id = id,
      .len = (uint16_t)len,
      .index = index,
      .management = management,
      .generation = 1,
      .chosen = AUTH_RESIDENT_ANY,
      .rp = rp,
      .account = account,
      .account_len = account_len,
      .account_known = account_known,
      .replacing = AUTH_RESIDENT_ANY,
      .replacing_generation = 1,
      .result = AUTH_OK,
  };
  result = auth_backend_slot_walk(session.root, resident_set_visit, &scan);
  if (result != AUTH_OK) return credential_finish(result);
  if (scan.result != AUTH_OK) return credential_finish(scan.result);
  if (index == AUTH_RESIDENT_ANY) {
    if (scan.replacing != AUTH_RESIDENT_ANY) {
      // This party's record for this account, replaced where it stands. One
      // authenticated snapshot commit is the only way to do that without a
      // moment in which the account has no record at all, and it needs no free
      // slot: a device with every slot occupied can still replace.
      index = scan.replacing;
      scan.generation = scan.replacing_generation;
    } else if (scan.chosen != AUTH_RESIDENT_ANY) {
      index = scan.chosen;
    } else {
      // Nothing was free. Said as its own result rather than as a denial,
      // because a denial would be indistinguishable from an authorization
      // failure and the caller has to tell a platform which of the two it is.
      return credential_finish(AUTH_STORE_FULL);
    }
  }
  uint32_t generation = scan.generation;
  result = auth_backend_slot_capacity(index, len);
  if (result != AUTH_OK) return credential_finish(result);

  uint16_t record_len = 0;
  result = auth_record_encode(index, generation, rp, id, (uint16_t)len,
                              credential_work.data,
                              sizeof(credential_work.data), &record_len);
  if (result != AUTH_OK) return credential_finish(result);

  // One call. The old path needed three -- invalidate the tag, write the
  // record, write the tag -- and the ordering comments that went with them
  // existed only because those three writes could not be made atomic. A
  // snapshot commit is atomic by construction: the previous snapshot stays
  // authoritative until the new one authenticates in full.
  if (!auth_backend_slot_write(session.root, index, credential_work.data,
                               record_len))
    return credential_finish(AUTH_ERROR);
  uint16_t length = 0;
  result = resident_read(index, &length);
  return credential_finish(
      result == AUTH_OK && length == record_len ? AUTH_OK : AUTH_ERROR);
}
auth_result auth_resident_delete(uint8_t index) {
  if (index >= 100) return credential_finish(AUTH_INVALID_ARGUMENT);
  if (!authorized(4, session.bound ? session.rp : NULL))
    return credential_finish(AUTH_DENIED);
  uint16_t length = 0;
  auth_result result = resident_read(index, &length);
  if (result == AUTH_OK && !authorized(4, credential_work.data + 8))
    return credential_finish(AUTH_DENIED);
  if (result != AUTH_OK && result != AUTH_UNPROVISIONED)
    return credential_finish(result);
  return credential_finish(
      auth_backend_slot_delete(session.root, index) ? AUTH_OK : AUTH_ERROR);
}

#ifdef AUTH_TEST_BACKEND
// A record's generation, which nothing outside the vault can otherwise see. It
// decides which copy a torn write recovers, so a replacement that did not advance
// it could let an old credential come back; that is worth being able to assert.
bool auth_test_record_generation(uint8_t index, uint32_t *out) {
  if (!out || index >= 100) return false;
  uint16_t length = 0;
  auth_record_view view;
  bool ok = resident_read(index, &length) == AUTH_OK;
  if (ok)
    ok = auth_record_decode(credential_work.data, length, index, &view) ==
         AUTH_OK;
  if (ok) *out = view.generation;
  credential_finish(AUTH_OK);
  return ok;
}
bool auth_test_credential_work_zero(void) {
  return auth_backend_zeroized(&credential_work, sizeof(credential_work));
}
bool auth_test_transients_zero(void) {
  uint8_t sum = 0;
  for (size_t i = 0; i < sizeof(scratch); i++)
    sum |= ((const uint8_t *)&scratch)[i];
  for (size_t i = 0; i < 32; i++)
    sum |= session.token[i] | session.private_key[i] | session.rp[i] |
           session.root[i];
  return sum == 0 && !session.issued && !session.agreement;
}
#endif
