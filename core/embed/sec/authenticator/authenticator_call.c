#include <sec/authenticator_call.h>
#include <string.h>
#include "authenticator_backend.h"
#include "memzero.h"

static bool disjoint(const void *a, size_t an, const void *b, size_t bn) {
  uintptr_t aa = (uintptr_t)a, bb = (uintptr_t)b;
  if (!an || !bn) return true;
  if (aa > UINTPTR_MAX - an || bb > UINTPTR_MAX - bn) return false;
  return aa + an <= bb || bb + bn <= aa;
}
static bool optional(const void *p, size_t len, auth_read_probe read) {
  return len == 0 ? p == NULL : read(p, len);
}
static auth_result invalid(void) {
  auth_result result = auth_vault_clear_session();
  return result == AUTH_OK ? AUTH_INVALID_ARGUMENT : AUTH_ERROR;
}
static auth_result clear(void *area, size_t len, auth_result result) {
  memzero(area, len);
  if (!auth_backend_zeroized(area, len)) {
    auth_vault_clear_session();
    return AUTH_ERROR;
  }
  return result;
}
auth_result auth_call_provision(const uint8_t *pin, size_t len,
                                auth_read_probe read) {
  if (len != 16 || !read(pin, len)) return invalid();
  uint8_t copy[16] = {0};
  memcpy(copy, pin, 16);
  auth_result result = auth_vault_provision(copy, 16);
  return clear(copy, sizeof(copy), result);
}
auth_result auth_call_change(const uint8_t *old_pin, size_t old_len,
                             const uint8_t *new_pin, size_t new_len,
                             auth_read_probe read) {
  if (old_len != 16 || new_len != 16 || !read(old_pin, 16) ||
      !read(new_pin, 16))
    return invalid();
  uint8_t copy[32] = {0};
  memcpy(copy, old_pin, 16);
  memcpy(copy + 16, new_pin, 16);
  auth_result result = auth_vault_change_pin(copy, 16, copy + 16, 16);
  return clear(copy, sizeof(copy), result);
}
auth_result auth_call_public(uint8_t *out, size_t len, auth_write_probe write) {
  if (len != 65 || !write(out, len)) return invalid();
  uint8_t copy[65] = {0};
  auth_result result = auth_vault_key_agreement(copy, sizeof(copy));
  memcpy(out, copy, sizeof(copy));
  result = clear(copy, sizeof(copy), result);
  if (result != AUTH_OK) memzero(out, len);
  return result;
}
auth_result auth_call_status(auth_status *out, auth_write_probe write) {
  if (!write(out, sizeof(*out))) return invalid();
  auth_status status = auth_vault_status();
  memcpy(out, &status, sizeof(status));
  return clear(&status, sizeof(status), AUTH_OK);
}
auth_result auth_call_issue(const auth_token_request *request,
                            auth_read_probe read, auth_write_probe write) {
  if (!read(request, sizeof(*request))) return invalid();
  struct {
    auth_token_request request;
    // 32 bytes: protocol 2 sends the encrypted PIN hash with a leading IV.
    uint8_t pin[32], rp[32], peer[65], encrypted[48];
    size_t written;
  } copy = {0};
  memcpy(&copy.request, request, sizeof(*request));
  auth_token_request *r = &copy.request;
  auth_result result = AUTH_INVALID_ARGUMENT;
  // Each protocol pins one ciphertext length, checked before the pointer is
  // probed so a wrong length can never widen what gets read out of the
  // application.
  if ((r->protocol != 1 && r->protocol != 2) ||
      r->pin_len != (r->protocol == 2 ? 32u : 16u) || r->peer_len != 65 ||
      !r->permissions || (r->permissions & ~0x3f) ||
      (r->rp_len != 0 && r->rp_len != 32) ||
      ((r->permissions & 3) && r->rp_len != 32) ||
      r->capacity < (r->protocol == 2 ? 48 : 32) || r->capacity > 48 ||
      !read(r->pin, r->pin_len) || !read(r->peer, 65) ||
      !optional(r->rp, r->rp_len, read) || !write(r->encrypted, r->capacity) ||
      !write(r->written, sizeof(size_t)) ||
      !disjoint(r->encrypted, r->capacity, r->written, sizeof(size_t)))
    goto done;
  const void *inputs[] = {request, r->pin, r->peer, r->rp};
  const size_t sizes[] = {sizeof(*request), r->pin_len, 65, r->rp_len};
  for (size_t i = 0; i < 4; i++)
    if (!disjoint(r->encrypted, r->capacity, inputs[i], sizes[i]) ||
        !disjoint(r->written, sizeof(size_t), inputs[i], sizes[i]))
      goto done;
  memcpy(copy.pin, r->pin, r->pin_len);
  memcpy(copy.peer, r->peer, 65);
  if (r->rp_len) memcpy(copy.rp, r->rp, 32);
  result = auth_vault_issue_token(copy.pin, r->pin_len, r->protocol,
                                  r->permissions, r->rp_len ? copy.rp : NULL,
                                  r->rp_len, copy.peer, 65, copy.encrypted,
                                  sizeof(copy.encrypted), &copy.written);
  // Erase copies before returning any public output. Keep destinations locally.
  uint8_t *out = r->encrypted;
  size_t capacity = r->capacity;
  size_t *written = r->written;
  memcpy(out, copy.encrypted, capacity);
  size_t length = copy.written;
  result = clear(&copy, sizeof(copy), result);
  if (result != AUTH_OK) {
    memzero(out, capacity);
    length = 0;
  }
  memcpy(written, &length, sizeof(length));
  return result;
done:
  clear(&copy, sizeof(copy), result);
  return invalid();
}
auth_result auth_call_set_pin(const auth_set_pin_request *request,
                              auth_read_probe read) {
  if (!read(request, sizeof(*request))) return invalid();
  struct {
    auth_set_pin_request request;
    // 80 bytes: protocol 2 sends the padded PIN with a leading IV.
    uint8_t new_pin[80], param[32], peer[65];
  } copy = {0};
  memcpy(&copy.request, request, sizeof(*request));
  auth_set_pin_request *r = &copy.request;
  auth_result result = AUTH_INVALID_ARGUMENT;
  // Both lengths are pinned by the protocol before either pointer is probed, so
  // a wrong length cannot widen a read. Nothing is written back, so unlike the
  // token path there is no output range and nothing here can alias one.
  if ((r->protocol != 1 && r->protocol != 2) ||
      r->new_pin_len != (r->protocol == 2 ? 80u : 64u) ||
      r->param_len != (r->protocol == 2 ? 32u : 16u) || r->peer_len != 65 ||
      !read(r->new_pin, r->new_pin_len) || !read(r->param, r->param_len) ||
      !read(r->peer, 65))
    goto done;
  memcpy(copy.new_pin, r->new_pin, r->new_pin_len);
  memcpy(copy.param, r->param, r->param_len);
  memcpy(copy.peer, r->peer, 65);
  result = auth_vault_set_pin(r->protocol, copy.new_pin, r->new_pin_len,
                              copy.param, r->param_len, copy.peer, 65);
  // The local copy carries the user's PIN, so it is erased before the result is
  // reported rather than after.
  return clear(&copy, sizeof(copy), result);
done:
  clear(&copy, sizeof(copy), result);
  return invalid();
}
auth_result auth_call_check(const auth_mac_request *request,
                            auth_read_probe read) {
  if (!read(request, sizeof(*request))) return invalid();
  struct {
    auth_mac_request request;
    uint8_t message[1024], param[32], rp[32];
  } copy = {0};
  memcpy(&copy.request, request, sizeof(*request));
  auth_mac_request *r = &copy.request;
  auth_result result = AUTH_INVALID_ARGUMENT;
  if ((r->protocol != 1 && r->protocol != 2) ||
      r->param_len != (r->protocol == 1 ? 16 : 32) || r->message_len > 1024 ||
      !r->permissions || (r->permissions & ~0x3f) ||
      (r->rp_len != 0 && r->rp_len != 32) || !read(r->param, r->param_len) ||
      !optional(r->rp, r->rp_len, read) ||
      (r->message_len && !read(r->message, r->message_len)))
    goto done;
  if (r->message_len) memcpy(copy.message, r->message, r->message_len);
  memcpy(copy.param, r->param, r->param_len);
  if (r->rp_len) memcpy(copy.rp, r->rp, r->rp_len);
  result = auth_vault_check_auth(r->protocol, copy.message, r->message_len,
                                 copy.param, r->param_len, r->permissions,
                                 r->rp_len ? copy.rp : NULL, r->rp_len);
done:
  result = clear(&copy, sizeof(copy), result);
  if (result == AUTH_INVALID_ARGUMENT) return invalid();
  return result;
}

static bool id_range(const uint8_t *id, size_t len, auth_read_probe read) {
  return len >= 78 && len <= AUTH_CREDENTIAL_ID_MAX && read(id, len);
}
static bool public_ranges(void *out, size_t size, const void *request,
                          size_t request_len, const uint8_t *rp,
                          const uint8_t *input, size_t input_len,
                          auth_read_probe read, auth_write_probe write) {
  return read(rp, 32) && write(out, size) &&
         disjoint(out, size, request, request_len) &&
         disjoint(out, size, rp, 32) && disjoint(out, size, input, input_len);
}
auth_result auth_call_credential_create(const auth_create_request *request,
                                        auth_read_probe read,
                                        auth_write_probe write) {
  if (!read(request, sizeof(*request))) return invalid();
  struct {
    auth_create_request r;
    uint8_t rp[32], metadata[AUTH_METADATA_MAX];
    auth_credential_public out;
  } copy = {0};
  memcpy(&copy.r, request, sizeof(*request));
  auth_create_request *r = &copy.r;
  if (r->metadata_len < 10 || r->metadata_len > AUTH_METADATA_MAX ||
      (r->algorithm != -7 && r->algorithm != -8) ||
      !read(r->metadata, r->metadata_len) ||
      !public_ranges(r->out, sizeof(*r->out), request, sizeof(*request), r->rp,
                     r->metadata, r->metadata_len, read, write)) {
    clear(&copy, sizeof(copy), AUTH_INVALID_ARGUMENT);
    return invalid();
  }
  memcpy(copy.rp, r->rp, 32);
  memcpy(copy.metadata, r->metadata, r->metadata_len);
  auth_result result = auth_credential_create(
      copy.rp, r->algorithm, copy.metadata, r->metadata_len, &copy.out);
  auth_credential_public *out = r->out;
  memcpy(out, &copy.out, sizeof(*out));
  result = clear(&copy, sizeof(copy), result);
  if (result != AUTH_OK) memzero(out, sizeof(*out));
  return result;
}
auth_result auth_call_credential_open(const auth_open_request *request,
                                      auth_read_probe read,
                                      auth_write_probe write) {
  if (!read(request, sizeof(*request))) return invalid();
  struct {
    auth_open_request r;
    uint8_t rp[32], id[AUTH_CREDENTIAL_ID_MAX];
    auth_credential_public out;
  } copy = {0};
  memcpy(&copy.r, request, sizeof(*request));
  auth_open_request *r = &copy.r;
  if (!id_range(r->id, r->id_len, read) ||
      !public_ranges(r->out, sizeof(*r->out), request, sizeof(*request), r->rp,
                     r->id, r->id_len, read, write)) {
    clear(&copy, sizeof(copy), AUTH_INVALID_ARGUMENT);
    return invalid();
  }
  memcpy(copy.rp, r->rp, 32);
  memcpy(copy.id, r->id, r->id_len);
  auth_result result =
      auth_credential_open(copy.id, r->id_len, copy.rp, &copy.out);
  auth_credential_public *out = r->out;
  memcpy(out, &copy.out, sizeof(*out));
  result = clear(&copy, sizeof(copy), result);
  if (result != AUTH_OK) memzero(out, sizeof(*out));
  return result;
}
auth_result auth_call_credential_sign(const auth_sign_request *request,
                                      auth_read_probe read,
                                      auth_write_probe write) {
  if (!read(request, sizeof(*request))) return invalid();
  struct {
    auth_sign_request r;
    uint8_t rp[32], id[AUTH_CREDENTIAL_ID_MAX], message[1024], out[72];
    size_t written;
  } copy = {0};
  memcpy(&copy.r, request, sizeof(*request));
  auth_sign_request *r = &copy.r;
  if (!id_range(r->id, r->id_len, read) || !r->message_len ||
      r->message_len > 1024 || (r->algorithm != -7 && r->algorithm != -8) ||
      !read(r->message, r->message_len) ||
      !public_ranges(r->out, 72, request, sizeof(*request), r->rp, r->id,
                     r->id_len, read, write) ||
      !disjoint(r->out, 72, r->message, r->message_len) ||
      !write(r->written, sizeof(size_t)) ||
      !disjoint(r->written, sizeof(size_t), r->out, 72) ||
      !disjoint(r->written, sizeof(size_t), request, sizeof(*request)) ||
      !disjoint(r->written, sizeof(size_t), r->rp, 32) ||
      !disjoint(r->written, sizeof(size_t), r->id, r->id_len) ||
      !disjoint(r->written, sizeof(size_t), r->message, r->message_len)) {
    clear(&copy, sizeof(copy), AUTH_INVALID_ARGUMENT);
    return invalid();
  }
  memcpy(copy.rp, r->rp, 32);
  memcpy(copy.id, r->id, r->id_len);
  memcpy(copy.message, r->message, r->message_len);
  auth_result result = auth_credential_sign(
      copy.id, r->id_len, copy.rp, r->algorithm, copy.message, r->message_len,
      r->attesting, copy.out, &copy.written);
  uint8_t *out = r->out;
  size_t *written = r->written;
  size_t length = copy.written;
  memcpy(out, copy.out, 72);
  result = clear(&copy, sizeof(copy), result);
  if (result != AUTH_OK) {
    memzero(out, 72);
    length = 0;
  }
  memcpy(written, &length, sizeof(length));
  return result;
}
auth_result auth_call_credential_hmac(const auth_hmac_request *request,
                                      auth_read_probe read,
                                      auth_write_probe write) {
  if (!read(request, sizeof(*request))) return invalid();
  struct {
    auth_hmac_request r;
    uint8_t rp[32], id[AUTH_CREDENTIAL_ID_MAX], salts[64], out[64];
  } copy = {0};
  memcpy(&copy.r, request, sizeof(*request));
  auth_hmac_request *r = &copy.r;
  if (!id_range(r->id, r->id_len, read) ||
      (r->salts_len != 32 && r->salts_len != 64) ||
      !read(r->salts, r->salts_len) ||
      !public_ranges(r->out, 64, request, sizeof(*request), r->rp, r->id,
                     r->id_len, read, write) ||
      !disjoint(r->out, 64, r->salts, r->salts_len)) {
    clear(&copy, sizeof(copy), AUTH_INVALID_ARGUMENT);
    return invalid();
  }
  memcpy(copy.rp, r->rp, 32);
  memcpy(copy.id, r->id, r->id_len);
  memcpy(copy.salts, r->salts, r->salts_len);
  auth_result result = auth_credential_hmac_secret(
      copy.id, r->id_len, copy.rp, copy.salts, r->salts_len, copy.out);
  uint8_t *out = r->out;
  memcpy(out, copy.out, 64);
  result = clear(&copy, sizeof(copy), result);
  if (result != AUTH_OK) memzero(out, 64);
  return result;
}
auth_result auth_call_resident_get(uint8_t index, auth_credential_public *out,
                                   auth_write_probe write) {
  if (index >= 100 || !write(out, sizeof(*out))) return invalid();
  auth_credential_public copy = {0};
  auth_result result = auth_resident_get(index, &copy);
  memcpy(out, &copy, sizeof(copy));
  result = clear(&copy, sizeof(copy), result);
  if (result != AUTH_OK) memzero(out, sizeof(*out));
  return result;
}
auth_result auth_call_resident_set(uint8_t index,
                                   const auth_open_request *request,
                                   auth_read_probe read) {
  if (index > AUTH_RESIDENT_ANY || !read(request, sizeof(*request)))
    return invalid();
  struct {
    auth_open_request r;
    uint8_t rp[32], id[AUTH_CREDENTIAL_ID_MAX];
  } copy = {0};
  memcpy(&copy.r, request, sizeof(*request));
  auth_open_request *r = &copy.r;
  if (r->out || !read(r->rp, 32) || !id_range(r->id, r->id_len, read)) {
    clear(&copy, sizeof(copy), AUTH_INVALID_ARGUMENT);
    return invalid();
  }
  memcpy(copy.rp, r->rp, 32);
  memcpy(copy.id, r->id, r->id_len);
  auth_result result = auth_resident_set(index, copy.id, r->id_len, copy.rp);
  return clear(&copy, sizeof(copy), result);
}
auth_result auth_call_resident_delete(uint8_t index) {
  if (index >= 100) return invalid();
  return auth_resident_delete(index);
}
auth_result auth_call_resident_scan(const uint8_t *rp, uint8_t *out,
                                    auth_read_probe read,
                                    auth_write_probe write) {
  if (!write(out, AUTH_RESIDENT_CAPACITY)) return invalid();
  // A null filter is the documented "every slot I may see", so it is not an
  // invalid pointer; anything else has to be readable application memory.
  if (rp != NULL && !read(rp, 32)) return invalid();
  struct {
    uint8_t filter[32];
    uint8_t map[AUTH_RESIDENT_CAPACITY];
  } copy = {0};
  if (rp != NULL) memcpy(copy.filter, rp, 32);
  auth_result result =
      auth_resident_scan(rp != NULL ? copy.filter : NULL, copy.map);
  memcpy(out, copy.map, AUTH_RESIDENT_CAPACITY);
  result = clear(&copy, sizeof(copy), result);
  if (result != AUTH_OK) memzero(out, AUTH_RESIDENT_CAPACITY);
  return result;
}
