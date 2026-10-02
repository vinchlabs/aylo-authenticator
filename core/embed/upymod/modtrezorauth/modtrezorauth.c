#include <io/auth_presence.h>
#include <sec/authenticator.h>
#include "memzero.h"
#include "py/objstr.h"
#include "py/runtime.h"

static void invalid(void) {
  auth_vault_clear_session();
  mp_raise_ValueError(MP_ERROR_TEXT("Invalid authenticator argument"));
}

static mp_buffer_info_t buffer(mp_obj_t obj, size_t min, size_t max) {
  mp_buffer_info_t result = {0};
  if (!mp_get_buffer(obj, &result, MP_BUFFER_READ) || result.len < min ||
      result.len > max)
    invalid();
  return result;
}

static uint8_t number(mp_obj_t obj, uint8_t min, uint8_t max) {
  if (!mp_obj_is_small_int(obj)) invalid();
  mp_int_t value = MP_OBJ_SMALL_INT_VALUE(obj);
  if (value < min || value > max) invalid();
  return value;
}

static mp_buffer_info_t rp_buffer(mp_obj_t obj) {
  mp_buffer_info_t result = {0};
  if (obj != mp_const_none) result = buffer(obj, 32, 32);
  return result;
}

static mp_obj_t status(void) {
  auth_status value = auth_vault_status();
  mp_obj_t items[3] = {MP_OBJ_NEW_SMALL_INT(value.state),
                       MP_OBJ_NEW_SMALL_INT(value.retries),
                       MP_OBJ_NEW_SMALL_INT(value.consecutive)};
  return mp_obj_new_tuple(3, items);
}
static MP_DEFINE_CONST_FUN_OBJ_0(status_obj, status);

static mp_obj_t provision(mp_obj_t pin) {
  mp_buffer_info_t hash = buffer(pin, 16, 16);
  return MP_OBJ_NEW_SMALL_INT(auth_vault_provision(hash.buf, hash.len));
}
static MP_DEFINE_CONST_FUN_OBJ_1(provision_obj, provision);

static mp_obj_t change_pin(mp_obj_t old_pin, mp_obj_t new_pin) {
  mp_buffer_info_t old_hash = buffer(old_pin, 16, 16);
  mp_buffer_info_t new_hash = buffer(new_pin, 16, 16);
  return MP_OBJ_NEW_SMALL_INT(auth_vault_change_pin(
      old_hash.buf, old_hash.len, new_hash.buf, new_hash.len));
}
static MP_DEFINE_CONST_FUN_OBJ_2(change_pin_obj, change_pin);

// Only non-secret public key or protocol ciphertext enters a Python object.
// Allocation exceptions erase native transient state and the local output.
static mp_obj_t output_tuple(auth_result result, uint8_t *out, size_t len,
                             size_t capacity) {
  nlr_buf_t nlr;
  if (nlr_push(&nlr) == 0) {
    mp_obj_t items[2] = {MP_OBJ_NEW_SMALL_INT(result),
                         mp_obj_new_bytes(out, len)};
    mp_obj_t tuple = mp_obj_new_tuple(2, items);
    memzero(out, capacity);
    nlr_pop();
    return tuple;
  }
  memzero(out, capacity);
  auth_vault_clear_session();
  nlr_jump(nlr.ret_val);
}

static mp_obj_t key_agreement(void) {
  uint8_t public_key[65] = {0};
  auth_result result = auth_vault_key_agreement(public_key, sizeof(public_key));
  return output_tuple(result, public_key, result == AUTH_OK ? 65 : 0, 65);
}
static MP_DEFINE_CONST_FUN_OBJ_0(key_agreement_obj, key_agreement);

static mp_obj_t issue_token(size_t count, const mp_obj_t *args) {
  // The PIN hash arrives as the platform sent it: encrypted under the shared
  // secret, 16 bytes on protocol 1 and 32 on protocol 2 with its leading IV.
  // Only the vault can open it, which is why the application passes it through
  // untouched rather than decrypting and handing over a hash.
  uint8_t protocol = number(args[1], 1, 2);
  mp_buffer_info_t hash =
      buffer(args[0], protocol == 2 ? 32 : 16, protocol == 2 ? 32 : 16);
  uint8_t permissions = number(args[2], 1, 0x3f);
  mp_buffer_info_t rp = rp_buffer(args[3]);
  mp_buffer_info_t peer = buffer(args[4], 65, 65);
  if ((permissions & 3) && rp.len != 32) invalid();
  uint8_t encrypted[48] = {0};
  size_t written = 0;
  auth_result result = auth_vault_issue_token(
      hash.buf, hash.len, protocol, permissions, rp.buf, rp.len, peer.buf,
      peer.len, encrypted, sizeof(encrypted), &written);
  return output_tuple(result, encrypted, written, sizeof(encrypted));
}
static MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(issue_token_obj, 5, 5, issue_token);

// CTAP setPIN. The PIN itself never appears here: it arrives zero-padded to 64
// bytes and encrypted under the shared secret, 64 bytes on protocol 1 and 80 on
// protocol 2, and the vault is the only thing that can read it.
static mp_obj_t set_pin(size_t count, const mp_obj_t *args) {
  uint8_t protocol = number(args[0], 1, 2);
  mp_buffer_info_t new_pin =
      buffer(args[1], protocol == 2 ? 80 : 64, protocol == 2 ? 80 : 64);
  // CTAP's MAC over that ciphertext, under the shared secret. Verified by the
  // vault, which is the only holder of the key it was computed with.
  mp_buffer_info_t param =
      buffer(args[2], protocol == 2 ? 32 : 16, protocol == 2 ? 32 : 16);
  mp_buffer_info_t peer = buffer(args[3], 65, 65);
  return MP_OBJ_NEW_SMALL_INT(
      auth_vault_set_pin(protocol, new_pin.buf, new_pin.len, param.buf,
                         param.len, peer.buf, peer.len));
}
static MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(set_pin_obj, 4, 4, set_pin);

static mp_obj_t check_auth(size_t count, const mp_obj_t *args) {
  uint8_t protocol = number(args[0], 1, 2);
  mp_buffer_info_t message = buffer(args[1], 0, 1024);
  mp_buffer_info_t param =
      buffer(args[2], protocol == 1 ? 16 : 32, protocol == 1 ? 16 : 32);
  uint8_t permissions = number(args[3], 1, 0x3f);
  mp_buffer_info_t rp = rp_buffer(args[4]);
  return MP_OBJ_NEW_SMALL_INT(
      auth_vault_check_auth(protocol, message.buf, message.len, param.buf,
                            param.len, permissions, rp.buf, rp.len));
}
static MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(check_auth_obj, 5, 5, check_auth);

static mp_obj_t disconnect(void) {
  return MP_OBJ_NEW_SMALL_INT(auth_vault_disconnect());
}
static MP_DEFINE_CONST_FUN_OBJ_0(disconnect_obj, disconnect);
static mp_obj_t wipe(void) { return MP_OBJ_NEW_SMALL_INT(auth_vault_wipe()); }
static MP_DEFINE_CONST_FUN_OBJ_0(wipe_obj, wipe);
// One reading of the physical confirmation line. Takes nothing, so there is
// nothing to validate and no session to clear; the debounce and the one-shot
// rule live above this, in presence.py.
static mp_obj_t presence_sample(void) {
  return MP_OBJ_NEW_SMALL_INT(auth_presence_sample());
}
static MP_DEFINE_CONST_FUN_OBJ_0(presence_sample_obj, presence_sample);

static int32_t algorithm(mp_obj_t value) {
  if (!mp_obj_is_small_int(value)) invalid();
  mp_int_t n = MP_OBJ_SMALL_INT_VALUE(value);
  if (n != -7 && n != -8) invalid();
  return n;
}
static mp_obj_t credential_tuple(auth_result result,
                                 auth_credential_public *out) {
  nlr_buf_t nlr;
  if (nlr_push(&nlr) == 0) {
    mp_obj_t items[6] = {MP_OBJ_NEW_SMALL_INT(result),
                         mp_obj_new_bytes(out->id, out->id_len),
                         mp_obj_new_bytes(out->rp, result == AUTH_OK ? 32 : 0),
                         MP_OBJ_NEW_SMALL_INT(out->algorithm),
                         mp_obj_new_bytes(out->metadata, out->metadata_len),
                         mp_obj_new_bytes(out->cose, out->cose_len)};
    mp_obj_t tuple = mp_obj_new_tuple(6, items);
    memzero(out, sizeof(*out));
    nlr_pop();
    return tuple;
  }
  memzero(out, sizeof(*out));
  auth_vault_clear_session();
  nlr_jump(nlr.ret_val);
}
static mp_obj_t credential_create(mp_obj_t rp_obj, mp_obj_t algorithm_obj,
                                  mp_obj_t metadata_obj) {
  mp_buffer_info_t rp = buffer(rp_obj, 32, 32),
                   metadata = buffer(metadata_obj, 10, AUTH_METADATA_MAX);
  int32_t alg = algorithm(algorithm_obj);
  auth_credential_public out = {0};
  auth_result result =
      auth_credential_create(rp.buf, alg, metadata.buf, metadata.len, &out);
  return credential_tuple(result, &out);
}
static MP_DEFINE_CONST_FUN_OBJ_3(credential_create_obj, credential_create);
static mp_obj_t credential_open(mp_obj_t id_obj, mp_obj_t rp_obj) {
  mp_buffer_info_t id = buffer(id_obj, 78, AUTH_CREDENTIAL_ID_MAX),
                   rp = buffer(rp_obj, 32, 32);
  auth_credential_public out = {0};
  auth_result result = auth_credential_open(id.buf, id.len, rp.buf, &out);
  return credential_tuple(result, &out);
}
static MP_DEFINE_CONST_FUN_OBJ_2(credential_open_obj, credential_open);
// The two names exist so that a call site says which signature it is asking
// for. They are one operation in the vault, which is where the permission for
// each is decided.
static mp_obj_t sign_with(const mp_obj_t *args, bool attesting) {
  mp_buffer_info_t id = buffer(args[0], 78, AUTH_CREDENTIAL_ID_MAX),
                   rp = buffer(args[1], 32, 32);
  int32_t alg = algorithm(args[2]);
  mp_buffer_info_t message = buffer(args[3], 1, 1024);
  uint8_t out[72] = {0};
  size_t written = 0;
  auth_result result =
      auth_credential_sign(id.buf, id.len, rp.buf, alg, message.buf,
                           message.len, attesting, out, &written);
  return output_tuple(result, out, written, sizeof(out));
}
static mp_obj_t credential_sign(size_t count, const mp_obj_t *args) {
  return sign_with(args, false);
}
static MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(credential_sign_obj, 4, 4,
                                           credential_sign);
static mp_obj_t credential_attest(size_t count, const mp_obj_t *args) {
  return sign_with(args, true);
}
static MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(credential_attest_obj, 4, 4,
                                           credential_attest);
static mp_obj_t credential_hmac_secret(mp_obj_t id_obj, mp_obj_t rp_obj,
                                       mp_obj_t salts_obj) {
  mp_buffer_info_t id = buffer(id_obj, 78, AUTH_CREDENTIAL_ID_MAX),
                   rp = buffer(rp_obj, 32, 32),
                   salts = buffer(salts_obj, 32, 64);
  if (salts.len != 32 && salts.len != 64) invalid();
  uint8_t out[64] = {0};
  auth_result result = auth_credential_hmac_secret(id.buf, id.len, rp.buf,
                                                   salts.buf, salts.len, out);
  return output_tuple(result, out, result == AUTH_OK ? salts.len : 0,
                      sizeof(out));
}
static MP_DEFINE_CONST_FUN_OBJ_3(credential_hmac_secret_obj,
                                 credential_hmac_secret);
static mp_obj_t resident_get(mp_obj_t index_obj) {
  uint8_t index = number(index_obj, 0, 99);
  auth_credential_public out = {0};
  auth_result result = auth_resident_get(index, &out);
  return credential_tuple(result, &out);
}
static MP_DEFINE_CONST_FUN_OBJ_1(resident_get_obj, resident_get);
static mp_obj_t resident_set(mp_obj_t index_obj, mp_obj_t id_obj,
                             mp_obj_t rp_obj) {
  // 100 is AUTH_RESIDENT_ANY: store this credential wherever there is room.
  uint8_t index = number(index_obj, 0, 100);
  mp_buffer_info_t id = buffer(id_obj, 78, AUTH_CREDENTIAL_ID_MAX),
                   rp = buffer(rp_obj, 32, 32);
  return MP_OBJ_NEW_SMALL_INT(auth_resident_set(index, id.buf, id.len, rp.buf));
}
static MP_DEFINE_CONST_FUN_OBJ_3(resident_set_obj, resident_set);
static mp_obj_t resident_delete(mp_obj_t index_obj) {
  return MP_OBJ_NEW_SMALL_INT(auth_resident_delete(number(index_obj, 0, 99)));
}
static MP_DEFINE_CONST_FUN_OBJ_1(resident_delete_obj, resident_delete);
static mp_obj_t resident_scan(mp_obj_t rp_obj) {
  uint8_t map[AUTH_RESIDENT_CAPACITY] = {0};
  auth_result result;
  if (rp_obj == mp_const_none) {
    result = auth_resident_scan(NULL, map);
  } else {
    mp_buffer_info_t rp = buffer(rp_obj, 32, 32);
    result = auth_resident_scan(rp.buf, map);
  }
  // Status first, same shape as every other call here, so a caller cannot read
  // the map without having looked at whether it means anything.
  if (result != AUTH_OK) memzero(map, sizeof(map));
  mp_obj_t items[2] = {MP_OBJ_NEW_SMALL_INT(result),
                       mp_obj_new_bytes(map, sizeof(map))};
  memzero(map, sizeof(map));
  return mp_obj_new_tuple(2, items);
}
static MP_DEFINE_CONST_FUN_OBJ_1(resident_scan_obj, resident_scan);

static const mp_rom_map_elem_t globals[] = {
    {MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_trezorauth)},
    {MP_ROM_QSTR(MP_QSTR_status), MP_ROM_PTR(&status_obj)},
    {MP_ROM_QSTR(MP_QSTR_provision), MP_ROM_PTR(&provision_obj)},
    {MP_ROM_QSTR(MP_QSTR_change_pin), MP_ROM_PTR(&change_pin_obj)},
    {MP_ROM_QSTR(MP_QSTR_key_agreement), MP_ROM_PTR(&key_agreement_obj)},
    {MP_ROM_QSTR(MP_QSTR_issue_token), MP_ROM_PTR(&issue_token_obj)},
    {MP_ROM_QSTR(MP_QSTR_set_pin), MP_ROM_PTR(&set_pin_obj)},
    {MP_ROM_QSTR(MP_QSTR_check_auth), MP_ROM_PTR(&check_auth_obj)},
    {MP_ROM_QSTR(MP_QSTR_disconnect), MP_ROM_PTR(&disconnect_obj)},
    {MP_ROM_QSTR(MP_QSTR_wipe), MP_ROM_PTR(&wipe_obj)},
    {MP_ROM_QSTR(MP_QSTR_presence_sample), MP_ROM_PTR(&presence_sample_obj)},
    {MP_ROM_QSTR(MP_QSTR_credential_create),
     MP_ROM_PTR(&credential_create_obj)},
    {MP_ROM_QSTR(MP_QSTR_credential_open), MP_ROM_PTR(&credential_open_obj)},
    {MP_ROM_QSTR(MP_QSTR_credential_sign), MP_ROM_PTR(&credential_sign_obj)},
    {MP_ROM_QSTR(MP_QSTR_credential_attest),
     MP_ROM_PTR(&credential_attest_obj)},
    {MP_ROM_QSTR(MP_QSTR_credential_hmac_secret),
     MP_ROM_PTR(&credential_hmac_secret_obj)},
    {MP_ROM_QSTR(MP_QSTR_resident_get), MP_ROM_PTR(&resident_get_obj)},
    {MP_ROM_QSTR(MP_QSTR_resident_set), MP_ROM_PTR(&resident_set_obj)},
    {MP_ROM_QSTR(MP_QSTR_resident_delete), MP_ROM_PTR(&resident_delete_obj)},
    {MP_ROM_QSTR(MP_QSTR_resident_scan), MP_ROM_PTR(&resident_scan_obj)},
#ifdef AUTH_ASSUMED_PRESENCE
    // Present only in a build that confirms operations without asking. Python
    // reads its absence as "ask the line", so a build that forgot to define it
    // cannot accidentally stop asking.
    {MP_ROM_QSTR(MP_QSTR_ASSUMED_PRESENCE), mp_const_true},
#endif
    {MP_ROM_QSTR(MP_QSTR_PRESENCE_ABSENT), MP_ROM_INT(AUTH_PRESENCE_ABSENT)},
    {MP_ROM_QSTR(MP_QSTR_PRESENCE_PRESENT), MP_ROM_INT(AUTH_PRESENCE_PRESENT)},
    {MP_ROM_QSTR(MP_QSTR_PRESENCE_FAULT), MP_ROM_INT(AUTH_PRESENCE_FAULT)},
    {MP_ROM_QSTR(MP_QSTR_OK), MP_ROM_INT(AUTH_OK)},
    {MP_ROM_QSTR(MP_QSTR_UNPROVISIONED), MP_ROM_INT(AUTH_UNPROVISIONED)},
    {MP_ROM_QSTR(MP_QSTR_INVALID_ARGUMENT), MP_ROM_INT(AUTH_INVALID_ARGUMENT)},
    {MP_ROM_QSTR(MP_QSTR_PIN_INVALID), MP_ROM_INT(AUTH_PIN_INVALID)},
    {MP_ROM_QSTR(MP_QSTR_PIN_AUTH_BLOCKED), MP_ROM_INT(AUTH_PIN_AUTH_BLOCKED)},
    {MP_ROM_QSTR(MP_QSTR_PIN_BLOCKED), MP_ROM_INT(AUTH_PIN_BLOCKED)},
    {MP_ROM_QSTR(MP_QSTR_DENIED), MP_ROM_INT(AUTH_DENIED)},
    {MP_ROM_QSTR(MP_QSTR_ERROR), MP_ROM_INT(AUTH_ERROR)},
    {MP_ROM_QSTR(MP_QSTR_LIMIT_EXCEEDED), MP_ROM_INT(AUTH_LIMIT_EXCEEDED)},
    // The storage areas hold data that is not ours, so nothing was read, erased
    // or rewritten. Named here because auth_vault_status() can return it and
    // the application otherwise receives a bare integer it cannot distinguish
    // from a future addition.
    // A well-formed PIN the policy refuses, currently only one shorter than the
    // minimum. Named so the application can answer CTAP's PIN_POLICY_VIOLATION
    // rather than a generic parameter error: a short PIN the platform can fix
    // by asking for a longer one, a malformed request it cannot.
    {MP_ROM_QSTR(MP_QSTR_PIN_POLICY), MP_ROM_INT(AUTH_PIN_POLICY)},
    {MP_ROM_QSTR(MP_QSTR_MIN_PIN_CODE_POINTS),
     MP_ROM_INT(AUTH_MIN_PIN_CODE_POINTS)},
    {MP_ROM_QSTR(MP_QSTR_MIGRATION_REQUIRED),
     MP_ROM_INT(AUTH_MIGRATION_REQUIRED)},
#ifdef AUTH_TEST_BACKEND
    {MP_ROM_QSTR(MP_QSTR_TEST_BACKEND), MP_ROM_INT(1)},
#endif
};
static MP_DEFINE_CONST_DICT(globals_dict, globals);
const mp_obj_module_t mp_module_trezorauth = {
    .base = {&mp_type_module},
    .globals = (mp_obj_dict_t *)&globals_dict,
};
MP_REGISTER_MODULE(MP_QSTR_trezorauth, mp_module_trezorauth);
