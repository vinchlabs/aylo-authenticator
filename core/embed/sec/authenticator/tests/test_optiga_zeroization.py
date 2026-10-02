"""Execute the real shared OPTIGA setter with audited erasure and transport faults."""
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[5]


def function(source, signature):
    start = source.index(signature)
    opening = source.index("{", start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


PRELUDE = r"""
#include <sec/optiga.h>
#include <sec/optiga_commands.h>
#include <string.h>
#define ENCRYPT_SYM_PREFIX_SIZE 3
#define OID_PIN_SECRET (OPTIGA_OID_DATA + 0)
#define OID_PIN_HMAC (OPTIGA_OID_DATA + 8)
#define OID_STRETCHED_PIN_CTR (OPTIGA_OID_COUNTER + 0)
#define OID_PIN_HMAC_CTR (OPTIGA_OID_COUNTER + 2)
static const uint16_t OID_STRETCHED_PINS[] = {OPTIGA_OID_DATA + 4};
static unsigned sensitive_wipes, rng_calls, transport_calls, fault;
static void audited_zero(void *buffer, size_t len) {
  uint8_t *p = buffer;
  bool sensitive = len == 32;
  for (size_t i = 0; sensitive && i < 32; i++) sensitive = p[i] == i + 1;
  volatile uint8_t *v = buffer;
  for (size_t i = 0; i < len; i++) v[i] = 0;
  if (sensitive) {
    for (size_t i = 0; i < len; i++) if (v[i]) __builtin_trap();
    sensitive_wipes++;
  }
}
#define memzero audited_zero
void rng_fill_buffer_strong(void *buffer, size_t len) {
  uint8_t *p = buffer;
  for (size_t i = 0; i < len; i++) p[i] = i + 1 + rng_calls * 64;
  rng_calls++;
}
void hmac_sha256(const uint8_t *key, uint32_t keylen,
                 const uint8_t *message, uint32_t len, uint8_t *out) {
  memset(out, 0x80, 32);
}
void optiga_set_ui_progress(optiga_ui_progress_t cb) {}
optiga_result optiga_clear_all_auto_states(void) { return OPTIGA_SUCCESS; }
static optiga_result transport(void) {
  return ++transport_calls == fault ? OPTIGA_ERR_CMD : OPTIGA_SUCCESS;
}
optiga_result optiga_set_data_object(uint16_t oid, bool metadata,
                                     const uint8_t *data, size_t len) { return transport(); }
optiga_result optiga_set_auto_state(uint16_t nonce, uint16_t key,
                                    const uint8_t *data, size_t len) { return transport(); }
optiga_result optiga_reset_counter(uint16_t oid, uint32_t limit) { return transport(); }
"""

MAIN = r"""
int main(void) {
  for (fault = 0; fault <= 7; fault++) {
    uint8_t slots[STRETCHED_PIN_COUNT][32] = {{1}}, reset_key[32] = {0};
    sensitive_wipes = rng_calls = transport_calls = 0;
    bool success = optiga_pin_set(NULL, slots, reset_key);
    if (success != (fault == 0) || sensitive_wipes != 1) return 1;
  }
  return 0;
}
"""


class OptigaZeroizationTests(unittest.TestCase):
    def test_shared_setter_erases_stretching_secret_on_success_and_each_fault(self):
        source = (ROOT / "core/embed/sec/optiga/optiga.c").read_text()
        program = PRELUDE + function(source, "static void optiga_pin_stretch_hmac_offline(")
        program += function(source, "bool optiga_pin_set(") + MAIN
        with tempfile.TemporaryDirectory(prefix="auth-optiga-zero-") as directory:
            native = pathlib.Path(directory) / "test.c"
            executable = pathlib.Path(directory) / "test"
            native.write_text(program)
            command = ["cc", "-std=c11", "-O2", "-DUSE_OPTIGA=1"]
            for include in ("core/embed/rtl/inc", "core/embed/sec/optiga/inc",
                            "core/embed/sec/storage/inc", "core/vendor"):
                command += ["-I", str(ROOT / include)]
            subprocess.run(command + [str(native), "-o", str(executable)], check=True)
            result = subprocess.run([str(executable)])
            self.assertEqual(result.returncode, 0, "OPTIGA HMAC stretching secret was not erased")


if __name__ == "__main__":
    unittest.main()
