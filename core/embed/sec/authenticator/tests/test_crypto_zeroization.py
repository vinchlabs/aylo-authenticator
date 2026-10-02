"""Run actual ChaCha/AEAD helpers with erasure audited while buffers are alive."""
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[5]
PROGRAM = r'''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "chacha20poly1305/rfc7539.h"
static unsigned erased64;
static const uint8_t *expected;
static size_t expected_len;
static bool saw_partial;
void auth_audited_zero(void *const p, const size_t len) {
  if (len == 64 && expected_len && !memcmp(p, expected, expected_len)) saw_partial = true;
  volatile uint8_t *v = p;
  for (size_t i = 0; i < len; i++) v[i] = 0;
  for (size_t i = 0; i < len; i++) assert(v[i] == 0);
  if (len == 64) erased64++;
}
int main(void) {
  uint8_t key[32] = {1}, nonce[12] = {2};
  uint8_t plain[129], cipher[129], decoded[129];
  for (size_t i = 0; i < sizeof(plain); i++) plain[i] = i + 1;
  const unsigned sizes[] = {0, 1, 16, 32, 63, 64, 65, 128, 129};
  for (size_t i = 0; i < sizeof(sizes)/sizeof(sizes[0]); i++) {
    chacha20poly1305_ctx enc = {0}, dec = {0};
    erased64 = 0;
    rfc7539_init(&enc, key, nonce);
    assert(erased64 == 2);
    erased64 = 0;
    expected = cipher + (sizes[i] / 64) * 64;
    expected_len = sizes[i] % 64;
    saw_partial = false;
    ECRYPT_encrypt_bytes(&enc.chacha20, plain, cipher, sizes[i]);
    assert(erased64 == 1);
    assert(!expected_len || saw_partial);
    expected_len = 0;
    erased64 = 0;
    rfc7539_init(&dec, key, nonce);
    assert(erased64 == 2);
    erased64 = 0;
    expected = plain + (sizes[i] / 64) * 64;
    expected_len = sizes[i] % 64;
    saw_partial = false;
    ECRYPT_decrypt_bytes(&dec.chacha20, cipher, decoded, sizes[i]);
    assert(erased64 == 1);
    assert(!expected_len || saw_partial);
    expected_len = 0;
    assert(memcmp(plain, decoded, sizes[i]) == 0);
  }
  return 0;
}
'''


class CryptoZeroizationTests(unittest.TestCase):
    def test_real_helpers_erase_block0_and_tmp_on_all_exercised_paths(self):
        with tempfile.TemporaryDirectory(prefix="auth-crypto-zero-") as directory:
            source = pathlib.Path(directory) / "test.c"
            executable = pathlib.Path(directory) / "test"
            source.write_text(PROGRAM)
            command = ["cc", "-std=c11", "-O2", "-Dmemzero=auth_audited_zero",
                       "-I", str(ROOT / "crypto"), str(source)]
            command += [str(ROOT / "crypto/chacha20poly1305" / name) for name in
                        ("chacha_merged.c", "rfc7539.c", "poly1305-donna.c")]
            command.append(str(ROOT / "crypto/consteq.c"))
            command.append(str(ROOT / "crypto/fault_handler_noop.c"))
            subprocess.run(command + ["-o", str(executable)], check=True)
            result = subprocess.run([str(executable)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
