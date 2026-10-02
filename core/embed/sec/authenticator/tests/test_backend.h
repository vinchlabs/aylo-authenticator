#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
  TEST_NONE,
  TEST_RNG,
  TEST_PIN_INIT,
  TEST_PIN_SET,
  TEST_PIN_VERIFY,
  TEST_COUNTER,
  TEST_READ,
  TEST_WRITE,
  TEST_INTERRUPTED,
  TEST_ERASE,
  TEST_ZEROIZE
} auth_test_failure;

void auth_test_reset(void);
void auth_test_fail(auth_test_failure failure);
void auth_test_corrupt(size_t offset);
const uint8_t *auth_test_record(void);
const uint8_t *auth_test_verifier(void);
size_t auth_test_rng_bytes(void);
size_t auth_test_zeroize_checks(void);
bool auth_test_transients_zero(void);
void auth_test_exhaust(void);
