#include <stdint.h>

// The linked ELF, rather than build flags or source text, is the audit input.
__attribute__((used, section(".rodata.authenticator_audit")))
const uint8_t g_authenticator_build_audit[8] = {
    'A', 'U', 'T', 'H', 'M', '1', 1,
    0
#ifdef AUTH_TEST_PRESENCE
        | 1
#endif
#ifdef AUTH_TEST_BACKEND
        | 2
#endif
#ifdef AUTH_INTEGRATION_CREDENTIALS
        | 4
#endif
#ifdef AUTH_PRODUCTION
        | 8
#endif
#ifdef AUTH_ASSUMED_PRESENCE
        | 16
#endif
};
