#include <assert.h>
#include <stddef.h>

#include "protocol.h"

int main(void) {
  assert(headless_validate_command("ping", 0, 4, 0) == HEADLESS_PING);
  assert(headless_validate_command("ping", 1, 128, 64) == HEADLESS_PING);
  assert(headless_validate_command("ping", 1, 129, 64) == HEADLESS_ERROR);
  assert(headless_validate_command("ping", 1, 70, 65) == HEADLESS_ERROR);
  assert(headless_validate_command("ping", 2, 12, 3) == HEADLESS_ERROR);

  assert(headless_validate_command("version", 0, 7, 0) == HEADLESS_VERSION);
  assert(headless_validate_command("version", 1, 11, 0) == HEADLESS_ERROR);

  assert(headless_validate_command("reboot-to-bootloader", 0, 20, 0) ==
         HEADLESS_REBOOT);
  assert(headless_validate_command("reboot-to-bootloader", 1, 24, 0) ==
         HEADLESS_ERROR);

  assert(headless_validate_command("otp-write", 0, 9, 0) == HEADLESS_ERROR);
  assert(headless_validate_command("unknown", 0, 7, 0) == HEADLESS_ERROR);
  assert(headless_validate_command(NULL, 0, 0, 0) == HEADLESS_ERROR);
  return 0;
}
