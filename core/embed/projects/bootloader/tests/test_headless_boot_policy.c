#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "headless_boot_policy.h"
#include "protob/pb/messages.pb.h"

#define assert(condition)                                                 \
  do {                                                                    \
    if (!(condition)) {                                                   \
      fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__, __LINE__, \
              #condition);                                                \
      exit(1);                                                            \
    }                                                                     \
  } while (0)

static void test_jump_matrix(void) {
  for (unsigned valid = 0; valid <= 1; valid++) {
    for (unsigned forced = 0; forced <= 1; forced++) {
      for (unsigned session = 0; session <= 1; session++) {
        for (unsigned expired = 0; expired <= 1; expired++) {
          bool expected = valid && !forced && !session && expired;
          assert(headless_should_jump(valid, forced, session, expired) ==
                 expected);
        }
      }
    }
  }
}

static void test_poll_deadline(void) {
  assert(headless_poll_deadline(1000, 5000, 100) == 1100);
  assert(headless_poll_deadline(4950, 5000, 100) == 5000);
  assert(headless_poll_deadline(5000, 5000, 100) == 5000);
  assert(headless_poll_deadline(5001, 5000, 100) == 5001);
  assert(headless_poll_deadline(0xFFFFFFF0, 0x00000020, 100) == 0x00000020);
}

static void test_recognized_messages(void) {
  assert(headless_is_recognized_message(MessageType_MessageType_Initialize));
  assert(headless_is_recognized_message(MessageType_MessageType_Ping));
  assert(headless_is_recognized_message(MessageType_MessageType_GetFeatures));
  assert(headless_is_recognized_message(MessageType_MessageType_WipeDevice));
  assert(headless_is_recognized_message(MessageType_MessageType_FirmwareErase));
#if defined(LOCKABLE_BOOTLOADER)
  assert(
      headless_is_recognized_message(MessageType_MessageType_UnlockBootloader));
#endif

  assert(
      !headless_is_recognized_message(MessageType_MessageType_FirmwareUpload));
  assert(!headless_is_recognized_message(0xFFFF));
}

static void test_forced_loader_commands(void) {
  assert(!headless_forced_loader(false, 0x00000000ULL));
  assert(!headless_forced_loader(false, 0xA5C3D4E2ULL));
  assert(headless_forced_loader(false, 0x0FC35A96ULL));
  assert(headless_forced_loader(false, 0x3B7E1C64ULL));
  assert(headless_forced_loader(false, 0xFA4A5C8DULL));
  assert(headless_forced_loader(false, 0x7CD945A0ULL));
  assert(headless_forced_loader(false, 0xD965CE36ULL));
  assert(headless_forced_loader(false, 0x24EEE8828ULL));
  assert(headless_forced_loader(true, 0x00000000ULL));

  // Observed after a real cold power cycle: uninitialized retained SRAM must
  // not turn into an implicit request to stay in the bootloader.
  assert(!headless_forced_loader(false, 0x023A1F8AULL));
}

int main(void) {
  test_jump_matrix();
  test_poll_deadline();
  test_recognized_messages();
  test_forced_loader_commands();
  return 0;
}
