#include "headless_boot_policy.h"

#include "protob/pb/messages.pb.h"

#include <sys/bootargs.h>

bool headless_should_jump(bool valid_firmware, bool forced_loader,
                          bool recognized_session, bool window_expired) {
  return valid_firmware && !forced_loader && !recognized_session &&
         window_expired;
}

uint32_t headless_poll_deadline(uint32_t now, uint32_t window_deadline,
                                uint32_t max_wait_ms) {
  int32_t remaining = (int32_t)(window_deadline - now);
  if (remaining <= 0) {
    return now;
  }
  if ((uint32_t)remaining <= max_wait_ms) {
    return window_deadline;
  }
  return now + max_wait_ms;
}

bool headless_is_recognized_message(uint16_t message_id) {
  switch (message_id) {
    case MessageType_MessageType_Initialize:
    case MessageType_MessageType_Ping:
    case MessageType_MessageType_GetFeatures:
    case MessageType_MessageType_WipeDevice:
    case MessageType_MessageType_FirmwareErase:
#if defined(LOCKABLE_BOOTLOADER)
    case MessageType_MessageType_UnlockBootloader:
#endif
      return true;
    default:
      return false;
  }
}

bool headless_forced_loader(bool stay_in_bootloader, uint64_t boot_command) {
  if (stay_in_bootloader) {
    return true;
  }

  switch (boot_command) {
    case BOOT_COMMAND_STOP_AND_WAIT:
    case BOOT_COMMAND_STOP_AND_CONNECT:
    case BOOT_COMMAND_INSTALL_UPGRADE:
    case BOOT_COMMAND_SHOW_RSOD:
    case BOOT_COMMAND_WIPE:
    case BOOT_COMMAND_POWER_OFF:
      return true;
    case BOOT_COMMAND_NONE:
    case BOOT_COMMAND_REBOOT:
    default:
      return false;
  }
}
