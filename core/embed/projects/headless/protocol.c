#include "protocol.h"

#include <string.h>

#define HEADLESS_MAX_LINE_LENGTH 128
#define HEADLESS_MAX_PING_LENGTH 64

headless_command_t headless_validate_command(const char *name, size_t argc,
                                             size_t line_len, size_t text_len) {
  if (name == NULL || line_len > HEADLESS_MAX_LINE_LENGTH) {
    return HEADLESS_ERROR;
  }

  if (strcmp(name, "ping") == 0) {
    return argc <= 1 && text_len <= HEADLESS_MAX_PING_LENGTH ? HEADLESS_PING
                                                             : HEADLESS_ERROR;
  }

  if (strcmp(name, "version") == 0) {
    return argc == 0 && text_len == 0 ? HEADLESS_VERSION : HEADLESS_ERROR;
  }

  if (strcmp(name, "reboot-to-bootloader") == 0) {
    return argc == 0 && text_len == 0 ? HEADLESS_REBOOT : HEADLESS_ERROR;
  }

  return HEADLESS_ERROR;
}
