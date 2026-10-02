#pragma once

#include <stddef.h>

typedef enum {
  HEADLESS_ERROR = 0,
  HEADLESS_PING,
  HEADLESS_VERSION,
  HEADLESS_REBOOT,
} headless_command_t;

headless_command_t headless_validate_command(const char *name, size_t argc,
                                             size_t line_len, size_t text_len);
