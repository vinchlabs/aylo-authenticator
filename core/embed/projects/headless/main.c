#include <trezor_bsp.h>
#include <trezor_model.h>
#include <trezor_rtl.h>

#include <io/usb.h>
#include <io/usb_config.h>
#include <rtl/cli.h>
#include <sys/sysevent.h>
#include <sys/system.h>
#include <sys/systick.h>

#ifdef USE_TRUSTZONE
#include <sec/tz_init.h>
#endif

#include "commands.h"

#ifndef TREZOR_MODEL_T3T1
#error "The headless development application is only supported on T3T1"
#endif

#define HEADLESS_CLI_LINE_LIMIT 128
#define HEADLESS_USB_SERIAL "TS5HEADLESSDEV0001"

static cli_t g_cli;

static ssize_t console_read(void *context, char *buf, size_t size) {
  (void)context;
  return syshandle_read(SYSHANDLE_USB_VCP, buf, size);
}

static ssize_t console_write(void *context, const char *buf, size_t size) {
  (void)context;
  static uint32_t timeout = 2000;
  ssize_t written =
      syshandle_write_blocking(SYSHANDLE_USB_VCP, buf, size, timeout);
  timeout = written < 0 || (size_t)written < size ? 100 : 2000;
  return written;
}

static void usb_vcp_intr_callback(void) { cli_abort(&g_cli); }

int main(void) {
#ifdef USE_TRUSTZONE
  tz_init();
#endif

  system_init(NULL);

  if (sectrue != usb_configure(&usb_vcp_intr_callback)) {
    return 1;
  }
  static const usb_start_params_t usb_params = {
      .serial_number = HEADLESS_USB_SERIAL,
      .usb21_landing = secfalse,
  };
  if (sectrue != usb_start(&usb_params)) {
    return 1;
  }
  if (!cli_init(&g_cli, console_read, console_write, NULL)) {
    return 1;
  }

  cli_set_strict_input(&g_cli, true);
  cli_set_line_limit(&g_cli, HEADLESS_CLI_LINE_LIMIT);
  cli_set_commands(&g_cli, commands_get_ptr(), commands_count());

  for (;;) {
    sysevents_t awaited = {.read_ready = 1 << SYSHANDLE_USB_VCP};
    sysevents_t signalled = {0};
    sysevents_poll(&awaited, &signalled, ticks_timeout(100));

    if (signalled.read_ready & awaited.read_ready) {
      const cli_command_t *command = cli_process_io(&g_cli);
      if (command != NULL) {
        cli_process_command(&g_cli, command);
      }
    }
  }
}
