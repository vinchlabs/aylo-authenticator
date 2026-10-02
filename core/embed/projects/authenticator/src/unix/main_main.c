#include <stdlib.h>
#include <string.h>

#include <trezor_rtl.h>
#include <io/usb_config.h>
#include <sec/monoctr.h>
#include <sec/unit_properties.h>
#include <sys/applet.h>
#include <sys/bootutils.h>
#include <sys/coreapp.h>
#include <sys/flash.h>
#include <sys/flash_otp.h>
#include <sys/system.h>
#include <sys/sysevent.h>
#include <sys/systick.h>
#include <sys/systimer.h>

#include "../../version.h"

static void panic_handler(const systask_postmortem_t *info) {
  UNUSED(info);
  abort();
}

void show_wipe_info(const bootutils_wipe_info_t *info) {
  UNUSED(info);
}

int main(int argc, char **argv) {
  system_init(panic_handler);
  if (argc > 1 && strcmp(argv[1], "--emulator-properties") == 0) {
    return 0;
  }
  flash_init();
  flash_otp_init();
  monoctr_init();
  unit_properties_init();
  usb_configure(NULL);

  applet_t coreapp;
  if (!coreapp_init(&coreapp, argc, argv)) {
    abort();
  }
  applet_run(&coreapp);
  while (applet_is_alive(&coreapp)) {
    sysevents_t awaited = {0};
    sysevents_t signalled = {0};
    sysevents_poll(&awaited, &signalled, ticks_timeout(100));
  }
  flash_deinit();
  return coreapp.task.pminfo.exit.code;
}
