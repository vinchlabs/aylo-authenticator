#include "commands.h"

#include <trezor_rtl.h>

#include <sys/bootutils.h>
#include <sys/systick.h>

#include "protocol.h"
#include "version.h"

static bool validate(cli_t *cli, const char *name, headless_command_t expected,
                     size_t text_len) {
  headless_command_t command = headless_validate_command(
      name, cli_arg_count(cli), cli->raw_line_len, text_len);
  if (command != expected) {
    cli_error(cli, CLI_ERROR_INVALID_ARG, "Invalid command arguments.");
    return false;
  }
  return true;
}

static void headless_ping(cli_t *cli) {
  const char *text = cli_arg(cli, "text");
  if (!validate(cli, "ping", HEADLESS_PING, strlen(text))) {
    return;
  }
  cli_ok(cli, "%s", text);
}

static void headless_version(cli_t *cli) {
  if (!validate(cli, "version", HEADLESS_VERSION, 0)) {
    return;
  }
  cli_ok(cli, "ts5-headless-dev %d.%d.%d T3T1", VERSION_MAJOR, VERSION_MINOR,
         VERSION_PATCH);
}

static void headless_reboot_to_bootloader(cli_t *cli) {
  if (!validate(cli, "reboot-to-bootloader", HEADLESS_REBOOT, 0)) {
    return;
  }
  cli_ok(cli, "");
  systick_delay_ms(1000);
  reboot_to_bootloader();
}

// clang-format off

PRODTEST_CLI_CMD(
  .name = "ping",
  .func = headless_ping,
  .info = "Echo up to 64 bytes",
  .args = "[<text>]"
);

PRODTEST_CLI_CMD(
  .name = "version",
  .func = headless_version,
  .info = "Show headless firmware version",
  .args = ""
);

PRODTEST_CLI_CMD(
  .name = "reboot-to-bootloader",
  .func = headless_reboot_to_bootloader,
  .info = "Reboot into firmware update mode",
  .args = ""
);

// clang-format on

extern cli_command_t _prodtest_cli_cmd_section_start;
extern cli_command_t _prodtest_cli_cmd_section_end;

const cli_command_t *commands_get_ptr(void) {
  return &_prodtest_cli_cmd_section_start;
}

size_t commands_count(void) {
  return &_prodtest_cli_cmd_section_end - &_prodtest_cli_cmd_section_start;
}
