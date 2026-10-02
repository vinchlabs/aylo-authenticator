#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rtl/cli.h>

typedef struct {
  const uint8_t *input;
  size_t input_len;
  size_t input_pos;
  char output[256];
  size_t output_len;
  unsigned handler_calls;
} fixture_t;

#define CHECK(condition)                                                 \
  do {                                                                   \
    if (!(condition)) {                                                  \
      fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__, __LINE__, \
              #condition);                                               \
      exit(1);                                                           \
    }                                                                    \
  } while (0)

static ssize_t fixture_read(void *context, char *buf, size_t size) {
  fixture_t *fixture = context;
  if (size == 0 || fixture->input_pos >= fixture->input_len) {
    return 0;
  }
  *buf = (char)fixture->input[fixture->input_pos++];
  return 1;
}

static ssize_t fixture_write(void *context, const char *buf, size_t size) {
  fixture_t *fixture = context;
  size_t available = sizeof(fixture->output) - fixture->output_len - 1;
  size_t copy_len = size < available ? size : available;
  memcpy(fixture->output + fixture->output_len, buf, copy_len);
  fixture->output_len += copy_len;
  fixture->output[fixture->output_len] = '\0';
  return (ssize_t)size;
}

static void test_handler(cli_t *cli) {
  fixture_t *fixture = cli->callback_context;
  fixture->handler_calls++;
  cli_ok(cli, "");
}

static const cli_command_t commands[] = {{
    .name = "x",
    .func = test_handler,
    .info = "test",
    .args = "",
}, {
    .name = "reboot-to-bootloader",
    .func = test_handler,
    .info = "test",
    .args = "",
}};

static size_t count_occurrences(const char *text, const char *needle) {
  size_t count = 0;
  size_t needle_len = strlen(needle);
  while ((text = strstr(text, needle)) != NULL) {
    count++;
    text += needle_len;
  }
  return count;
}

static void run_case(const uint8_t *input, size_t input_len, size_t limit,
                     bool accepted) {
  fixture_t fixture = {.input = input, .input_len = input_len};
  cli_t cli;
  CHECK(cli_init(&cli, fixture_read, fixture_write, &fixture));
  cli_set_commands(&cli, commands, sizeof(commands) / sizeof(commands[0]));
  cli_set_strict_input(&cli, true);
  if (limit != 0) {
    cli_set_line_limit(&cli, limit);
  }

  const cli_command_t *command = cli_process_io(&cli);
  if (accepted) {
    CHECK(command == &commands[0]);
    cli_process_command(&cli, command);
    CHECK(fixture.handler_calls == 1);
    CHECK(strcmp(fixture.output, "OK\r\n") == 0);
  } else {
    CHECK(command == NULL);
    CHECK(fixture.handler_calls == 0);
    CHECK(count_occurrences(fixture.output, "ERROR") == 1);
  }
}

static void run_printable_case(size_t length, size_t limit, bool accepted) {
  uint8_t input[132];
  CHECK(length >= 1 && length + 1 <= sizeof(input));
  input[0] = 'x';
  memset(input + 1, ' ', length - 1);
  input[length] = '\n';
  run_case(input, length + 1, limit, accepted);
}

static void test_raw_byte_limit(void) {
  uint8_t valid[129] = {'x'};
  memset(valid + 1, ' ', sizeof(valid) - 2);
  valid[128] = '\n';
  run_case(valid, sizeof(valid), 128, true);

  uint8_t overlong[130] = {'x'};
  overlong[129] = '\n';
  run_case(overlong, sizeof(overlong), 128, false);
}

static void test_strict_input_rejects_controls_without_dispatch(void) {
  static const uint8_t nul_in_reboot[] =
      "reboot-to-\0bootloader\n";
  run_case(nul_in_reboot, sizeof(nul_in_reboot) - 1, 128, false);

  static const uint8_t escape_in_reboot[] =
      "reboot-to-\x1b" "bootloader\n";
  run_case(escape_in_reboot, sizeof(escape_in_reboot) - 1, 128, false);
}

static void test_strict_input_recovers_on_next_line(void) {
  static const uint8_t input[] = {'x', 0, '\n', 'x', '\n'};
  fixture_t fixture = {.input = input, .input_len = sizeof(input)};
  cli_t cli;
  CHECK(cli_init(&cli, fixture_read, fixture_write, &fixture));
  cli_set_commands(&cli, commands, sizeof(commands) / sizeof(commands[0]));
  cli_set_strict_input(&cli, true);
  cli_set_line_limit(&cli, 128);

  CHECK(cli_process_io(&cli) == NULL);
  CHECK(fixture.handler_calls == 0);
  CHECK(count_occurrences(fixture.output, "ERROR") == 1);

  const cli_command_t *command = cli_process_io(&cli);
  CHECK(command == &commands[0]);
  cli_process_command(&cli, command);
  CHECK(fixture.handler_calls == 1);
  CHECK(count_occurrences(fixture.output, "ERROR") == 1);
  CHECK(count_occurrences(fixture.output, "OK") == 1);
}

void putchar_(char ch) { (void)ch; }

int main(void) {
  run_printable_case(128, 128, true);
  run_printable_case(129, 128, false);
  run_printable_case(129, 0, true);
  test_raw_byte_limit();
  test_strict_input_rejects_controls_without_dispatch();
  test_strict_input_recovers_on_next_line();
  return 0;
}
