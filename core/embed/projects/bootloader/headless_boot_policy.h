#pragma once

#include <stdbool.h>
#include <stdint.h>

bool headless_should_jump(bool valid_firmware, bool forced_loader,
                          bool recognized_session, bool window_expired);

bool headless_is_recognized_message(uint16_t message_id);

bool headless_forced_loader(bool stay_in_bootloader, uint64_t boot_command);

uint32_t headless_poll_deadline(uint32_t now, uint32_t window_deadline,
                                uint32_t max_wait_ms);
