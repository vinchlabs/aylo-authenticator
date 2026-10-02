/*
 * This file is part of the Trezor project, https://trezor.io/
 *
 * Copyright (c) SatoshiLabs
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <trezor_bsp.h>

#include <io/auth_presence.h>

#if KERNEL_MODE

// The card-detect line, and nothing else.
//
// No SDMMC peripheral, no card power, no clock to the card, no command or data
// pins, no filesystem. This driver is incapable of talking to a card: it reads
// one input. That is not a description of intent, it is what the image audit
// checks -- an artifact where the SD subsystem's symbols reappear is refused,
// because a card slot that can be read from is a second way into the device.
//
// The board header gives the port and the pin but neither a pull nor a
// clock-enable macro for this line, so both are supplied here. The line is
// active low: a card in the slot shorts it to ground, and the pull-up holds it
// high while the slot is empty. That polarity is what makes the idle state the
// safe one -- an unconnected or broken line reads as "no card", never as a
// confirmation.

typedef struct {
  bool initialized;
} auth_presence_driver_t;

static auth_presence_driver_t g_auth_presence_driver = {
    .initialized = false,
};

bool auth_presence_init(void) {
  auth_presence_driver_t *drv = &g_auth_presence_driver;
  if (drv->initialized) {
    return true;
  }

  // One port, named rather than derived. If a board revision moves the line,
  // this refuses instead of configuring a pin whose clock was never enabled and
  // reading whatever the floating input happens to say.
  if (SD_DETECT_PORT != GPIOC) {
    return false;
  }
  __HAL_RCC_GPIOC_CLK_ENABLE();

  GPIO_InitTypeDef GPIO_InitStructure = {0};
  GPIO_InitStructure.Mode = GPIO_MODE_INPUT;
  GPIO_InitStructure.Pull = GPIO_PULLUP;
  GPIO_InitStructure.Speed = GPIO_SPEED_FREQ_LOW;
  GPIO_InitStructure.Pin = SD_DETECT_PIN;
  HAL_GPIO_Init(SD_DETECT_PORT, &GPIO_InitStructure);

  drv->initialized = true;
  return true;
}

auth_presence_state auth_presence_sample(void) {
  auth_presence_driver_t *drv = &g_auth_presence_driver;
  if (!drv->initialized && !auth_presence_init()) {
    // Nothing was configured, so there is nothing to read. Reporting an absence
    // here would claim a working line that happens to be empty.
    return AUTH_PRESENCE_FAULT;
  }
  return (GPIO_PIN_RESET == HAL_GPIO_ReadPin(SD_DETECT_PORT, SD_DETECT_PIN))
             ? AUTH_PRESENCE_PRESENT
             : AUTH_PRESENCE_ABSENT;
}

void auth_presence_deinit(void) {
  auth_presence_driver_t *drv = &g_auth_presence_driver;
  if (!drv->initialized) {
    return;
  }
  HAL_GPIO_DeInit(SD_DETECT_PORT, SD_DETECT_PIN);
  drv->initialized = false;
}

#endif
