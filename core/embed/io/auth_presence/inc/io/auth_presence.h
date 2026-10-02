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

#ifndef __TREZORHAL_AUTH_PRESENCE_H__
#define __TREZORHAL_AUTH_PRESENCE_H__

#include <trezor_types.h>

// One reading of the physical confirmation line. On this board that line is the
// microSD card-detect pin, which is the only input a person can reach: there is
// no button, and the touchscreen is left out of this firmware entirely.
//
// Three values rather than a bool, on purpose. A reading that cannot be trusted
// has to be distinguishable from "no card", because the two demand opposite
// answers: an absence is something to keep waiting through, while a fault is
// something to refuse at once. Collapsing them would turn a broken line into a
// wait that can never end.
typedef enum {
  AUTH_PRESENCE_ABSENT = 0,
  AUTH_PRESENCE_PRESENT = 1,
  AUTH_PRESENCE_FAULT = 2,
} auth_presence_state;

// Configures the line. Idempotent, and the only function here that changes
// hardware configuration.
//
// Deliberately not given a syscall stub: the unprivileged application cannot
// configure, reconfigure or release the pin, and a call from there fails to
// link rather than being refused at runtime. The kernel configures the line on
// the first reading it is asked for.
bool auth_presence_init(void);

// One reading, and the only part of this module the application can reach.
// Initializes the line if it has not been initialized yet, so asking for a
// reading never requires the right to configure anything.
auth_presence_state auth_presence_sample(void);

void auth_presence_deinit(void);

#endif
