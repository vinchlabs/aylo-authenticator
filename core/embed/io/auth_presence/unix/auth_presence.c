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

#include <io/auth_presence.h>

// A host has no slot, so there is no line to read and no configuration that
// would give it one. Reporting an absence would claim a working line that
// happens to be empty, and a wait above it would then sit out its full timeout
// waiting for a card that cannot arrive. A fault is the truth and is refused at
// once.
//
// Emulator tests that need a confirmation drive the test provider directly.
// This backend exists so the emulator links the same seam as the device rather
// than a different one, not so the emulator can pretend to have hardware.

bool auth_presence_init(void) { return false; }

auth_presence_state auth_presence_sample(void) { return AUTH_PRESENCE_FAULT; }

void auth_presence_deinit(void) {}
