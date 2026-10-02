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

// The host backend's fail-closed contract.
//
// There is nothing to mock here and nothing to simulate: the point of these
// assertions is that a build with no line to read says so, in every state, and
// never once reports an empty slot. An empty slot is something a caller waits
// through; a fault is something it refuses at once, and on a host the second is
// the truth.

#include <stdio.h>

#include <io/auth_presence.h>

static int failures = 0;

#define CHECK(cond)                                  \
  do {                                               \
    if (!(cond)) {                                   \
      printf("FAIL line %d: %s\n", __LINE__, #cond); \
      failures++;                                    \
    }                                                \
  } while (0)

int main(void) {
  // Before anything is initialized.
  CHECK(auth_presence_sample() == AUTH_PRESENCE_FAULT);

  // A host cannot configure a line it does not have, and says so rather than
  // reporting success and then reading a value nobody wrote.
  CHECK(auth_presence_init() == false);
  CHECK(auth_presence_sample() == AUTH_PRESENCE_FAULT);

  // Idempotent, and still a fault afterwards.
  CHECK(auth_presence_init() == false);
  CHECK(auth_presence_sample() == AUTH_PRESENCE_FAULT);

  // Releasing something that was never configured is not an error, and does not
  // turn the reading into an absence.
  auth_presence_deinit();
  CHECK(auth_presence_sample() == AUTH_PRESENCE_FAULT);
  auth_presence_deinit();
  CHECK(auth_presence_sample() == AUTH_PRESENCE_FAULT);

  // The three states are compared by value on the Python side. A collision
  // would turn a fault into a confirmation, so their distinctness is part of
  // the contract rather than an implementation detail.
  CHECK(AUTH_PRESENCE_ABSENT != AUTH_PRESENCE_PRESENT);
  CHECK(AUTH_PRESENCE_PRESENT != AUTH_PRESENCE_FAULT);
  CHECK(AUTH_PRESENCE_ABSENT != AUTH_PRESENCE_FAULT);
  // And the values themselves are the contract: presence.py mirrors these
  // numbers, because a reading crosses the boundary as a plain integer.
  CHECK(AUTH_PRESENCE_ABSENT == 0);
  CHECK(AUTH_PRESENCE_PRESENT == 1);
  CHECK(AUTH_PRESENCE_FAULT == 2);

  if (failures) {
    printf("auth presence host backend: FAIL (%d)\n", failures);
    return 1;
  }
  printf("auth presence host backend: PASS\n");
  return 0;
}
