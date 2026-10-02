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

#pragma once

#include "bootloaders/bootloader_hashes.h"
#include "secret_layout.h"

#include <rtl/sizedefs.h>

#define MODEL_NAME "Safe 5"
#define MODEL_FULL_NAME "Trezor Safe 5"
#define MODEL_INTERNAL_NAME "T3T1"
#define MODEL_INTERNAL_NAME_TOKEN T3T1
#define MODEL_INTERNAL_NAME_QSTR MP_QSTR_T3T1
#define MODEL_USB_MANUFACTURER "Trezor Company"
#define MODEL_USB_PRODUCT MODEL_FULL_NAME
#define MODEL_HOMESCREEN_MAXSIZE 16384

// Replaced for this project: the constants that were here are SatoshiLabs' and
// nobody outside SatoshiLabs holds the private halves, so a non-devel build using
// them could never be signed at all. These are the aylo authenticator's own,
// generated for activation step 2; the private halves live only off this machine.
// See docs/authenticator/activation.md for which set verifies what, and keys/README.md
// beside them for what losing one costs.
#define MODEL_BOARDLOADER_KEYS \
  (const uint8_t *)"\x7c\xfd\x63\xaa\xa1\x99\x46\x71\xb9\x2d\xe7\x37\x01\x09\xec\x7b\xd4\xf0\x49\x7a\x76\x57\x9e\xe6\xd6\xc6\x56\x49\xa7\xf5\x7f\xb2", \
  (const uint8_t *)"\xba\xd3\x74\x6e\xc8\x34\x19\x10\x47\xe9\x4f\x5f\x37\x55\x65\x5d\x68\x64\xe5\x8c\x84\x9a\x9f\xc1\xd7\xd7\x4b\x9e\x3c\x4b\x78\xb4", \
  (const uint8_t *)"\x7d\x09\x4e\x14\x59\x78\xf7\x69\x65\x86\x21\xe6\x4e\x78\x84\x9f\x5f\xdd\xd4\x9f\x37\xc0\x1a\x7a\x94\x2b\x24\x83\xea\xd3\x6b\xb6",

#define MODEL_BOOTLOADER_KEYS \
  (const uint8_t *)"\xaa\x17\x37\xdf\xda\xb2\x07\xff\x95\xba\x42\xe0\x3a\x1d\x37\x7b\x8f\x5b\x70\x0d\xf7\x6d\x29\x76\x52\xb1\xe3\x09\xc4\xfc\x5b\x8d", \
  (const uint8_t *)"\x8e\x79\x8e\x39\xcc\xe1\xb1\x19\x02\xe6\xc9\x44\x4b\x05\xcf\x38\xc3\xff\xbb\x28\x2f\xdb\x52\x7c\x36\xa7\x04\x83\xb7\x85\x60\x31", \
  (const uint8_t *)"\xfa\x77\xd3\x85\x02\x01\x05\x65\x43\x3e\x56\xc0\x01\x80\xad\x62\x80\xee\x07\x07\x67\x8b\x78\x61\xf9\x37\xac\x63\xc0\x1e\xaf\xfb",

#define IMAGE_CHUNK_SIZE (128 * 1024)
#define IMAGE_HASH_SHA256

#define DISPLAY_JUMP_BEHAVIOR DISPLAY_RETAIN_CONTENT
#define RSOD_INFINITE_LOOP 1

#define NORCOW_SECTOR_SIZE (8 * 8 * 1024)  // 64 kB
#define NORCOW_MIN_VERSION 0x00000004

#include "memory.h"
