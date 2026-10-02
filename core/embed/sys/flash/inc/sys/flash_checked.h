#pragma once
// Checked, ECC-aware reads for the authenticator's three replica areas.
//
// Why this exists: the triple-replica vault must be able to *examine* a replica
// that a power cut left partially written. On STM32U5 an interrupted program
// can leave a flash line whose ECC no longer checks out, and reading such a
// line raises an ECC double error (ECCD) as an asynchronous NMI. A plain
// dereference of a torn replica would therefore kill the firmware on every
// boot, for ever, because the next boot reads the same line again.
//
// This module provides the *only* sanctioned way for vault code to read those
// areas. Vault code must never dereference a memory-mapped pointer into them.
//
// How a torn line is survived, and why it is not survived inside the read.
//
// The obvious design is to contain the ECCD: catch the NMI, redirect the
// stacked return address into a recovery point, and hand the caller an error.
// That was built, and then removed. Containment cannot be validated on this
// silicon: an ECC double error needs a program that stopped partway through,
// measurement on hardware established that software cannot produce one --
// re-programming a line is refused by the driver and then by the flash
// controller, a reset mid-program leaves the line either untouched or complete,
// and withdrawing the program request does not stop the controller at all.
// Twenty-two measurements, no torn line. Only a collapsing supply can make one,
// which no bench here can do. Resuming out of an asynchronous NMI on a stack
// whose register state the compiler chose is the riskiest construct this
// project had, and it is not worth keeping for a hazard that cannot be
// exercised.
//
// What replaced it is deliberately duller. An ECCD stays fatal. Before the
// fault path takes the device down, the NMI records *which replica* the failing
// line belonged to, in storage that survives the reboot the fault path already
// performs. The next boot refuses that replica without reading it, so the
// manager excludes it and the remaining replicas carry the vault. Nothing is
// resumed, no exception frame is rewritten, and the only work done in fault
// context is one store.
//
// The cost is one lost boot per torn replica, and the worst case of a wrong
// decision is excluding a replica that did not need excluding -- which a
// three-replica design already tolerates. Compare that with the worst case of
// resuming: continuing on a stack the compiler no longer agrees about, with
// credential material in flight.
//
// Scope discipline, in order of importance:
//
//   * Exactly three areas are accepted, compared by object identity, not by
//     contents: the two storage areas and assets. A forged flash_area_t that
//     merely describes the same sectors is refused.
//   * Output is copied into caller-owned RAM and the *entire* requested
//     destination is zeroized on any result that does not carry data, so a
//     partial copy can never be mistaken for data.
//   * The reader is strictly non-reentrant. One active context at a time; a
//     nested call is refused rather than silently nesting.
//   * Attribution is narrow. An ECCD is blamed on a replica only when a checked
//     read of that replica is in flight and the failing ECC line lies inside
//     the range being read. Anything else -- an unrelated ECCD, a Clock
//     Security System NMI, a fault with no read open -- is recorded against
//     nothing and stays fatal, exactly as before this module existed.
//
// The decision logic is deliberately separated from the platform code so that
// the security-critical part is exercised on the host rather than only on a
// board.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <trezor-storage/flash_area.h>

typedef enum {
  FLASH_CHECKED_OK = 0,
  // Read succeeded but the hardware corrected a single-bit ECC error. Data is
  // usable; the caller should prefer this replica as a repair destination.
  FLASH_CHECKED_ECC_CORRECTED,
  // This replica cannot be read. Either an ECC double error was latched without
  // taking the fault path, or a previous boot died reading this replica and it
  // is still quarantined. The destination has been fully zeroized and the
  // caller must exclude only this replica.
  FLASH_CHECKED_ECC_UNCORRECTABLE,
  // Bad area identity, offset/length outside the area, overflow, null or
  // overlapping destination.
  FLASH_CHECKED_RANGE,
  // A checked read is already active; this call would be reentrant.
  FLASH_CHECKED_BUSY,
  // This platform cannot read the area at all.
  FLASH_CHECKED_UNSUPPORTED,
} flash_checked_result_t;

// The three replica areas, in the order their indices are assigned.
#define FLASH_CHECKED_AREA_COUNT 3u
// Returned by flash_checked_area_index() for anything not allowlisted, and the
// value an inactive context carries.
#define FLASH_CHECKED_AREA_NONE 0xffu

// State of the single in-flight checked read. Consulted from NMI context, so it
// stays plain data with no locks and no allocation.
typedef struct {
  bool active;
  // Which replica is being read, so the NMI knows what to blame. Indices come
  // from flash_checked_area_index().
  uint8_t area_index;
  // Source range being read, [begin, end). These live in a *comparison space*
  // chosen by the platform: the only requirement is that the platform places
  // the ECC fault address it reports to flash_checked_attribute_eccd() into the
  // same space. The stm32u5 backend uses alias-stripped flash offsets so that
  // the secure and non-secure views of one physical line compare equal.
  uint32_t source_begin;
  uint32_t source_end;
  // Caller-owned destination, [begin, end).
  uint32_t dest_begin;
  uint32_t dest_end;
} flash_checked_context_t;

// ---------------------------------------------------------------------------
// Policy layer. Platform independent and host tested.
// ---------------------------------------------------------------------------

// Returns true when `area` is one of the three allowlisted replica areas,
// compared by pointer identity so a forged copy cannot impersonate one.
bool flash_checked_area_allowed(const flash_area_t *area);

// Maps an allowlisted area onto its replica index, or FLASH_CHECKED_AREA_NONE.
// The mapping lives here rather than in the vault because the NMI needs it and
// must not depend on anything above sys.
uint8_t flash_checked_area_index(const flash_area_t *area);

// Validates a request without touching flash. `dst` is treated as an opaque
// address range purely for null and wrap checks.
flash_checked_result_t flash_checked_validate(const flash_area_t *area,
                                              uint32_t offset, const void *dst,
                                              uint32_t len);

// True when the two byte ranges share at least one byte. Backends use this to
// refuse a destination that aliases the mapped source, which they can only
// check once the source address is resolved.
bool flash_checked_ranges_overlap(uintptr_t first_begin, uint32_t first_len,
                                  uintptr_t second_begin, uint32_t second_len);

// True only for results whose destination holds trustworthy data.
bool flash_checked_result_has_data(flash_checked_result_t result);

// Single definition of the destination rule: a result that does not carry data
// leaves the *whole* requested destination zeroized. Every backend funnels its
// return value through this, so no exit path can leak a partial copy. Returns
// `result` unchanged.
flash_checked_result_t flash_checked_finalize(flash_checked_result_t result,
                                              void *dst, uint32_t len);

// Returns the single global context. Exposed so the NMI path and the tests can
// reach the same state the reader uses.
flash_checked_context_t *flash_checked_active_context(void);

// Puts `context` into the no-read-in-flight state. Not a memset: the replica
// index is set to FLASH_CHECKED_AREA_NONE rather than zero, because zero is a
// real replica. A plain memset would leave a context that blames replica 0 to
// anything that forgot to check `active` first, and that is a mistake worth
// making impossible rather than merely documenting.
void flash_checked_context_clear(flash_checked_context_t *context);

// ---------------------------------------------------------------------------
// The quarantine word
// ---------------------------------------------------------------------------
//
// One word, held by the platform in storage that survives a reset, naming the
// replicas a previous boot died reading. The magic is what distinguishes a real
// record from an uninitialised or tamper-erased register: without it, a
// register that happens to read 0xFFFFFFFF would quarantine every replica at
// once and brick the vault far more thoroughly than the fault it is meant to
// survive.

// Occupies the upper 24 bits, leaving the low byte for the replica mask.
#define FLASH_CHECKED_QUARANTINE_MAGIC 0x51554100u
#define FLASH_CHECKED_QUARANTINE_MASK 0x000000ffu

// True when `word` carries the magic and no bits outside the defined replicas.
bool flash_checked_quarantine_valid(uint32_t word);

// True when `word` is valid and quarantines `index`. A word without the magic
// quarantines nothing, which is the fail-open direction on purpose: the
// alternative is a device that refuses every replica because a register was
// never written.
bool flash_checked_quarantine_holds(uint32_t word, uint8_t index);

// Returns `word` with `index` quarantined. An invalid input word is replaced
// rather than extended, so garbage cannot survive into the result.
uint32_t flash_checked_quarantine_add(uint32_t word, uint8_t index);

// Returns `word` with `index` no longer quarantined. An invalid input word
// becomes a valid empty one, so a replica that has just been rewritten is
// trusted again regardless of what the register held before.
uint32_t flash_checked_quarantine_remove(uint32_t word, uint8_t index);

// Decides whether an ECC double error is attributable to the read in flight,
// and to which replica. Every condition must hold: a read is active, it names a
// replica, its range is well formed, and the failing ECC line lies inside that
// range.
//
// Deliberately weaker than the containment decision it replaces, which also
// checked the stacked PC and the exception's stack. Both of those existed to
// make *resuming* safe. Nothing is resumed now, and neither says anything about
// which replica the failing line belongs to, which is the only question left.
//
// On success writes the replica index to `index_out` and returns true.
bool flash_checked_attribute_eccd(const flash_checked_context_t *context,
                                  uint32_t fault_address, uint8_t *index_out);

// ---------------------------------------------------------------------------
// Platform layer
// ---------------------------------------------------------------------------

// Copies `len` bytes from `area` at `offset` into `dst`. Zeroizes the whole of
// `dst` on every result that does not carry data. Never reentrant.
//
// Refuses a quarantined replica without performing a load, which is what stops
// a torn line from killing every subsequent boot.
flash_checked_result_t flash_area_checked_read(const flash_area_t *area,
                                               uint32_t offset, void *dst,
                                               uint32_t len);

// The retained quarantine word. On STM32U5 this is a backup register that
// survives a reset; on the host it is a plain variable, which is enough because
// the host never faults.
uint32_t flash_checked_quarantine_load(void);
void flash_checked_quarantine_store(uint32_t word);

// Called from the NMI dispatcher, inside the existing ECCD branch, *before* the
// fatal path runs. Records the replica the failing line belongs to, if any, and
// returns. It never prevents the fault: the caller's existing behaviour is
// unchanged, which is why this takes no exception frame and cannot redirect
// anything.
void flash_checked_record_eccd(uint32_t eccr);
