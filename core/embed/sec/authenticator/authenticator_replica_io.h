#pragma once
// Private three-area replica IO contract used by replica_store and by the
// host fault model. This is deliberately a callback table rather than a
// direct flash dependency so that:
//
//   * replica_store contains no flash addresses, MPU transitions, or
//     platform headers and can be exercised entirely on the host;
//   * the T3T1 adapter in stm32u5/ is the only place that maps a replica index
//     onto a real flash area, and it reaches flash through the checked
//     reader in sys/flash rather than raw mapped pointers;
//   * the host power-cut model can interrupt any individual program line
//     or page erase without the manager being able to tell the difference.
//
// None of this is a syscall or binding surface.

#include <stdbool.h>
#include <stdint.h>

#include "replica_format.h"  // AUTH_REPLICA_AREA_SIZE

// Replica indices are logical (0, 1, 2). The mapping onto STORAGE_1,
// STORAGE_2, and ASSETS lives in the platform adapter, never here.
#define AUTH_REPLICA_COUNT 3u
#define AUTH_REPLICA_NONE 0xffu

// STM32U5 program granularity. A single line write is NOT assumed to be
// power-fail atomic: an interrupted line may read back as unknown bytes or
// raise ECCD.
#define AUTH_REPLICA_LINE_SIZE 16u

// STM32U5 page erase granularity within one 64 KiB replica area. Also not
// assumed power-fail atomic.
#define AUTH_REPLICA_PAGE_SIZE 8192u
#define AUTH_REPLICA_PAGES_PER_AREA \
  (AUTH_REPLICA_AREA_SIZE / AUTH_REPLICA_PAGE_SIZE)  // 8

typedef enum {
  AUTH_REPLICA_IO_OK = 0,
  // Read succeeded, but the hardware reported a corrected ECC error. The
  // data is usable; the replica is treated as degraded and preferred as a
  // repair destination rather than a long-term source.
  AUTH_REPLICA_IO_ECC_CORRECTED,
  // Read failed with an uncorrectable ECC error. The caller must treat the
  // output buffer as meaningless (the adapter zeroizes it) and exclude only
  // this replica.
  AUTH_REPLICA_IO_ECC_UNCORRECTABLE,
  // Offset/length outside the replica area, or a bad replica index.
  AUTH_REPLICA_IO_RANGE,
  // Any other transport/adapter failure.
  AUTH_REPLICA_IO_FAILED,
} auth_replica_io_result;

typedef struct {
  // Copies `len` bytes from `replica` at `offset` into caller-owned `out`.
  // Must zeroize `out` on any non-success result.
  auth_replica_io_result (*read)(void *context, uint8_t replica,
                                 uint32_t offset, uint8_t *out, uint32_t len);
  // Programs exactly one AUTH_REPLICA_LINE_SIZE-byte line. `offset` must be
  // line aligned. Returns false on any failure.
  bool (*write_line)(void *context, uint8_t replica, uint32_t offset,
                     const uint8_t line[AUTH_REPLICA_LINE_SIZE]);
  // Erases exactly one AUTH_REPLICA_PAGE_SIZE-byte page. `offset` must be
  // page aligned. Returns false on any failure.
  bool (*erase_page)(void *context, uint8_t replica, uint32_t offset);
  void *context;
} auth_replica_io;

// The T3T1 binding: replica 0/1/2 onto the storage-1, storage-2 and assets
// areas. Implemented in stm32u5/authenticator_replica_io.c, which is the only
// translation unit that knows a replica has a physical address. Returns a
// pointer to static storage; there is no per-call state.
const auth_replica_io *auth_replica_io_t3t1(void);
