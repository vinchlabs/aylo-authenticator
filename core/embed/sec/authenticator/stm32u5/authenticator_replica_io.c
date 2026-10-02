// T3T1 binding for the three replica areas.
//
// This is the only place in the vault that knows a replica index corresponds to
// a physical flash area. Everything above it -- the codec, the transaction
// manager, the credential logic -- deals in indices 0, 1, 2 and never sees a
// flash address, a sector number, or an MPU mode.
//
// Three rules shape the file:
//
//   * Reads go through the checked reader, never through a mapped pointer. A
//     replica torn by a power cut can raise an ECC double error when read, and
//     the checked reader is what decides whether that is survivable. While it
//     reports UNSUPPORTED -- which it does on any image without the validated
//     ECCD probe -- every read here fails, and the vault stays closed rather
//     than risking a fault or, worse, mistaking unreadable media for blank.
//
//   * The MPU window is opened for exactly one operation and closed again on
//     every path. Storage and assets are programmed into the same banked MPU
//     region, so they cannot both be writable at once; holding a window open
//     across replicas is not possible even if it were desirable.
//
//   * Requests are validated before any flash call. A bad index, a misaligned
//     offset or a length that would leave the area is refused without touching
//     hardware, so a defect upstream cannot become a write to the wrong place.

#include <trezor_model.h>
#include <trezor_rtl.h>

#include <sys/flash.h>
#include <sys/flash_checked.h>
#include <sys/mpu.h>

#include "memzero.h"

#include "../authenticator_replica_io.h"

// The replica geometry is not negotiable: it is baked into the authenticated
// wire format, so a layout change would invalidate every provisioned device
// rather than merely move data. These assertions tie the format to the real
// T3T1 map, checked at compile time against the production memory layout.
_Static_assert(STORAGE_1_SECTOR_START == 0x18 && STORAGE_1_SECTOR_END == 0x1F,
               "replica 0 must be the storage-1 sectors");
_Static_assert(STORAGE_2_SECTOR_START == 0x20 && STORAGE_2_SECTOR_END == 0x27,
               "replica 1 must be the storage-2 sectors");
_Static_assert(ASSETS_SECTOR_START == 0xF8 && ASSETS_SECTOR_END == 0xFF,
               "replica 2 must be the assets sectors");
_Static_assert(STORAGE_1_MAXSIZE == AUTH_REPLICA_AREA_SIZE &&
                   STORAGE_2_MAXSIZE == AUTH_REPLICA_AREA_SIZE &&
                   ASSETS_MAXSIZE == AUTH_REPLICA_AREA_SIZE,
               "every replica area must be exactly one snapshot in size");
// Sector count times page size must account for the whole area, which is what
// makes a page-indexed erase sweep equivalent to erasing the area.
_Static_assert((STORAGE_1_SECTOR_END - STORAGE_1_SECTOR_START + 1) *
                       AUTH_REPLICA_PAGE_SIZE ==
                   AUTH_REPLICA_AREA_SIZE,
               "replica page size does not match the T3T1 sector map");
_Static_assert(AUTH_REPLICA_PAGES_PER_AREA ==
                   (STORAGE_1_SECTOR_END - STORAGE_1_SECTOR_START + 1),
               "replica page count does not match the T3T1 sector map");
_Static_assert(FLASH_BLOCK_SIZE == AUTH_REPLICA_LINE_SIZE,
               "replica line size must equal the flash program granularity");
// The three replicas must be disjoint from each other and from the firmware
// image, so that replacing the firmware cannot reach vault data and so that one
// replica's erase can never clip another. Proving it from the layout constants
// means a future memory-map change cannot quietly create an overlap.
_Static_assert(STORAGE_1_SECTOR_END < STORAGE_2_SECTOR_START,
               "replica 0 and replica 1 must not overlap");
_Static_assert(STORAGE_2_SECTOR_END < FIRMWARE_SECTOR_START &&
                   FIRMWARE_SECTOR_END < ASSETS_SECTOR_START,
               "a firmware image must not overlap any replica area");

typedef struct {
  const flash_area_t *area;
  mpu_mode_t mpu_mode;
} replica_binding_t;

// Index order is part of the on-device layout. Reordering these entries would
// silently repoint an already-provisioned device's replicas at each other, so
// the order is fixed even though the manager treats the three symmetrically.
static const replica_binding_t kBindings[AUTH_REPLICA_COUNT] = {
    {.area = &STORAGE_AREAS[0], .mpu_mode = MPU_MODE_STORAGE},
    {.area = &STORAGE_AREAS[1], .mpu_mode = MPU_MODE_STORAGE},
    {.area = &ASSETS_AREA, .mpu_mode = MPU_MODE_ASSETS},
};

static const replica_binding_t *binding(uint8_t replica) {
  if (replica >= AUTH_REPLICA_COUNT) {
    return NULL;
  }
  return &kBindings[replica];
}

static auth_replica_io_result replica_read(void *context, uint8_t replica,
                                           uint32_t offset, uint8_t *out,
                                           uint32_t len) {
  (void)context;

  if (out == NULL || len == 0) {
    return AUTH_REPLICA_IO_RANGE;
  }
  // Cleared up front so that every refusal below leaves a destination the
  // caller cannot mistake for data. The manager reuses one region buffer across
  // replicas, so a failed read must not leave the previous replica's bytes in
  // it.
  memzero(out, len);

  // Written as a subtraction so a wrapping offset + len cannot pass.
  if (offset > AUTH_REPLICA_AREA_SIZE ||
      len > AUTH_REPLICA_AREA_SIZE - offset) {
    return AUTH_REPLICA_IO_RANGE;
  }

  const replica_binding_t *bound = binding(replica);
  if (bound == NULL) {
    return AUTH_REPLICA_IO_RANGE;
  }

  mpu_mode_t previous = mpu_reconfig(bound->mpu_mode);
  flash_checked_result_t result =
      flash_area_checked_read(bound->area, offset, out, len);
  mpu_restore(previous);

  switch (result) {
    case FLASH_CHECKED_OK:
      return AUTH_REPLICA_IO_OK;
    case FLASH_CHECKED_ECC_CORRECTED:
      return AUTH_REPLICA_IO_ECC_CORRECTED;
    case FLASH_CHECKED_ECC_UNCORRECTABLE:
      return AUTH_REPLICA_IO_ECC_UNCORRECTABLE;
    case FLASH_CHECKED_RANGE:
      return AUTH_REPLICA_IO_RANGE;
    case FLASH_CHECKED_BUSY:
    case FLASH_CHECKED_UNSUPPORTED:
    default:
      // The manager must treat this replica as unreadable, never as blank.
      return AUTH_REPLICA_IO_FAILED;
  }
}

static bool replica_write_line(void *context, uint8_t replica, uint32_t offset,
                               const uint8_t line[AUTH_REPLICA_LINE_SIZE]) {
  (void)context;

  if (line == NULL) {
    return false;
  }
  if (offset % AUTH_REPLICA_LINE_SIZE != 0) {
    return false;
  }
  if (offset > AUTH_REPLICA_AREA_SIZE - AUTH_REPLICA_LINE_SIZE) {
    return false;
  }

  const replica_binding_t *bound = binding(replica);
  if (bound == NULL) {
    return false;
  }

  // flash_area_write_block() reads the payload as 32-bit words, so it is copied
  // into an aligned block rather than casting the caller's byte buffer.
  flash_block_t block;
  memcpy(block, line, AUTH_REPLICA_LINE_SIZE);

  mpu_mode_t previous = mpu_reconfig(bound->mpu_mode);
  // Programming needs the flash controller unlocked; unlike erase, the area
  // helper does not do this for us. The window is closed again immediately.
  bool unlocked = (sectrue == flash_unlock_write());
  secbool written = secfalse;
  if (unlocked) {
    written = flash_area_write_block(bound->area, offset, block);
    if (sectrue != flash_lock_write()) {
      written = secfalse;
    }
  }
  mpu_restore(previous);

  memzero(block, sizeof(block));
  return written == sectrue;
}

static bool replica_erase_page(void *context, uint8_t replica,
                               uint32_t offset) {
  (void)context;

  if (offset % AUTH_REPLICA_PAGE_SIZE != 0) {
    return false;
  }
  if (offset > AUTH_REPLICA_AREA_SIZE - AUTH_REPLICA_PAGE_SIZE) {
    return false;
  }

  const replica_binding_t *bound = binding(replica);
  if (bound == NULL) {
    return false;
  }

  mpu_mode_t previous = mpu_reconfig(bound->mpu_mode);
  uint32_t bytes_erased = 0;
  secbool erased = flash_area_erase_partial(bound->area, offset, &bytes_erased);
  mpu_restore(previous);

  // Anything other than exactly one page means the sector map is not what this
  // adapter was built against, and the manager's page accounting would be
  // wrong. Refuse rather than carry on with a different geometry.
  if (erased != sectrue || bytes_erased != AUTH_REPLICA_PAGE_SIZE) {
    return false;
  }

  // A page that has just been erased holds no torn line, so whatever made a
  // previous boot die here is gone and the replica deserves another chance.
  // This is the only way out of quarantine: without it a replica damaged once
  // would be refused for the life of the device, and the repair the manager is
  // in the middle of would be pointless.
  //
  // Clearing on any page erase rather than on a full-area rewrite is
  // deliberate. The quarantine records a replica, not an offset, so there is
  // nothing to match a page against. If damage remains in a page this erase did
  // not touch, the next read of it faults again and re-quarantines -- one
  // wasted boot, and the state is correct afterwards. The alternative, staying
  // quarantined until some larger operation completes, risks never clearing at
  // all.
  const uint8_t index = flash_checked_area_index(bound->area);
  flash_checked_quarantine_store(
      flash_checked_quarantine_remove(flash_checked_quarantine_load(), index));
  return true;
}

const auth_replica_io *auth_replica_io_t3t1(void) {
  static const auth_replica_io io = {
      .read = replica_read,
      .write_line = replica_write_line,
      .erase_page = replica_erase_page,
      // The binding is static, so there is no per-call state to carry.
      .context = NULL,
  };
  return &io;
}
