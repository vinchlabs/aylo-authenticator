// STM32U5 backend for checked flash reads.
//
// The read itself is an ordinary copy. There is no assembly window, no recovery
// point and nothing clever about the load, because an ECC double error is not
// survived inside the read: it is fatal, and what this file arranges is that
// the *next* boot knows which replica killed the last one. See
// sys/flash_checked.h for why containment was removed rather than kept
// unvalidated.
//
// Two platform details are all that distinguish this from the host backend:
// where the ECC fault address comes from, and where the quarantine word lives.

#include <trezor_bsp.h>
#include <trezor_model.h>
#include <trezor_rtl.h>

#include <sys/flash_checked.h>

#ifdef KERNEL_MODE

// The secure and non-secure flash aliases (0x0C000000 and 0x08000000) map the
// same physical array, and flash_get_address() hands back whichever one matches
// the sector's security attribute. The ECC fail address, by contrast, is
// reported bank-relative. Stripping the alias puts both into one comparison
// space: a plain byte offset from the start of flash.
#define FLASH_CHECKED_ALIAS_STRIP_MASK 0x03FFFFFFu

static inline uint32_t flash_checked_strip_alias(uint32_t address) {
  return address & FLASH_CHECKED_ALIAS_STRIP_MASK;
}

// Bank size as a compile-time constant. The CMSIS FLASH_BANK_SIZE macro derives
// this by dereferencing the flash-size register, and this value is needed
// inside NMI context while an ECC error is latched; a flash read there is
// exactly what we are trying not to do.
#define FLASH_CHECKED_BANK_SIZE (FLASH_SIZE_DEFAULT / 2U)

// ECC is computed over 128-bit lines, so the hardware reports the address of
// the failing line rather than of the byte the load asked for. The source range
// is widened to line granularity before it is compared, otherwise a genuine
// fault on the line holding the first or last requested byte would not be
// attributed to the replica it belongs to.
#define FLASH_CHECKED_ECC_LINE_SIZE 16u

// Clears the ECC latch while preserving the correction-interrupt enable. ECCC
// and ECCD are write-1-to-clear; the address and bank fields are read-only.
static inline void flash_checked_clear_ecc_flags(uint32_t flags) {
  FLASH->ECCR = (FLASH->ECCR & FLASH_ECCR_ECCIE_Msk) | flags;
}

// ---------------------------------------------------------------------------
// The quarantine word
// ---------------------------------------------------------------------------
//
// A TAMP backup register, chosen over a RAM location for two reasons. It
// survives the reset the fault path performs -- which ordinary RAM does not,
// because reboot_with_args_phase_2() clears everything except the stack and the
// boot arguments, and the boot arguments are rewritten by that same path. And
// writing it is a single store, which is all that should happen in fault
// context.
//
// Register 31 is the last of the thirty-two and deliberately far from registers
// 0..7, which sec/secret holds and which TAMP_SECCFGR.BKPRWSEC protects. A
// tamper event erases all backup registers, which clears the quarantine as a
// side effect; that is correct, since a tamper wipe destroys the vault anyway.
#define FLASH_CHECKED_QUARANTINE_REG (TAMP->BKP31R)

uint32_t flash_checked_quarantine_load(void) {
  return FLASH_CHECKED_QUARANTINE_REG;
}

void flash_checked_quarantine_store(uint32_t word) {
  FLASH_CHECKED_QUARANTINE_REG = word;
}

// ---------------------------------------------------------------------------

flash_checked_result_t flash_area_checked_read(const flash_area_t *area,
                                               uint32_t offset, void *dst,
                                               uint32_t len) {
  // Everything up to the load behaves identically on every backend, so a caller
  // cannot tell the platforms apart by probing for bad requests.
  flash_checked_result_t validated =
      flash_checked_validate(area, offset, dst, len);
  if (validated != FLASH_CHECKED_OK) {
    return flash_checked_finalize(validated, dst, len);
  }

  flash_checked_context_t *context = flash_checked_active_context();
  // Checked before the context is touched, so a nested call cannot disturb the
  // read that is already in flight.
  if (context->active) {
    return flash_checked_finalize(FLASH_CHECKED_BUSY, dst, len);
  }

  const uint8_t index = flash_checked_area_index(area);

  // The load is refused before it happens if a previous boot died reading this
  // replica. This is the whole mechanism: without it the same line would fault
  // again, and the device would reboot for ever instead of once.
  if (flash_checked_quarantine_holds(flash_checked_quarantine_load(), index)) {
    return flash_checked_finalize(FLASH_CHECKED_ECC_UNCORRECTABLE, dst, len);
  }

  const void *source = flash_area_get_address(area, offset, len);
  if (source == NULL) {
    return flash_checked_finalize(FLASH_CHECKED_RANGE, dst, len);
  }
  if (flash_checked_ranges_overlap((uintptr_t)source, len, (uintptr_t)dst,
                                   len)) {
    return flash_checked_finalize(FLASH_CHECKED_RANGE, dst, len);
  }

  const uint32_t source_offset =
      flash_checked_strip_alias((uint32_t)(uintptr_t)source);

  context->area_index = index;
  context->source_begin = source_offset & ~(FLASH_CHECKED_ECC_LINE_SIZE - 1u);
  context->source_end =
      (source_offset + len + FLASH_CHECKED_ECC_LINE_SIZE - 1u) &
      ~(FLASH_CHECKED_ECC_LINE_SIZE - 1u);
  context->dest_begin = (uint32_t)(uintptr_t)dst;
  context->dest_end = context->dest_begin + len;

  // Drop any stale latch so that what is observed afterwards belongs to this
  // read, then publish the context before the load can possibly fault. The
  // barrier is what makes the context visible to an NMI taken by the very first
  // byte of the copy.
  flash_checked_clear_ecc_flags(FLASH_ECCR_ECCC | FLASH_ECCR_ECCD);
  context->active = true;
  __DMB();

  memcpy(dst, source, len);

  __DMB();
  const uint32_t eccr = FLASH->ECCR;
  flash_checked_clear_ecc_flags(FLASH_ECCR_ECCC | FLASH_ECCR_ECCD);

  flash_checked_result_t result;
  if ((eccr & FLASH_ECCR_ECCD_Msk) != 0) {
    // Reaching here means an uncorrectable error was latched without the NMI
    // taking the device down -- the ECC interrupt disabled, or a fault path
    // that returned. The data cannot be trusted, so this replica is excluded
    // for this session. It is deliberately *not* quarantined: the read was
    // survived, and persisting an exclusion needs the stronger evidence of a
    // boot that died.
    result = FLASH_CHECKED_ECC_UNCORRECTABLE;
  } else if ((eccr & FLASH_ECCR_ECCC_Msk) != 0) {
    // Data is good, but this replica is decaying and makes a better repair
    // destination than a repair source.
    result = FLASH_CHECKED_ECC_CORRECTED;
  } else {
    result = FLASH_CHECKED_OK;
  }

  // Cleared on every exit path that claimed it.
  flash_checked_context_clear(context);
  return flash_checked_finalize(result, dst, len);
}

void flash_checked_record_eccd(uint32_t eccr) {
  // Only an ECC double error is ours to consider.
  if ((eccr & FLASH_ECCR_ECCD_Msk) == 0) return;
  // A failure in system flash is never one of our replicas.
  if ((eccr & FLASH_ECCR_SYSF_ECC_Msk) != 0) return;

  const uint32_t bank = (eccr & FLASH_ECCR_BK_ECC_Msk) >> FLASH_ECCR_BK_ECC_Pos;
  // ADDR_ECC is a byte offset inside the reporting bank: the field is exactly
  // as wide as a bank on each variant (20 bits for the 1 MiB banks of
  // STM32U585, 21 bits for the 2 MiB banks of U5A5/U5G9).
  const uint32_t fault_offset =
      (eccr & FLASH_ECCR_ADDR_ECC_Msk) + bank * FLASH_CHECKED_BANK_SIZE;

  uint8_t index = FLASH_CHECKED_AREA_NONE;
  if (!flash_checked_attribute_eccd(flash_checked_active_context(),
                                    fault_offset, &index)) {
    // Not attributable to a replica. Recorded against nothing; the caller's
    // fatal path is unchanged either way.
    return;
  }

  // One store, and nothing else. The caller takes the device down immediately
  // after this returns, and the register survives that.
  flash_checked_quarantine_store(
      flash_checked_quarantine_add(flash_checked_quarantine_load(), index));
}

#endif  // KERNEL_MODE
