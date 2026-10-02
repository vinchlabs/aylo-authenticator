// Host/emulator backend for checked flash reads.
//
// There is no ECC hardware here, so this is an ordinary bounds-checked copy
// that enforces exactly the same contract as the STM32 backend: allowlisted
// areas only, non-reentrant, no destination aliasing the source, a quarantined
// replica refused without a read, and the whole destination zeroized on any
// result that does not carry data. It never *invents* an ECC result, because
// that would let host tests pass on behaviour the hardware has not been shown
// to have -- but it does honour the quarantine, so the exclusion logic above it
// is exercised on the host rather than only on a board.

#include <sys/flash_checked.h>

#include <string.h>

// Plain storage. On hardware this word is a backup register that survives a
// reset; here nothing ever reboots, so a variable is the whole of it. Tests
// drive it through the same two accessors the firmware uses.
static uint32_t g_quarantine;

uint32_t flash_checked_quarantine_load(void) { return g_quarantine; }

void flash_checked_quarantine_store(uint32_t word) { g_quarantine = word; }

flash_checked_result_t flash_area_checked_read(const flash_area_t *area,
                                               uint32_t offset, void *dst,
                                               uint32_t len) {
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

  // Same publication order as the stm32u5 backend: every field first, `active`
  // last. Nothing here can observe a half-published context because the host
  // has no NMI, but the two backends should not disagree about the rule.
  context->area_index = index;
  context->source_begin = (uint32_t)(uintptr_t)source;
  context->source_end = context->source_begin + len;
  context->dest_begin = (uint32_t)(uintptr_t)dst;
  context->dest_end = context->dest_begin + len;
  context->active = true;

  memcpy(dst, source, len);

  // Cleared on every exit path that claimed it.
  flash_checked_context_clear(context);
  return flash_checked_finalize(FLASH_CHECKED_OK, dst, len);
}

void flash_checked_record_eccd(uint32_t eccr) {
  (void)eccr;
  // No NMI and no ECC on the host, so there is never anything to record.
}
