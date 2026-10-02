// Platform-independent policy for checked flash reads.
//
// Everything here is pure decision logic over plain integers, so the rules that
// decide which replica an ECC double error belongs to -- and which replicas a
// previous boot has already condemned -- are exercised on the host instead of
// only on a board. The platform backends own the actual loads, the NMI and the
// retained register; they own no policy.

#include <sys/flash_checked.h>

#include <string.h>

// The three areas the authenticator owns. Defined by the platform's flash
// layout; the host test provides its own definitions.
extern const flash_area_t STORAGE_AREAS[];
extern const flash_area_t ASSETS_AREA;

static flash_checked_context_t g_context;

flash_checked_context_t *flash_checked_active_context(void) {
  return &g_context;
}

void flash_checked_context_clear(flash_checked_context_t *context) {
  if (context == NULL) return;
  memset(context, 0, sizeof(*context));
  context->area_index = FLASH_CHECKED_AREA_NONE;
}

bool flash_checked_area_allowed(const flash_area_t *area) {
  return flash_checked_area_index(area) != FLASH_CHECKED_AREA_NONE;
}

uint8_t flash_checked_area_index(const flash_area_t *area) {
  // Identity, not equality. A caller-fabricated flash_area_t that happens to
  // describe the same sectors is deliberately rejected: allowing it would turn
  // this into a general-purpose flash reader.
  if (area == &STORAGE_AREAS[0]) return 0u;
  if (area == &STORAGE_AREAS[1]) return 1u;
  if (area == &ASSETS_AREA) return 2u;
  return FLASH_CHECKED_AREA_NONE;
}

flash_checked_result_t flash_checked_validate(const flash_area_t *area,
                                              uint32_t offset, const void *dst,
                                              uint32_t len) {
  if (area == NULL || dst == NULL || len == 0) return FLASH_CHECKED_RANGE;
  if (!flash_checked_area_allowed(area)) return FLASH_CHECKED_RANGE;

  uint32_t size = flash_area_get_size(area);
  // Written as a subtraction so that a wrapping offset+len cannot pass.
  if (offset > size) return FLASH_CHECKED_RANGE;
  if (len > size - offset) return FLASH_CHECKED_RANGE;

  // Reject a destination range that wraps the address space.
  uintptr_t begin = (uintptr_t)dst;
  if (begin + len < begin) return FLASH_CHECKED_RANGE;

  return FLASH_CHECKED_OK;
}

bool flash_checked_ranges_overlap(uintptr_t first_begin, uint32_t first_len,
                                  uintptr_t second_begin, uint32_t second_len) {
  // An empty range touches nothing.
  if (first_len == 0 || second_len == 0) return false;
  uintptr_t first_end = first_begin + first_len;
  uintptr_t second_end = second_begin + second_len;
  // A wrapping range is treated as overlapping so that callers fail closed
  // rather than silently accepting a nonsensical pair.
  if (first_end < first_begin || second_end < second_begin) return true;
  return first_begin < second_end && second_begin < first_end;
}

bool flash_checked_result_has_data(flash_checked_result_t result) {
  return result == FLASH_CHECKED_OK || result == FLASH_CHECKED_ECC_CORRECTED;
}

flash_checked_result_t flash_checked_finalize(flash_checked_result_t result,
                                              void *dst, uint32_t len) {
  if (!flash_checked_result_has_data(result) && dst != NULL && len > 0) {
    memset(dst, 0, len);
  }
  return result;
}

// ---------------------------------------------------------------------------
// The quarantine word
// ---------------------------------------------------------------------------

// Bits above the replica mask that a valid word must reproduce exactly.
#define QUARANTINE_MAGIC_MASK (~FLASH_CHECKED_QUARANTINE_MASK)
// Only the three defined replicas may be named; a word claiming more than that
// is corruption, not a larger vault.
#define QUARANTINE_DEFINED_BITS ((1u << FLASH_CHECKED_AREA_COUNT) - 1u)

bool flash_checked_quarantine_valid(uint32_t word) {
  if ((word & QUARANTINE_MAGIC_MASK) != FLASH_CHECKED_QUARANTINE_MAGIC) {
    return false;
  }
  // An erased or never-written register reads as all ones or all zeroes; the
  // magic already rejects both. This additionally rejects a word whose magic
  // survived but whose mask names replicas that do not exist, which is the
  // shape a partially clobbered register takes.
  return (word & FLASH_CHECKED_QUARANTINE_MASK & ~QUARANTINE_DEFINED_BITS) ==
         0u;
}

bool flash_checked_quarantine_holds(uint32_t word, uint8_t index) {
  if (index >= FLASH_CHECKED_AREA_COUNT) return false;
  if (!flash_checked_quarantine_valid(word)) return false;
  return (word & (1u << index)) != 0u;
}

uint32_t flash_checked_quarantine_add(uint32_t word, uint8_t index) {
  if (index >= FLASH_CHECKED_AREA_COUNT) return word;
  // An invalid word contributes nothing: extending garbage would let a
  // clobbered register condemn replicas that never failed.
  const uint32_t existing =
      flash_checked_quarantine_valid(word)
          ? (word & FLASH_CHECKED_QUARANTINE_MASK & QUARANTINE_DEFINED_BITS)
          : 0u;
  return FLASH_CHECKED_QUARANTINE_MAGIC | existing | (1u << index);
}

uint32_t flash_checked_quarantine_remove(uint32_t word, uint8_t index) {
  const uint32_t existing =
      flash_checked_quarantine_valid(word)
          ? (word & FLASH_CHECKED_QUARANTINE_MASK & QUARANTINE_DEFINED_BITS)
          : 0u;
  if (index >= FLASH_CHECKED_AREA_COUNT) {
    // Still normalises the word, so a caller that hands over a bad index does
    // not leave garbage behind in the register.
    return FLASH_CHECKED_QUARANTINE_MAGIC | existing;
  }
  return FLASH_CHECKED_QUARANTINE_MAGIC | (existing & ~(1u << index));
}

bool flash_checked_attribute_eccd(const flash_checked_context_t *context,
                                  uint32_t fault_address, uint8_t *index_out) {
  if (index_out == NULL || context == NULL) return false;

  // No checked read in flight: this ECCD belongs to something else entirely and
  // must be recorded against nothing.
  if (!context->active) return false;

  // A context that names no replica cannot blame one.
  if (context->area_index >= FLASH_CHECKED_AREA_COUNT) return false;

  // Degenerate or inverted ranges are never attributable.
  if (context->source_begin >= context->source_end) return false;

  // The failing ECC line must be inside the very range we are reading. This is
  // the whole of the attribution rule: a fault outside it says nothing about
  // this replica, and a fault inside it can only be about this replica even if
  // some other code happened to issue the load.
  if (fault_address < context->source_begin ||
      fault_address >= context->source_end) {
    return false;
  }

  *index_out = context->area_index;
  return true;
}
