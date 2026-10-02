#pragma once

#include <stdbool.h>
#include <stdint.h>

// The monotonic counter lives in STM32U5 secret flash as a unary run of written
// 16-byte lines, 0x400 bytes long on T3T1, so it represents 0..63 and nothing
// above. A header asking for more than this cannot be committed: monoctr_write
// refuses it and ensure_firmware_min_version then halts the device. Catching it
// here turns a brick into a refusal.
#define AUTHENTICATOR_MONOTONIC_MAX 63

// Why an update was allowed or refused. A verdict rather than a bool because the
// caller has to pick an upload_status_t and a message, and because a test that can
// only say "no" cannot tell a downgrade from an unsigned image.
typedef enum {
  AUTHENTICATOR_UPDATE_ALLOWED = 0,
  // The request did not come from a session that proved it may ask.
  AUTHENTICATOR_UPDATE_NOT_AUTHORIZED,
  // Vendor header keys or image header signature did not verify.
  AUTHENTICATOR_UPDATE_UNSIGNED,
  // Right signature, wrong hardware.
  AUTHENTICATOR_UPDATE_WRONG_MODEL,
  // A correctly signed image for this model that is not an authenticator.
  AUTHENTICATOR_UPDATE_WRONG_PRODUCT,
  // Older than what the counter has already seen.
  AUTHENTICATOR_UPDATE_DOWNGRADE,
  // A version the counter cannot hold, in the image or in the counter itself.
  AUTHENTICATOR_UPDATE_VERSION_OUT_OF_RANGE,
} authenticator_update_verdict_t;

// Everything about the offered image that the caller has already established by
// verifying it. This struct deliberately holds conclusions, not bytes: the policy
// does no parsing and no cryptography, so it can be read and tested as a decision.
typedef struct {
  // Vendor header verified against the device keys, and the image header verified
  // against the vendor header's own m-of-n set.
  bool signature_valid;
  // check_image_model and check_vendor_header_model both passed.
  bool model_matches;
  // The vendor header names this product as the authenticator rather than ordinary
  // firmware. Without this the monotonic counter cannot tell the two apart,
  // because the authenticator inherits the model's firmware monotonic version.
  bool product_is_authenticator;
  // image_header.monotonic as offered.
  uint8_t image_monotonic;
  // monoctr_read(MONOCTR_FIRMWARE_VERSION) as stored.
  uint8_t stored_monotonic;
} authenticator_image_facts_t;

// The whole decision, in one place.
//
// cold_recovery_window is true only on a cold start inside the bootloader's own
// window -- a power cycle, not a reboot out of the application. app_authorized is
// true only when the application asked for this reboot after a verified PIN and a
// gesture.
authenticator_update_verdict_t authenticator_update_check(
    const authenticator_image_facts_t *facts, bool cold_recovery_window,
    bool app_authorized);

// The plan's named interface, over the verdict.
bool authenticator_update_allowed(const authenticator_image_facts_t *facts,
                                  bool cold_recovery_window,
                                  bool app_authorized);
