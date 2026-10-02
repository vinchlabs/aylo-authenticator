#include <stddef.h>

#include "authenticator_update_policy.h"

authenticator_update_verdict_t authenticator_update_check(
    const authenticator_image_facts_t *facts, bool cold_recovery_window,
    bool app_authorized) {
  if (facts == NULL) {
    return AUTHENTICATOR_UPDATE_NOT_AUTHORIZED;
  }

  // Authorization is decided first, and that ordering is the point rather than an
  // accident. Whoever is holding the cable chose the image; if the image were
  // judged first, the refusal would tell them whether they hold a correctly signed
  // authenticator image for this model before telling them they may not install it.
  // That is a validity oracle for images, and it is free to withhold.
  //
  // A cold start inside the window needs no authorization, because the case it
  // exists for is a device whose application cannot run and therefore cannot
  // authorize anything. Everything else still applies to it.
  if (!cold_recovery_window && !app_authorized) {
    return AUTHENTICATOR_UPDATE_NOT_AUTHORIZED;
  }

  if (!facts->signature_valid) {
    return AUTHENTICATOR_UPDATE_UNSIGNED;
  }
  if (!facts->model_matches) {
    return AUTHENTICATOR_UPDATE_WRONG_MODEL;
  }
  // Checked after the model so that a signed image for other hardware is reported
  // as the wrong hardware, which is what it is, rather than as the wrong product.
  if (!facts->product_is_authenticator) {
    return AUTHENTICATOR_UPDATE_WRONG_PRODUCT;
  }

  // Out of range before downgrade: a stored counter above the maximum is a damaged
  // read, and comparing against it would produce an answer about an image from a
  // number that means nothing.
  if (facts->image_monotonic > AUTHENTICATOR_MONOTONIC_MAX ||
      facts->stored_monotonic > AUTHENTICATOR_MONOTONIC_MAX) {
    return AUTHENTICATOR_UPDATE_VERSION_OUT_OF_RANGE;
  }
  // The same comparison the silicon makes, and never a laxer one. Equal is allowed:
  // reinstalling the running version is how a damaged image is repaired, and the
  // counter write for it is a no-op.
  if (facts->image_monotonic < facts->stored_monotonic) {
    return AUTHENTICATOR_UPDATE_DOWNGRADE;
  }

  return AUTHENTICATOR_UPDATE_ALLOWED;
}

bool authenticator_update_allowed(const authenticator_image_facts_t *facts,
                                  bool cold_recovery_window,
                                  bool app_authorized) {
  return authenticator_update_check(facts, cold_recovery_window,
                                    app_authorized) ==
         AUTHENTICATOR_UPDATE_ALLOWED;
}
