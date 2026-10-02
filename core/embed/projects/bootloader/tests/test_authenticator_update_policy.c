#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "authenticator_update_policy.h"

#define assert(condition)                                                 \
  do {                                                                    \
    if (!(condition)) {                                                   \
      fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__, __LINE__,  \
              #condition);                                                \
      exit(1);                                                            \
    }                                                                     \
  } while (0)

// A correctly signed, current authenticator image. Every test below starts from
// this and spoils exactly one thing, so a failure names the thing it spoiled.
static authenticator_image_facts_t good(void) {
  authenticator_image_facts_t facts;
  memset(&facts, 0, sizeof(facts));
  facts.signature_valid = true;
  facts.model_matches = true;
  facts.product_is_authenticator = true;
  facts.image_monotonic = 3;
  facts.stored_monotonic = 3;
  return facts;
}

static void test_a_good_image_is_allowed_both_ways(void) {
  authenticator_image_facts_t facts = good();
  // Warm, with the application's authorization.
  assert(authenticator_update_check(&facts, false, true) ==
         AUTHENTICATOR_UPDATE_ALLOWED);
  assert(authenticator_update_allowed(&facts, false, true));
  // Cold, inside the window, with nothing to authorize it -- which is the case the
  // window exists for: an application that cannot run cannot authorize anything.
  assert(authenticator_update_check(&facts, true, false) ==
         AUTHENTICATOR_UPDATE_ALLOWED);
  assert(authenticator_update_allowed(&facts, true, false));
}

static void test_a_warm_update_without_authorization_is_refused(void) {
  authenticator_image_facts_t facts = good();
  assert(authenticator_update_check(&facts, false, false) ==
         AUTHENTICATOR_UPDATE_NOT_AUTHORIZED);
  assert(!authenticator_update_allowed(&facts, false, false));
}

static void test_authorization_is_judged_before_the_image(void) {
  // An unauthorized request is told it is unauthorized and nothing else, even when
  // the image it offered is unsigned, for the wrong model, the wrong product and a
  // downgrade all at once. Otherwise the refusal would be an oracle telling whoever
  // holds the cable whether they hold a valid image for this device.
  authenticator_image_facts_t facts;
  memset(&facts, 0, sizeof(facts));
  facts.image_monotonic = 0;
  facts.stored_monotonic = 9;
  assert(authenticator_update_check(&facts, false, false) ==
         AUTHENTICATOR_UPDATE_NOT_AUTHORIZED);

  // And the same bad image, once authorized, is refused on its own merits.
  assert(authenticator_update_check(&facts, false, true) ==
         AUTHENTICATOR_UPDATE_UNSIGNED);
}

static void test_the_cold_window_excuses_authorization_and_nothing_else(void) {
  authenticator_image_facts_t facts = good();
  facts.signature_valid = false;
  assert(authenticator_update_check(&facts, true, false) ==
         AUTHENTICATOR_UPDATE_UNSIGNED);

  facts = good();
  facts.model_matches = false;
  assert(authenticator_update_check(&facts, true, false) ==
         AUTHENTICATOR_UPDATE_WRONG_MODEL);

  facts = good();
  facts.product_is_authenticator = false;
  assert(authenticator_update_check(&facts, true, false) ==
         AUTHENTICATOR_UPDATE_WRONG_PRODUCT);

  facts = good();
  facts.image_monotonic = 2;
  facts.stored_monotonic = 3;
  assert(authenticator_update_check(&facts, true, false) ==
         AUTHENTICATOR_UPDATE_DOWNGRADE);
}

static void test_an_unsigned_image_is_never_installed(void) {
  authenticator_image_facts_t facts = good();
  facts.signature_valid = false;
  assert(authenticator_update_check(&facts, false, true) ==
         AUTHENTICATOR_UPDATE_UNSIGNED);
  assert(authenticator_update_check(&facts, true, true) ==
         AUTHENTICATOR_UPDATE_UNSIGNED);
}

static void test_ordinary_firmware_is_refused_as_the_wrong_product(void) {
  // The reason this check has to exist: the authenticator inherits the model's
  // firmware monotonic version, so a correctly signed ordinary Trezor image for
  // this model carries the same counter value and passes every other test here.
  authenticator_image_facts_t facts = good();
  facts.product_is_authenticator = false;
  assert(authenticator_update_check(&facts, false, true) ==
         AUTHENTICATOR_UPDATE_WRONG_PRODUCT);
  // Including when it is newer.
  facts.image_monotonic = AUTHENTICATOR_MONOTONIC_MAX;
  assert(authenticator_update_check(&facts, false, true) ==
         AUTHENTICATOR_UPDATE_WRONG_PRODUCT);
}

static void test_the_counter_may_not_go_backwards(void) {
  authenticator_image_facts_t facts = good();
  facts.stored_monotonic = 5;
  facts.image_monotonic = 4;
  assert(authenticator_update_check(&facts, false, true) ==
         AUTHENTICATOR_UPDATE_DOWNGRADE);
  // Equal is allowed: reinstalling the running version is how a damaged image is
  // repaired, and the counter write for it is a no-op.
  facts.image_monotonic = 5;
  assert(authenticator_update_check(&facts, false, true) ==
         AUTHENTICATOR_UPDATE_ALLOWED);
  // Forward is allowed.
  facts.image_monotonic = 6;
  assert(authenticator_update_check(&facts, false, true) ==
         AUTHENTICATOR_UPDATE_ALLOWED);
}

static void test_a_version_the_counter_cannot_hold_is_refused(void) {
  // monoctr_write refuses anything above the maximum and
  // ensure_firmware_min_version halts the device when the write fails, so an image
  // asking for 64 would be installed and then refuse to boot. Refusing it here is
  // the difference between a declined update and a brick.
  authenticator_image_facts_t facts = good();
  facts.image_monotonic = AUTHENTICATOR_MONOTONIC_MAX + 1;
  assert(authenticator_update_check(&facts, false, true) ==
         AUTHENTICATOR_UPDATE_VERSION_OUT_OF_RANGE);

  facts = good();
  facts.image_monotonic = AUTHENTICATOR_MONOTONIC_MAX;
  assert(authenticator_update_check(&facts, false, true) ==
         AUTHENTICATOR_UPDATE_ALLOWED);
}

static void test_a_damaged_counter_read_is_not_compared_against(void) {
  // A stored value above the maximum cannot have come from the counter. Comparing
  // an image against it would produce a confident answer derived from a number that
  // means nothing, so it is refused as out of range instead.
  authenticator_image_facts_t facts = good();
  facts.stored_monotonic = AUTHENTICATOR_MONOTONIC_MAX + 1;
  facts.image_monotonic = AUTHENTICATOR_MONOTONIC_MAX;
  assert(authenticator_update_check(&facts, false, true) ==
         AUTHENTICATOR_UPDATE_VERSION_OUT_OF_RANGE);
}

static void test_no_facts_at_all_is_refused(void) {
  // A caller that lost its facts is not a caller that may install firmware.
  assert(authenticator_update_check(NULL, true, true) ==
         AUTHENTICATOR_UPDATE_NOT_AUTHORIZED);
  assert(!authenticator_update_allowed(NULL, true, true));
}

int main(void) {
  test_a_good_image_is_allowed_both_ways();
  test_a_warm_update_without_authorization_is_refused();
  test_authorization_is_judged_before_the_image();
  test_the_cold_window_excuses_authorization_and_nothing_else();
  test_an_unsigned_image_is_never_installed();
  test_ordinary_firmware_is_refused_as_the_wrong_product();
  test_the_counter_may_not_go_backwards();
  test_a_version_the_counter_cannot_hold_is_refused();
  test_a_damaged_counter_read_is_not_compared_against();
  test_no_facts_at_all_is_refused();
  puts("authenticator update policy: PASS");
  return 0;
}
