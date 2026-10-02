#pragma once
#include <sec/authenticator.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../replica_records.h"

// Private secure-kernel adapter binding the vault to the T3T1 replica areas.
// No binding or syscall exports any of this.
//
// Everything here forwards to replica_records, which owns the snapshot model,
// and reaches flash only through auth_replica_io_t3t1(). There is deliberately
// no key-value surface left: the previous version spoke NORCOW keys
// 0xff01/0xff10+i /0xff80+i, and the key-range validation that came with it now
// lives in the record codec instead.

// Classifies the three replica areas. `provision` is accepted for call-site
// compatibility with the previous facade but no longer changes behaviour:
// nothing is created here, and whether provisioning is permitted is decided by
// the classification.
auth_result auth_store_open(bool provision);

// AUTH_OK when a snapshot is present, AUTH_UNPROVISIONED when the areas are
// ours and empty, AUTH_MIGRATION_REQUIRED when they hold data that is not ours.
auth_result auth_store_state(void);

auth_result auth_store_root_candidates(
    uint8_t out[AUTH_REPLICA_COUNT][AUTH_RECORD_SIZE], uint8_t *count);
auth_result auth_store_unlock(const uint8_t kek[32], uint8_t root_out[32]);
auth_result auth_store_provision(const uint8_t root[32],
                                 const uint8_t envelope[AUTH_RECORD_SIZE],
                                 const uint8_t nonce[AUTH_REPLICA_NONCE_SIZE]);
auth_result auth_store_commit_root(
    const uint8_t root[32], const uint8_t envelope[AUTH_RECORD_SIZE],
    const uint8_t nonce[AUTH_REPLICA_NONCE_SIZE]);
auth_result auth_store_record_read(const uint8_t root[32], uint8_t index,
                                   uint8_t *out, uint16_t capacity,
                                   uint16_t *length);
auth_result auth_store_record_walk(const uint8_t root[32],
                                   auth_slot_visitor visitor, void *context);
auth_result auth_store_record_write(
    const uint8_t root[32], uint8_t index, const uint8_t *record,
    uint16_t length, const uint8_t nonce[AUTH_REPLICA_NONCE_SIZE]);
auth_result auth_store_record_delete(
    const uint8_t root[32], uint8_t index,
    const uint8_t nonce[AUTH_REPLICA_NONCE_SIZE]);
auth_result auth_store_repair(const uint8_t root[32]);
auth_result auth_store_resident_capacity(uint8_t index, uint16_t id_len);
auth_result auth_store_wipe(void);
