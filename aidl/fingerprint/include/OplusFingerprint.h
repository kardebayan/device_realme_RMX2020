/*
 * Copyright (C) 2026 The LineageOS Project
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <hardware/fingerprint.h>

#include <cstddef>

// Oplus extensions to the legacy fingerprint HAL, as handled by the stock
// vendor.oplus.hardware.biometrics.fingerprint@2.1-service.

// Extra fingerprint_msg_type_t values.
enum oplus_fingerprint_msg_type {
    OPLUS_FINGERPRINT_TOUCH_DOWN = 7,
    OPLUS_FINGERPRINT_TOUCH_UP = 8,
    // Sent instead of FINGERPRINT_TEMPLATE_ENUMERATING, carrying the whole template list.
    OPLUS_FINGERPRINT_TEMPLATE_SYNC = 11,
};

#define OPLUS_FINGERPRINT_MAX_TEMPLATES 5

// Payload of OPLUS_FINGERPRINT_TEMPLATE_SYNC, overlaid on fingerprint_msg_t::data.
typedef struct oplus_fingerprint_sync {
    fingerprint_finger_id_t fingers[OPLUS_FINGERPRINT_MAX_TEMPLATES];
    uint32_t count;
    uint32_t gid;
} oplus_fingerprint_sync_t;

static_assert(offsetof(fingerprint_msg_t, data) == 0x8);
static_assert(offsetof(fingerprint_msg_t, data) + offsetof(oplus_fingerprint_sync_t, count) == 0x30);
static_assert(offsetof(fingerprint_msg_t, data) + offsetof(oplus_fingerprint_sync_t, gid) == 0x34);
static_assert(sizeof(oplus_fingerprint_sync_t) <= sizeof(fingerprint_msg_t::data));

// fingerprint_device_t::reserved[0] holds authenticate_as_type().
typedef int (*oplus_authenticate_as_type_t)(fingerprint_device_t* dev, uint64_t operation_id,
                                            uint32_t gid, uint32_t type);

enum oplus_fingerprint_auth_type {
    OPLUS_FINGERPRINT_AUTH_TYPE_KEYGUARD = 1,
    OPLUS_FINGERPRINT_AUTH_TYPE_PAY = 2,
    OPLUS_FINGERPRINT_AUTH_TYPE_OTHER = 3,
};
