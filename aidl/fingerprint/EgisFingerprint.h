/*
 * Copyright (C) 2026 The LineageOS Project
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <hardware/fingerprint.h>

namespace aidl::android::hardware::biometrics::fingerprint::egis {

// Opens the Egis ET520 capacitive sensor through libRbsFlow_cap.so and exposes it as a
// legacy fingerprint_device_t, like the stock Oplus fingerprint service does internally.
fingerprint_device_t* open();

}  // namespace aidl::android::hardware::biometrics::fingerprint::egis
