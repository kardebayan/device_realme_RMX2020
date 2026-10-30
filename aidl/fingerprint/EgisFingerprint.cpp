/*
 * Copyright (C) 2026 The LineageOS Project
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define LOG_TAG "EgisFingerprint"

#include "EgisFingerprint.h"
#include "OplusFingerprint.h"

#include <android-base/logging.h>
#include <dlfcn.h>
#include <log/log.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstring>

namespace aidl::android::hardware::biometrics::fingerprint::egis {

namespace {

constexpr char kRbsLibrary[] = "libRbsFlow_cap.so";
// Log path handed to the TA as a zero padded buffer, like stock.
constexpr char kLogPath[] = "/data/vendor_de/0/fpdata";
constexpr uint32_t kLogPathType = 1;
constexpr size_t kLogPathSize = 0x100;
constexpr uint32_t kNoActiveGroup = 9999;
// rbs_initialize() is retried once after this delay, as stock does.
constexpr unsigned int kInitRetryDelaySec = 3;
// The enroll challenge expires 600 seconds after pre_enroll().
constexpr time_t kChallengeTimeoutSec = 600;

// rbs_* return codes.
constexpr int RBS_ERR_SENSOR = 4;
constexpr int RBS_ERR_NO_SPACE = 0xb;
constexpr int RBS_ERR_SECURE_ID = 0x21;

// Events delivered by libRbsFlow_cap.so to the rbs_set_on_callback_proc() handler.
enum RbsEvent : int32_t {
    EVENT_ENROLL_PROGRESS = 1002,  // value1: fid, value2: percentage
    EVENT_VERIFY_DONE = 1003,
    EVENT_IMG_INFO_1 = 1004,
    EVENT_IMG_INFO_2 = 1005,
    EVENT_VENDOR_ACQUIRED_1 = 1006,
    EVENT_VENDOR_ACQUIRED_2 = 1008,
    EVENT_IDENTIFY_MATCH = 1010,  // value1: gid, value2: fid, buffer: hw_auth_token_t
    EVENT_IDENTIFY_NO_MATCH = 1011,
    EVENT_IMG_BAD_QUALITY = 1013,
    EVENT_IMG_PARTIAL_1 = 1015,
    EVENT_IMG_PARTIAL_2 = 1016,
    EVENT_IMG_FAST_1 = 1017,
    EVENT_IMG_FAST_2 = 1018,
    EVENT_IMG_FAST_3 = 1019,
    EVENT_FINGER_TOUCH = 1021,
    EVENT_IMG_INFO_3 = 1022,
    EVENT_FINGER_LEAVE = 1023,
    EVENT_TOO_MANY_REJECTS = 1038,
    EVENT_ENGINEERING_INFO = 1039,
};

typedef void (*rbs_event_callback_t)(int32_t event, int32_t value1, int32_t value2,
                                     const uint8_t* buffer, int32_t size);

struct RbsFlow {
    void* handle;
    int (*initialize)(void* masterkey, uint32_t size);
    int (*uninitialize)();
    int (*cancel)();
    int (*active_user_group)(uint32_t gid, const char* path);
    int (*set_data_path)(uint32_t type, const char* path, uint32_t size);
    int (*chk_secure_id)(uint32_t gid, uint64_t secure_id);
    int (*pre_enroll)(uint32_t gid, uint32_t fid);
    int (*enroll)();
    int (*chk_auth_token)(const hw_auth_token_t* hat, uint32_t size);
    int (*get_authenticator_id)(uint64_t* id);
    int (*authenticator)(uint32_t gid, const uint32_t* fids, uint32_t count, uint64_t operation_id);
    int (*remove_fingerprint)(uint32_t gid, uint32_t fid);
    int (*get_fingerprint_ids)(uint32_t gid, uint32_t* fids, uint32_t* count);
    int (*get_screen_state)(int32_t* state);
    void (*set_on_callback_proc)(rbs_event_callback_t callback);
};

RbsFlow sRbs;
fingerprint_device_t sDevice;

// No lock is held around rbs_* calls: the library may block on its worker thread, which
// delivers events through onEvent().
std::atomic<uint32_t> sGid = kNoActiveGroup;
std::atomic<uint64_t> sChallenge;
std::atomic<time_t> sChallengeTime;
std::atomic<bool> sVerifying;
std::atomic<int32_t> sEnrollSteps;
std::atomic<int32_t> sEnrollPercentage;

void notify(const fingerprint_msg_t& msg) {
    if (sDevice.notify != nullptr) sDevice.notify(&msg);
}

void notifyError(fingerprint_error_t error) {
    fingerprint_msg_t msg = {.type = FINGERPRINT_ERROR};
    msg.data.error = error;
    notify(msg);
}

void notifyAcquired(int32_t info) {
    fingerprint_msg_t msg = {.type = FINGERPRINT_ACQUIRED};
    msg.data.acquired.acquired_info = static_cast<fingerprint_acquired_info_t>(info);
    notify(msg);
}

void notifyAuthenticated(uint32_t gid, uint32_t fid, const uint8_t* hat, int32_t size) {
    fingerprint_msg_t msg = {.type = FINGERPRINT_AUTHENTICATED};
    msg.data.authenticated.finger = {.gid = gid, .fid = fid};
    if (hat != nullptr && size == static_cast<int32_t>(sizeof(hw_auth_token_t))) {
        memcpy(&msg.data.authenticated.hat, hat, sizeof(hw_auth_token_t));
    } else if (fid != 0) {
        ALOGE("Invalid auth token size %d", size);
    }
    notify(msg);
}

int syncTemplates() {
    if (sGid == kNoActiveGroup) {
        ALOGE("No active group to enumerate");
        return -EINVAL;
    }

    uint32_t gid = sGid;
    uint32_t fids[OPLUS_FINGERPRINT_MAX_TEMPLATES] = {};
    uint32_t count = 0;
    int ret = sRbs.get_fingerprint_ids(gid, fids, &count);
    if (ret) {
        ALOGE("rbs_get_fingerprint_ids failed: %d", ret);
        return -EIO;
    }

    fingerprint_msg_t msg = {.type = static_cast<fingerprint_msg_type_t>(
                                     OPLUS_FINGERPRINT_TEMPLATE_SYNC)};
    auto* sync = reinterpret_cast<oplus_fingerprint_sync_t*>(&msg.data);
    sync->count = std::min<uint32_t>(count, OPLUS_FINGERPRINT_MAX_TEMPLATES);
    sync->gid = gid;
    for (uint32_t i = 0; i < sync->count; i++) {
        sync->fingers[i] = {.gid = gid, .fid = fids[i]};
    }
    notify(msg);
    return 0;
}

void onEnrollProgress(uint32_t fid, int32_t percentage) {
    // The library reports a percentage; derive the remaining samples the same way stock does.
    if (percentage != sEnrollPercentage) {
        sEnrollSteps++;
        sEnrollPercentage = percentage;
    }

    int32_t remaining;
    if (percentage >= 100) {
        remaining = 0;
        sEnrollSteps = 0;
        sEnrollPercentage = 0;
    } else if (percentage < 1) {
        remaining = 16;
    } else {
        int32_t steps = sEnrollSteps;
        int32_t total = static_cast<int32_t>(100.0f / percentage * steps);
        remaining = std::max(total - steps, 1);
    }

    fingerprint_msg_t msg = {.type = FINGERPRINT_TEMPLATE_ENROLLING};
    msg.data.enroll.finger = {.gid = sGid, .fid = fid};
    msg.data.enroll.samples_remaining = remaining;
    notify(msg);

    if (remaining == 0) syncTemplates();
}

void onBadImageQuality() {
    if (sVerifying) {
        // A bad image is a failed attempt, unless the sensor reports the screen is off.
        int32_t screenOn = 0;
        sRbs.get_screen_state(&screenOn);
        if (!screenOn) return;
        notifyAuthenticated(0, 0, nullptr, 0);
    }
    notifyAcquired(FINGERPRINT_ACQUIRED_IMAGER_DIRTY);
}

void onEvent(int32_t event, int32_t value1, int32_t value2, const uint8_t* buffer, int32_t size) {
    ALOGD("onEvent(%d, %d, %d)", event, value1, value2);

    switch (event) {
        case EVENT_ENROLL_PROGRESS:
            onEnrollProgress(value1, value2);
            break;
        case EVENT_VERIFY_DONE:
            sVerifying = false;
            break;
        case EVENT_VENDOR_ACQUIRED_1:
            notifyAcquired(FINGERPRINT_ACQUIRED_VENDOR_BASE + 1);
            break;
        case EVENT_VENDOR_ACQUIRED_2:
            notifyAcquired(FINGERPRINT_ACQUIRED_VENDOR_BASE + 2);
            break;
        case EVENT_IDENTIFY_MATCH:
        case EVENT_IDENTIFY_NO_MATCH:
            notifyAuthenticated(value1, value2, buffer, size);
            break;
        case EVENT_IMG_BAD_QUALITY:
            onBadImageQuality();
            break;
        case EVENT_IMG_PARTIAL_1:
        case EVENT_IMG_PARTIAL_2:
            notifyAcquired(FINGERPRINT_ACQUIRED_PARTIAL);
            break;
        case EVENT_IMG_FAST_1:
        case EVENT_IMG_FAST_2:
        case EVENT_IMG_FAST_3:
            notifyAcquired(FINGERPRINT_ACQUIRED_TOO_FAST);
            break;
        case EVENT_FINGER_TOUCH:
            notify({.type = static_cast<fingerprint_msg_type_t>(OPLUS_FINGERPRINT_TOUCH_DOWN)});
            break;
        case EVENT_FINGER_LEAVE:
            notify({.type = static_cast<fingerprint_msg_type_t>(OPLUS_FINGERPRINT_TOUCH_UP)});
            break;
        case EVENT_TOO_MANY_REJECTS:
            notifyError(FINGERPRINT_ERROR_UNABLE_TO_PROCESS);
            break;
        case EVENT_IMG_INFO_1:
        case EVENT_IMG_INFO_2:
        case EVENT_IMG_INFO_3:
        case EVENT_ENGINEERING_INFO:
            // Image quality / engineering mode reports, only used by the Oplus framework.
            break;
        default:
            ALOGW("Unhandled event %d", event);
            break;
    }
}

int setNotify(fingerprint_device_t* dev, fingerprint_notify_t notify) {
    dev->notify = notify;
    return 0;
}

uint64_t preEnroll(fingerprint_device_t* /*dev*/) {
    uint64_t challenge;
    arc4random_buf(&challenge, sizeof(challenge));
    sChallenge = challenge;
    sChallengeTime = time(nullptr);
    return challenge;
}

int enroll(fingerprint_device_t* /*dev*/, const hw_auth_token_t* hat, uint32_t gid,
           uint32_t /*timeout_sec*/) {
    sEnrollSteps = 0;
    sEnrollPercentage = 0;

    time_t now = time(nullptr);
    time_t challengeTime = sChallengeTime;
    if (now < challengeTime || now - challengeTime >= kChallengeTimeoutSec) {
        ALOGE("Enroll challenge expired");
        notifyError(FINGERPRINT_ERROR_TIMEOUT);
        return 0;
    }

    if (hat == nullptr || hat->timestamp == 0) {
        ALOGE("Invalid auth token");
        notifyError(FINGERPRINT_ERROR_UNABLE_TO_PROCESS);
        return 0;
    }

    if (hat->challenge != sChallenge) {
        ALOGE("Auth token challenge mismatch");
        notifyError(FINGERPRINT_ERROR_UNABLE_TO_PROCESS);
        return 0;
    }

    if (hat->version != HW_AUTH_TOKEN_VERSION) {
        ALOGE("Invalid auth token version %d", hat->version);
        return -EPROTONOSUPPORT;
    }

    if (sRbs.chk_auth_token(hat, sizeof(*hat))) {
        ALOGE("Auth token check failed");
        return -EPERM;
    }

    int ret = sRbs.chk_secure_id(gid, hat->user_id);
    if (ret == RBS_ERR_SECURE_ID) {
        // Templates belong to a previous secure user id, drop them and retry.
        ALOGW("Secure id changed, removing all fingerprints");
        if (sRbs.remove_fingerprint(gid, 0) == 0) {
            ret = sRbs.chk_secure_id(gid, hat->user_id);
        }
    }
    if (ret) {
        ALOGE("Secure id check failed: %d", ret);
        return -EPERM;
    }

    do {
        ret = sRbs.pre_enroll(gid, arc4random() & 0x7fffffff);
        if (ret == RBS_ERR_NO_SPACE) {
            ALOGE("No space left for a new template");
            notifyError(FINGERPRINT_ERROR_NO_SPACE);
            return 0;
        }
    } while (ret);

    sVerifying = false;
    ret = sRbs.enroll();
    if (ret) {
        ALOGE("rbs_enroll failed: %d", ret);
        return ret == RBS_ERR_SENSOR ? -ENODEV : -EIO;
    }

    return 0;
}

int postEnroll(fingerprint_device_t* /*dev*/) {
    sChallenge = 0;
    return 0;
}

uint64_t getAuthenticatorId(fingerprint_device_t* /*dev*/) {
    uint64_t id = 0;
    int ret = sRbs.get_authenticator_id(&id);
    if (ret) {
        ALOGE("rbs_get_authenticator_id failed: %d", ret);
    }
    return id;
}

int cancel(fingerprint_device_t* /*dev*/) {
    sEnrollSteps = 0;
    sEnrollPercentage = 0;

    int ret = sRbs.cancel();
    notifyError(FINGERPRINT_ERROR_CANCELED);
    return ret ? -EIO : 0;
}

int enumerate(fingerprint_device_t* /*dev*/) {
    return syncTemplates();
}

int remove(fingerprint_device_t* /*dev*/, uint32_t gid, uint32_t fid) {
    int ret = sRbs.remove_fingerprint(gid, fid);
    if (ret) {
        ALOGE("rbs_remove_fingerprint(%u) failed: %d", fid, ret);
        notifyError(FINGERPRINT_ERROR_UNABLE_TO_REMOVE);
        return 0;
    }

    fingerprint_msg_t msg = {.type = FINGERPRINT_TEMPLATE_REMOVED};
    msg.data.removed.finger = {.gid = gid, .fid = fid};
    notify(msg);

    syncTemplates();
    return 0;
}

int setActiveGroup(fingerprint_device_t* /*dev*/, uint32_t gid, const char* path) {
    sGid = gid;
    int ret = sRbs.active_user_group(gid, path);
    if (ret) {
        ALOGE("rbs_active_user_group failed: %d", ret);
        return -EIO;
    }
    return syncTemplates();
}

int authenticateAsType(fingerprint_device_t* /*dev*/, uint64_t operation_id, uint32_t gid,
                       uint32_t /*type*/) {
    sVerifying = true;
    int ret = sRbs.authenticator(gid, nullptr, 0, operation_id);
    if (ret) {
        ALOGE("rbs_authenticator failed: %d", ret);
        return ret == RBS_ERR_SENSOR ? -ENODEV : -EIO;
    }
    return 0;
}

int authenticate(fingerprint_device_t* dev, uint64_t operation_id, uint32_t gid) {
    return authenticateAsType(dev, operation_id, gid, OPLUS_FINGERPRINT_AUTH_TYPE_OTHER);
}

int close(hw_device_t* /*dev*/) {
    sRbs.uninitialize();
    dlclose(sRbs.handle);
    sRbs = {};
    return 0;
}

template <typename T>
bool loadSymbol(T& fn, const char* name) {
    fn = reinterpret_cast<T>(dlsym(sRbs.handle, name));
    if (fn == nullptr) {
        ALOGE("Failed to load %s: %s", name, dlerror());
        return false;
    }
    return true;
}

bool loadRbs() {
    sRbs.handle = dlopen(kRbsLibrary, RTLD_NOW);
    if (sRbs.handle == nullptr) {
        ALOGE("Failed to load %s: %s", kRbsLibrary, dlerror());
        return false;
    }

    if (loadSymbol(sRbs.initialize, "rbs_initialize") &&
        loadSymbol(sRbs.uninitialize, "rbs_uninitialize") &&
        loadSymbol(sRbs.cancel, "rbs_cancel") &&
        loadSymbol(sRbs.active_user_group, "rbs_active_user_group") &&
        loadSymbol(sRbs.set_data_path, "rbs_set_data_path") &&
        loadSymbol(sRbs.chk_secure_id, "rbs_chk_secure_id") &&
        loadSymbol(sRbs.pre_enroll, "rbs_pre_enroll") && loadSymbol(sRbs.enroll, "rbs_enroll") &&
        loadSymbol(sRbs.chk_auth_token, "rbs_chk_auth_token") &&
        loadSymbol(sRbs.get_authenticator_id, "rbs_get_authenticator_id") &&
        loadSymbol(sRbs.authenticator, "rbs_authenticator") &&
        loadSymbol(sRbs.remove_fingerprint, "rbs_remove_fingerprint") &&
        loadSymbol(sRbs.get_fingerprint_ids, "rbs_get_fingerprint_ids") &&
        loadSymbol(sRbs.get_screen_state, "rbs_get_screen_state") &&
        loadSymbol(sRbs.set_on_callback_proc, "rbs_set_on_callback_proc")) {
        return true;
    }

    dlclose(sRbs.handle);
    sRbs = {};
    return false;
}

}  // namespace

fingerprint_device_t* open() {
    if (!loadRbs()) return nullptr;

    char logPath[kLogPathSize] = {};
    strlcpy(logPath, kLogPath, sizeof(logPath));
    sRbs.set_data_path(kLogPathType, logPath, sizeof(logPath));
    sRbs.set_on_callback_proc(onEvent);

    int ret = sRbs.initialize(nullptr, 0);
    if (ret) {
        ALOGW("rbs_initialize failed: %d, retrying", ret);
        sleep(kInitRetryDelaySec);
        ret = sRbs.initialize(nullptr, 0);
    }
    if (ret) {
        ALOGE("rbs_initialize failed: %d", ret);
        dlclose(sRbs.handle);
        sRbs = {};
        return nullptr;
    }

    sDevice = {
            .common =
                    {
                            .tag = HARDWARE_DEVICE_TAG,
                            .version = FINGERPRINT_MODULE_API_VERSION_2_1,
                            .close = close,
                    },
            .set_notify = setNotify,
            .pre_enroll = preEnroll,
            .enroll = enroll,
            .post_enroll = postEnroll,
            .get_authenticator_id = getAuthenticatorId,
            .cancel = cancel,
            .enumerate = enumerate,
            .remove = remove,
            .set_active_group = setActiveGroup,
            .authenticate = authenticate,
    };
    sDevice.reserved[0] = reinterpret_cast<void*>(authenticateAsType);

    return &sDevice;
}

}  // namespace aidl::android::hardware::biometrics::fingerprint::egis
