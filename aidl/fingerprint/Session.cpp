/*
 * Copyright (C) 2024 The LineageOS Project
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <sys/stat.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <format>
#include <thread>

#include "Legacy2Aidl.h"
#include "OplusFingerprint.h"
#include "Session.h"

#include "CancellationSignal.h"

namespace aidl::android::hardware::biometrics::fingerprint {

namespace {
constexpr char FPDATA_PATH[] = "/data/vendor_de/{}/fpdata";
constexpr uint32_t ENROLL_TIMEOUT_SEC = 60;
}  // namespace

void onClientDeath(void* cookie) {
    ALOGI("FingerprintService has died");
    Session* session = static_cast<Session*>(cookie);
    if (session && !session->isClosed()) {
        session->close();
    }
}

Session::Session(fingerprint_device_t* device, int userId, std::shared_ptr<ISessionCallback> cb,
                 LockoutTracker lockoutTracker)
    : mDevice(device), mLockoutTracker(lockoutTracker), mUserId(userId), mCb(cb) {
    mDeathRecipient = AIBinder_DeathRecipient_new(onClientDeath);

    // The AIDL framework no longer creates the per-user store path.
    auto path = std::format(FPDATA_PATH, userId);
    if (mkdir(path.c_str(), 0700) != 0 && errno != EEXIST) {
        ALOGE("Failed to create %s: %s", path.c_str(), strerror(errno));
    }

    int error = mDevice->set_active_group(mDevice, mUserId, path.c_str());
    if (error) {
        ALOGE("set_active_group failed: %d", error);
    }
}

ndk::ScopedAStatus Session::generateChallenge() {
    uint64_t challenge = mDevice->pre_enroll(mDevice);
    ALOGI("generateChallenge: %ld", challenge);
    mCb->onChallengeGenerated(challenge);

    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::revokeChallenge(int64_t challenge) {
    ALOGI("revokeChallenge: %ld", challenge);
    mDevice->post_enroll(mDevice);
    mCb->onChallengeRevoked(challenge);

    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::enroll(const HardwareAuthToken& hat,
                                   std::shared_ptr<ICancellationSignal>* out) {
    hw_auth_token_t authToken = {.version = HW_AUTH_TOKEN_VERSION};
    translate(hat, authToken);
    int error = mDevice->enroll(mDevice, &authToken, mUserId, ENROLL_TIMEOUT_SEC);
    if (error) {
        ALOGE("enroll failed: %d", error);
        mCb->onError(HalErrorFilter(error), error);
    }

    *out = SharedRefBase::make<CancellationSignal>(this);
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::authenticate(int64_t operationId,
                                         std::shared_ptr<ICancellationSignal>* out) {
    *out = SharedRefBase::make<CancellationSignal>(this);

    if (checkSensorLockout()) {
        return ndk::ScopedAStatus::ok();
    }

    int error = authenticateAsType(operationId);
    if (error) {
        ALOGE("authenticate failed: %d", error);
        mCb->onError(HalErrorFilter(error), error);
    }

    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::detectInteraction(std::shared_ptr<ICancellationSignal>* out) {
    ALOGD("Detect interaction is not supported");
    mCb->onError(Error::UNABLE_TO_PROCESS, 0 /* vendorCode */);

    *out = SharedRefBase::make<CancellationSignal>(this);
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::enumerateEnrollments() {
    {
        std::lock_guard<std::mutex> lock(mTemplatesLock);
        mEnumeratePending = true;
    }

    // Answered through FINGERPRINT_TEMPLATE_ENUMERATING (Silead) or
    // OPLUS_FINGERPRINT_TEMPLATE_SYNC (Egis).
    int error = mDevice->enumerate(mDevice);
    if (error) {
        ALOGE("enumerate failed: %d, reporting the last known templates", error);
        std::vector<int32_t> templates;
        {
            std::lock_guard<std::mutex> lock(mTemplatesLock);
            if (!mEnumeratePending) return ndk::ScopedAStatus::ok();
            mEnumeratePending = false;
            templates = mTemplates;
        }
        mCb->onEnrollmentsEnumerated(templates);
    }

    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::removeEnrollments(const std::vector<int32_t>& enrollmentIds) {
    ALOGI("removeEnrollments, size: %zu", enrollmentIds.size());

    for (int32_t fid : enrollmentIds) {
        int error = mDevice->remove(mDevice, mUserId, fid);
        if (error) {
            ALOGE("remove failed: %d", error);
            mCb->onError(Error::UNABLE_TO_REMOVE, error);
        }
    }
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::getAuthenticatorId() {
    uint64_t auth_id = mDevice->get_authenticator_id(mDevice);
    ALOGI("getAuthenticatorId: %ld", auth_id);
    mCb->onAuthenticatorIdRetrieved(auth_id);
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::invalidateAuthenticatorId() {
    uint64_t auth_id = mDevice->get_authenticator_id(mDevice);
    ALOGI("invalidateAuthenticatorId: %ld", auth_id);
    mCb->onAuthenticatorIdInvalidated(auth_id);
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::resetLockout(const HardwareAuthToken& /*hat*/) {
    clearLockout(true);
    if (mIsLockoutTimerStarted) mIsLockoutTimerAborted = true;

    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::onPointerDown(int32_t /*pointerId*/, int32_t /*x*/, int32_t /*y*/,
                                          float /*minor*/, float /*major*/) {
    // Not used by rear sensors
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::onPointerUp(int32_t /*pointerId*/) {
    // Not used by rear sensors
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::onUiReady() {
    // Not used by rear sensors
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::authenticateWithContext(
        int64_t operationId, const common::OperationContext& /*context*/,
        std::shared_ptr<common::ICancellationSignal>* out) {
    return authenticate(operationId, out);
}

ndk::ScopedAStatus Session::enrollWithContext(const keymaster::HardwareAuthToken& hat,
                                              const common::OperationContext& /*context*/,
                                              std::shared_ptr<common::ICancellationSignal>* out) {
    return enroll(hat, out);
}

ndk::ScopedAStatus Session::detectInteractionWithContext(
        const common::OperationContext& /*context*/,
        std::shared_ptr<common::ICancellationSignal>* out) {
    return detectInteraction(out);
}

ndk::ScopedAStatus Session::onPointerDownWithContext(const PointerContext& context) {
    return onPointerDown(context.pointerId, context.x, context.y, context.minor, context.major);
}

ndk::ScopedAStatus Session::onPointerUpWithContext(const PointerContext& context) {
    return onPointerUp(context.pointerId);
}

ndk::ScopedAStatus Session::onContextChanged(const common::OperationContext& /*context*/) {
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::onPointerCancelWithContext(const PointerContext& /*context*/) {
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::setIgnoreDisplayTouches(bool /*shouldIgnore*/) {
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::cancel() {
    // The vendor HAL reports FINGERPRINT_ERROR_CANCELED by itself.
    int ret = mDevice->cancel(mDevice);
    if (ret) {
        ALOGE("cancel failed: %d", ret);
        return ndk::ScopedAStatus::fromServiceSpecificError(ret);
    }

    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::close() {
    mClosed = true;
    mCb->onSessionClosed();
    AIBinder_DeathRecipient_delete(mDeathRecipient);
    return ndk::ScopedAStatus::ok();
}

binder_status_t Session::linkToDeath(AIBinder* binder) {
    return AIBinder_linkToDeath(binder, mDeathRecipient, this);
}

bool Session::isClosed() {
    return mClosed;
}

// Like the stock Oplus HAL, authenticate through the vendor authenticate_as_type() extension:
// the Silead HAL uses its extended identify there, and the Egis HAL only starts identifying
// from it.
int Session::authenticateAsType(uint64_t operationId) {
    auto authenticateAsType = reinterpret_cast<oplus_authenticate_as_type_t>(mDevice->reserved[0]);
    if (authenticateAsType == nullptr) {
        return mDevice->authenticate(mDevice, operationId, mUserId);
    }
    return authenticateAsType(mDevice, operationId, mUserId, OPLUS_FINGERPRINT_AUTH_TYPE_OTHER);
}

// Translate errno style errors returned by the vendor HAL calls to AIDL-compliant Error
Error Session::HalErrorFilter(int error) {
    return error == -ENODEV ? Error::HW_UNAVAILABLE : Error::UNABLE_TO_PROCESS;
}

// Translate from errors returned by traditional HAL (see fingerprint.h) to
// AIDL-compliant Error
Error Session::VendorErrorFilter(int32_t error, int32_t* vendorCode) {
    *vendorCode = 0;

    switch (error) {
        case FINGERPRINT_ERROR_HW_UNAVAILABLE:
            return Error::HW_UNAVAILABLE;
        case FINGERPRINT_ERROR_UNABLE_TO_PROCESS:
            return Error::UNABLE_TO_PROCESS;
        case FINGERPRINT_ERROR_TIMEOUT:
            return Error::TIMEOUT;
        case FINGERPRINT_ERROR_NO_SPACE:
            return Error::NO_SPACE;
        case FINGERPRINT_ERROR_CANCELED:
            return Error::CANCELED;
        case FINGERPRINT_ERROR_UNABLE_TO_REMOVE:
            return Error::UNABLE_TO_REMOVE;
        case FINGERPRINT_ERROR_LOCKOUT: {
            *vendorCode = FINGERPRINT_ERROR_LOCKOUT;
            return Error::VENDOR;
        }
    }
    ALOGE("Unknown error from fingerprint vendor library: %d", error);
    return Error::UNABLE_TO_PROCESS;
}

// Translate acquired messages returned by traditional HAL (see fingerprint.h)
// to AIDL-compliant AcquiredInfo
AcquiredInfo Session::VendorAcquiredFilter(int32_t info, int32_t* vendorCode) {
    *vendorCode = 0;

    switch (info) {
        case FINGERPRINT_ACQUIRED_GOOD:
            return AcquiredInfo::GOOD;
        case FINGERPRINT_ACQUIRED_PARTIAL:
            return AcquiredInfo::PARTIAL;
        case FINGERPRINT_ACQUIRED_INSUFFICIENT:
            return AcquiredInfo::INSUFFICIENT;
        case FINGERPRINT_ACQUIRED_IMAGER_DIRTY:
            return AcquiredInfo::SENSOR_DIRTY;
        case FINGERPRINT_ACQUIRED_TOO_SLOW:
            return AcquiredInfo::TOO_SLOW;
        case FINGERPRINT_ACQUIRED_TOO_FAST:
            return AcquiredInfo::TOO_FAST;
        default:
            if (info >= FINGERPRINT_ACQUIRED_VENDOR_BASE) {
                // vendor specific code.
                *vendorCode = info - FINGERPRINT_ACQUIRED_VENDOR_BASE;
                return AcquiredInfo::VENDOR;
            }
    }
    ALOGE("Unknown acquired message from fingerprint vendor library: %d", info);
    return AcquiredInfo::UNKNOWN;
}

bool Session::checkSensorLockout() {
    LockoutTracker::LockoutMode lockoutMode = mLockoutTracker.getMode();
    if (lockoutMode == LockoutTracker::LockoutMode::kPermanent) {
        ALOGE("Fail: lockout permanent");
        mCb->onLockoutPermanent();
        mIsLockoutTimerAborted = true;
        return true;
    }
    if (lockoutMode == LockoutTracker::LockoutMode::kTimed) {
        int64_t timeLeft = mLockoutTracker.getLockoutTimeLeft();
        ALOGE("Fail: lockout timed: %ld", timeLeft);
        mCb->onLockoutTimed(timeLeft);
        if (!mIsLockoutTimerStarted) startLockoutTimer(timeLeft);
        return true;
    }
    return false;
}

void Session::clearLockout(bool clearAttemptCounter) {
    mLockoutTracker.reset(clearAttemptCounter);
    mCb->onLockoutCleared();
}

void Session::startLockoutTimer(int64_t timeout) {
    std::function<void()> action = std::bind(&Session::lockoutTimerExpired, this);
    std::thread([timeout, action]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(timeout));
        action();
    }).detach();

    mIsLockoutTimerStarted = true;
}

void Session::lockoutTimerExpired() {
    if (!mIsLockoutTimerAborted) clearLockout(false);

    mIsLockoutTimerStarted = false;
    mIsLockoutTimerAborted = false;
}

void Session::onTemplatesSynced(const fingerprint_msg_t* msg) {
    auto* sync = reinterpret_cast<const oplus_fingerprint_sync_t*>(&msg->data);
    uint32_t count = std::min<uint32_t>(sync->count, OPLUS_FINGERPRINT_MAX_TEMPLATES);
    ALOGD("onSyncTemplates(gid=%d, count=%d)", sync->gid, count);

    std::vector<int32_t> templates;
    for (uint32_t i = 0; i < count; i++) {
        templates.push_back(sync->fingers[i].fid);
    }
    onTemplatesReported(templates);
}

void Session::onTemplatesReported(const std::vector<int32_t>& templates) {
    bool enumeratePending;
    {
        std::lock_guard<std::mutex> lock(mTemplatesLock);
        mTemplates = templates;
        enumeratePending = mEnumeratePending;
        mEnumeratePending = false;
    }

    if (enumeratePending) {
        mCb->onEnrollmentsEnumerated(templates);
    }
}

void Session::notify(const fingerprint_msg_t* msg) {
    switch (static_cast<int>(msg->type)) {
        case FINGERPRINT_ERROR: {
            if (msg->data.error >= FINGERPRINT_ERROR_VENDOR_BASE) {
                // Dropped by the stock HAL as well.
                ALOGD("Ignoring vendor error %d", msg->data.error);
                break;
            }
            int32_t vendorCode = 0;
            Error result = VendorErrorFilter(msg->data.error, &vendorCode);
            ALOGD("onError(%hhd, %d)", result, vendorCode);
            mCb->onError(result, vendorCode);
        } break;
        case FINGERPRINT_ACQUIRED: {
            int32_t vendorCode = 0;
            AcquiredInfo result =
                    VendorAcquiredFilter(msg->data.acquired.acquired_info, &vendorCode);
            ALOGD("onAcquired(%hhd, %d)", result, vendorCode);
            mCb->onAcquired(result, vendorCode);
        } break;
        case FINGERPRINT_TEMPLATE_ENROLLING: {
            ALOGD("onEnrollResult(fid=%d, gid=%d, rem=%d)", msg->data.enroll.finger.fid,
                  msg->data.enroll.finger.gid, msg->data.enroll.samples_remaining);
            mCb->onEnrollmentProgress(msg->data.enroll.finger.fid,
                                      msg->data.enroll.samples_remaining);
        } break;
        case FINGERPRINT_TEMPLATE_REMOVED: {
            ALOGD("onRemove(fid=%d, gid=%d, rem=%d)", msg->data.removed.finger.fid,
                  msg->data.removed.finger.gid, msg->data.removed.remaining_templates);
            // Silead terminates a removal with fid 0.
            if (msg->data.removed.finger.fid == 0) break;
            std::vector<int> enrollments;
            enrollments.push_back(msg->data.removed.finger.fid);
            mCb->onEnrollmentsRemoved(enrollments);
        } break;
        case FINGERPRINT_AUTHENTICATED: {
            ALOGD("onAuthenticated(fid=%d, gid=%d)", msg->data.authenticated.finger.fid,
                  msg->data.authenticated.finger.gid);
            if (msg->data.authenticated.finger.fid != 0) {
                const hw_auth_token_t hat = msg->data.authenticated.hat;
                HardwareAuthToken authToken;
                translate(hat, authToken);

                mCb->onAuthenticationSucceeded(msg->data.authenticated.finger.fid, authToken);
                mLockoutTracker.reset(true);
            } else {
                mCb->onAuthenticationFailed();
                mLockoutTracker.addFailedAttempt();
                checkSensorLockout();
            }
        } break;
        case FINGERPRINT_TEMPLATE_ENUMERATING: {
            ALOGD("onEnumerate(fid=%d, gid=%d, rem=%d)", msg->data.enumerated.finger.fid,
                  msg->data.enumerated.finger.gid, msg->data.enumerated.remaining_templates);
            // An empty list is reported as a single fid 0.
            if (msg->data.enumerated.finger.fid != 0) {
                mEnumerated.push_back(msg->data.enumerated.finger.fid);
            }
            if (msg->data.enumerated.remaining_templates == 0) {
                onTemplatesReported(mEnumerated);
                mEnumerated.clear();
            }
        } break;
        case OPLUS_FINGERPRINT_TOUCH_DOWN: {
            ALOGD("onTouchDown()");
            mCb->onAcquired(AcquiredInfo::VENDOR, 0 /* vendorCode */);
        } break;
        case OPLUS_FINGERPRINT_TOUCH_UP: {
            ALOGD("onTouchUp()");
            mCb->onAcquired(AcquiredInfo::VENDOR, 1 /* vendorCode */);
        } break;
        case OPLUS_FINGERPRINT_TEMPLATE_SYNC: {
            onTemplatesSynced(msg);
        } break;
        default:
            // Image quality, DCS and engineering mode reports are only used by the Oplus framework.
            ALOGV("Ignoring message type %d", msg->type);
            break;
    }
}

}  // namespace aidl::android::hardware::biometrics::fingerprint
