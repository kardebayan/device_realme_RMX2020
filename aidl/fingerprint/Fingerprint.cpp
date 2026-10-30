/*
 * Copyright (C) 2024 The LineageOS Project
 *               2024 Paranoid Android
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "Fingerprint.h"
#include "EgisFingerprint.h"

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/strings.h>

namespace aidl::android::hardware::biometrics::fingerprint {

namespace {
constexpr int SENSOR_ID = 0;
constexpr common::SensorStrength SENSOR_STRENGTH = common::SensorStrength::STRONG;
constexpr int MAX_ENROLLMENTS_PER_USER = 5;
constexpr char HW_COMPONENT_ID[] = "fingerprintSensor";
constexpr char SW_COMPONENT_ID[] = "matchingAlgorithm";

// The kernel exposes the probed sensor (chip-name in the device tree) here.
constexpr char FP_ID_PATH[] = "/proc/fp_id";
constexpr char FP_ID_EGIS_ET520[] = "E_520";
constexpr char FP_ID_SILEAD_GSL6150[] = "S_gsl6150";

constexpr char SILEAD_MODULE_ID[] = "fingerprint.silead";
}  // namespace

static const uint16_t kVersion = HARDWARE_MODULE_API_VERSION(2, 1);
static Fingerprint* sInstance;

Fingerprint::Fingerprint() : mDevice(openHal()) {
    sInstance = this;  // keep track of the most recent instance
}

Fingerprint::~Fingerprint() {
    ALOGV("~Fingerprint()");
    if (mDevice == nullptr) {
        ALOGE("No valid device");
        return;
    }
    int err;
    if (0 != (err = mDevice->common.close(reinterpret_cast<hw_device_t*>(mDevice)))) {
        ALOGE("Can't close fingerprint module, error: %d", err);
        return;
    }
    mDevice = nullptr;
}

static fingerprint_device_t* openSileadHal() {
    int err;
    const hw_module_t* hw_mdl = nullptr;
    ALOGD("Opening silead fingerprint hal library...");
    if (0 != (err = hw_get_module(SILEAD_MODULE_ID, &hw_mdl))) {
        ALOGE("Can't open fingerprint HW Module, error: %d", err);
        return nullptr;
    }

    if (hw_mdl == nullptr) {
        ALOGE("No valid fingerprint module");
        return nullptr;
    }

    fingerprint_module_t const* module = reinterpret_cast<const fingerprint_module_t*>(hw_mdl);
    if (module->common.methods->open == nullptr) {
        ALOGE("No valid open method");
        return nullptr;
    }

    hw_device_t* device = nullptr;

    if (0 != (err = module->common.methods->open(hw_mdl, nullptr, &device))) {
        ALOGE("Can't open fingerprint methods, error: %d", err);
        return nullptr;
    }

    if (kVersion != device->version) {
        ALOGE("Wrong fp version. Expected %d, got %d", kVersion, device->version);
        return nullptr;
    }

    return reinterpret_cast<fingerprint_device_t*>(device);
}

fingerprint_device_t* Fingerprint::openHal() {
    std::string fpId;
    if (!::android::base::ReadFileToString(FP_ID_PATH, &fpId)) {
        ALOGE("Can't read %s", FP_ID_PATH);
        return nullptr;
    }
    mSensorId = ::android::base::Trim(fpId);
    ALOGI("Fingerprint sensor: %s", mSensorId.c_str());

    fingerprint_device_t* fp_device;
    if (mSensorId == FP_ID_SILEAD_GSL6150) {
        fp_device = openSileadHal();
    } else if (mSensorId == FP_ID_EGIS_ET520) {
        fp_device = egis::open();
    } else {
        ALOGE("Unsupported fingerprint sensor: %s", mSensorId.c_str());
        return nullptr;
    }

    if (fp_device == nullptr) {
        return nullptr;
    }

    int err;
    if (0 != (err = fp_device->set_notify(fp_device, Fingerprint::notify))) {
        ALOGE("Can't register fingerprint module callback, error: %d", err);
        return nullptr;
    }

    return fp_device;
}

void Fingerprint::notify(const fingerprint_msg_t* msg) {
    Fingerprint* thisPtr = sInstance;
    if (thisPtr == nullptr || thisPtr->mSession == nullptr || thisPtr->mSession->isClosed()) {
        ALOGE("Receiving callbacks before a session is opened.");
        return;
    }
    thisPtr->mSession->notify(msg);
}

ndk::ScopedAStatus Fingerprint::getSensorProps(std::vector<SensorProps>* out) {
    std::vector<common::ComponentInfo> componentInfo = {
            {HW_COMPONENT_ID, mSensorId /* hardwareVersion */, "" /* firmwareVersion */,
             "" /* serialNumber */, "" /* softwareVersion */},
            {SW_COMPONENT_ID, "" /* hardwareVersion */, "" /* firmwareVersion */,
             "" /* serialNumber */, mSensorId /* softwareVersion */}};

    common::CommonProps commonProps = {SENSOR_ID, SENSOR_STRENGTH, MAX_ENROLLMENTS_PER_USER,
                                       componentInfo};

    // Capacitive sensor on the back panel.
    *out = {{commonProps, FingerprintSensorType::REAR, {} /* sensorLocations */,
             false /* supportsNavigationGestures */, false /* supportsDetectInteraction */,
             false /* halHandlesDisplayTouches */, false /* halControlsIllumination */,
             std::nullopt /* touchDetectionParameters */}};
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Fingerprint::createSession(int32_t /*sensorId*/, int32_t userId,
                                              const std::shared_ptr<ISessionCallback>& cb,
                                              std::shared_ptr<ISession>* out) {
    CHECK(mSession == nullptr || mSession->isClosed()) << "Open session already exists!";

    mSession = SharedRefBase::make<Session>(mDevice, userId, cb, mLockoutTracker);
    *out = mSession;

    mSession->linkToDeath(cb->asBinder().get());

    return ndk::ScopedAStatus::ok();
}

}  // namespace aidl::android::hardware::biometrics::fingerprint
