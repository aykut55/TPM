#pragma once

#include "TpmBaseClass.h"
#include "TpmSharedDevice.h"

using namespace TpmCpp;

namespace TpmMonotonicTimerNS
{
    constexpr UINT32 MONOTONIC_COUNTER_NV_INDEX = 0x01500010;
}

class CTpmMonotonicTimer : public CTpmBaseClass
{
public:
    virtual ~CTpmMonotonicTimer();
             CTpmMonotonicTimer(CTpmSharedDevice* sharedDevice = nullptr);

    CTpmSharedDevice* GetTpmSharedDevice(void);
    bool              Release(void);
    bool              Initialize(void);
    bool              StartWatchdog(int intervalSeconds = 10);
    bool              StopWatchdog(void);
    bool              NVDefineWatchdogCounter(void);
    bool              NVUndefineWatchdogCounter(bool fullFactoryReset = false);
    bool              InitWatchdogCounter(void);
    bool              ResetWatchdogCounter(void);
    bool              ReadWatchdogCounter(UINT64& value);
    bool              IncrementWatchdogCounter(UINT64& value);

protected:

private:
    bool m_useSharedTpmDevice;
    CTpmSharedDevice* m_sharedTpmDevice;

    UINT64 m_watchdogCounter = 0;

    std::thread m_watchdogThread;
    std::atomic<bool> m_watchdogRunning{ false };
};