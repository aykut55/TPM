#pragma once

#include "TpmBaseClass.h"
#include "TpmSharedDevice.h"

using namespace TpmCpp;

namespace TpmOrdinaryTimerNS
{
    // Bunlar ordinary counter'e ait
    constexpr UINT32 ORDINARY_COUNTER_NV_INDEX = 0x01500020;
}

class CTpmOrdinaryTimer : public CTpmBaseClass
{
public:
    virtual ~CTpmOrdinaryTimer();
             CTpmOrdinaryTimer(CTpmSharedDevice* sharedDevice = nullptr);

    CTpmSharedDevice* GetTpmSharedDevice(void);
    bool              Release(void);
    bool              Initialize(void);
    bool              StartWatchdog(int intervalSeconds = 10);
    bool              StopWatchdog(void);
    bool              OrdinaryDefineWatchdogCounter(void);
    bool              OrdinaryUndefineWatchdogCounter(void);
    bool              InitWatchdogCounter(void);
    bool              ResetWatchdogCounter(void);

protected:

private:
    bool m_useSharedTpmDevice;
    CTpmSharedDevice* m_sharedTpmDevice;

    UINT64 m_ordinaryWatchdogCounter = 0;

    std::thread m_watchdogThread;
    std::atomic<bool> m_watchdogRunning{ false };
};