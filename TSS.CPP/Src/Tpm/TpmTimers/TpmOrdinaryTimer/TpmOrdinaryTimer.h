#pragma once

#include "TpmBaseClass.h"
#include "TpmSharedDevice.h"

using namespace TpmCpp;

namespace TpmOrdinaryTimerNS
{
    constexpr UINT32 ORDINARY_COUNTER_NV_INDEX = 0x01500020;
    // Min 0x01000000 
    //     0x01500020 <---
    // Max 0x01FFFFFF
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
    bool              OrdinaryDefineWatchdogCounter(UINT32 nvIndex);
    bool              OrdinaryUndefineWatchdogCounter(UINT32 nvIndex);
    bool              InitWatchdogCounter(UINT32 nvIndex);
    bool              ResetWatchdogCounter(UINT32 nvIndex);
    bool              ReadWatchdogCounter(UINT32 nvIndex, UINT64& value);
    bool              WriteWatchdogCounter(UINT32 nvIndex, UINT64& value);
    bool              OrdinaryDefineWatchdogCounter(void);
    bool              OrdinaryUndefineWatchdogCounter(void);
    bool              InitWatchdogCounter(void);
    bool              ResetWatchdogCounter(void);
    bool              ReadWatchdogCounter(UINT64& value);
    bool              WriteWatchdogCounter(UINT64& value);

protected:

private:
    bool m_useSharedTpmDevice;
    CTpmSharedDevice* m_sharedTpmDevice;

    UINT64 m_watchdogCounter = 0;

    std::thread m_watchdogThread;
    std::atomic<bool> m_watchdogRunning{ false };
};