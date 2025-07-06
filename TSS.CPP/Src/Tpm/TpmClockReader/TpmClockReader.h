#pragma once

#include "TpmBaseClass.h"
#include "TpmSharedDevice.h"

class CTpmClockReader : public CTpmBaseClass
{
public:
    virtual ~CTpmClockReader();
             CTpmClockReader(CTpmSharedDevice* sharedDevice = nullptr);

    CTpmSharedDevice* GetTpmSharedDevice(void);
    bool              Release(void);
    bool              Initialize(void);
    bool              ReadClock(void);
    uint64_t          GetClockTime(void);
    std::string       GetClockTimeAsString(void);
    bool              ResetClock(bool fullFactoryReset = false);

protected:
    std::string FormatClockAsDuration(uint64_t ms);

private:
    bool m_useSharedTpmDevice;
    CTpmSharedDevice* m_sharedTpmDevice;
    TPMS_TIME_INFO clockInfo;
};