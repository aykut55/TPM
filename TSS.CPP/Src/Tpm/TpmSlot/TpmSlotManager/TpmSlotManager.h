#pragma once

#include "TpmBaseClass.h"
#include "TpmSharedDevice.h"

class CTpmSlotManager : public CTpmBaseClass
{
public:
    virtual ~CTpmSlotManager();
             CTpmSlotManager(CTpmSharedDevice* sharedDevice = nullptr);

    CTpmSharedDevice* GetTpmSharedDevice(void);
    bool              Release(void);
    bool              Initialize(void);

protected:

private:
    bool m_useSharedTpmDevice;
    CTpmSharedDevice* m_sharedTpmDevice;
};