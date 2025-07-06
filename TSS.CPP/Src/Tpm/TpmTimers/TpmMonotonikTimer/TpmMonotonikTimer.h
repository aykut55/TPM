#pragma once

#include "TpmBaseClass.h"
#include "TpmSharedDevice.h"

class CTpmMonotonikTimer : public CTpmBaseClass
{
public:
    virtual ~CTpmMonotonikTimer();
             CTpmMonotonikTimer(CTpmSharedDevice* sharedDevice = nullptr);

    CTpmSharedDevice* GetTpmSharedDevice(void);
    bool              Release(void);
    bool              Initialize(void);

protected:

private:
    bool m_useSharedTpmDevice;
    CTpmSharedDevice* m_sharedTpmDevice;
};