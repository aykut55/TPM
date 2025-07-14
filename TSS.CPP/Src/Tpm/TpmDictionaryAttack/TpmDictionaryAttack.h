#pragma once

#include "TpmBaseClass.h"
#include "TpmSharedDevice.h"

class CTpmDictionaryAttack : public CTpmBaseClass
{
public:
    virtual ~CTpmDictionaryAttack();
             CTpmDictionaryAttack(CTpmSharedDevice* sharedDevice = nullptr);

    CTpmSharedDevice* GetTpmSharedDevice(void);
    bool              Release(void);
    bool              Initialize(void);

protected:

private:
    bool m_useSharedTpmDevice;
    CTpmSharedDevice* m_sharedTpmDevice;
};