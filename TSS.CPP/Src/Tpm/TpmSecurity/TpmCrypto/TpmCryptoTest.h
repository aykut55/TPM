#pragma once

#include "TpmCryptoRSA.h"
#include <memory>
#include <vector>

class CTpmCryptoTest
{
private:
    CTpmCryptoRSA* m_pTpmCrypto;

public:
    void SetTpmCrypto(CTpmCryptoRSA* pTpmCrypto);
    bool RunAllTests();

    bool TestSimpleTypes();
    bool TestArrayTypes();
    bool TestStringOperations();
    bool TestFileOperations();

    bool TestEncryptDecryptInternal();

};
