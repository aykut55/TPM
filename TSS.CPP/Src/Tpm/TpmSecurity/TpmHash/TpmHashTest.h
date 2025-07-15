#pragma once
#include "TpmHash.h"

class CTpmHashTest
{
public:
    // Dışarıdan TPM hash objesi enjekte edilir
    void SetTpmHash(CTpmHash* hashObj);

    // Temel testler
    bool RunAllTests();
    bool TestHashString();
    bool TestHashData();
    bool TestHashFile(const std::string& filePath);

private:
    CTpmHash* m_hash = nullptr;
};
