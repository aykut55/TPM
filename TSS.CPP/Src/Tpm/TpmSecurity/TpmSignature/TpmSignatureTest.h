#pragma once

#include "TpmSignature.h"
#include <memory>
#include <vector>

class CTpmSignatureTest
{
private:
    CTpmSignature* m_signature;

public:
    void SetTpmSignature(CTpmSignature* pSignature);
    bool RunAllTests();

    bool TestMesajSign(const std::string& rawMessage);
    bool TestMesajVerify(const std::string& hexEncodedData, const std::vector<BYTE>& signature);
    bool TestHmacSignOnly();
};
