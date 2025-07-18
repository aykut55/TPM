#pragma once

#include "TpmSignature.h"

using namespace TpmCpp;

namespace TpmSignatureHMACNS
{

}

class CTpmSignatureHMAC : public CTpmSignature
{
public:
    virtual ~CTpmSignatureHMAC();
             CTpmSignatureHMAC(CTpmSharedDevice* sharedDevice = nullptr);

    virtual bool GenerateKeyPair() override; 
    bool GenerateKeyPairEx(
        const std::vector<BYTE>& keyBytes,
        TPM_ALG_ID hashAlg,
        const std::vector<BYTE>& authValue = {}
    );

    virtual bool SignData(const std::vector<BYTE>& data, std::vector<BYTE>& signatureOut) override;
    virtual bool VerifySignature(const std::vector<BYTE>& data, const std::vector<BYTE>& signature) override;

    bool SignHashedData(const std::vector<BYTE>& digest, std::vector<BYTE>& signatureOut) override;
    bool VerifyHashedData(const std::vector<BYTE>& digest, const std::vector<BYTE>& signature) override;

protected:

private:
    TPM_HANDLE m_keyHandle;        // TPM üzerinde oluşturulan RSA anahtarın handle'ı
    TPM_ALG_ID m_hashAlg;          // Hash algoritması (örnek: SHA256)

    bool m_keyGenerated;           // Anahtar oluşturulmuş mu
};