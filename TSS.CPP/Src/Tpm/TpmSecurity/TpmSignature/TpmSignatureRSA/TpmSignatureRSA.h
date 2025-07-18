#pragma once

#include "TpmSignature.h"

using namespace TpmCpp;

namespace TpmSignatureRSANS
{

}

class CTpmSignatureRSA : public CTpmSignature
{
public:
    virtual ~CTpmSignatureRSA();
             CTpmSignatureRSA(CTpmSharedDevice* sharedDevice = nullptr);

    // Anahtar çifti üret
    bool GenerateKeyPair() override;

    bool GenerateKeyPairEx(
        UINT16 keyBits,
        TPM_ALG_ID hashAlg,
        UINT32 publicExponent = 0,
        const std::vector<BYTE>& authValue = {}
    ) override;

    // Veriyi imzala
    bool SignData(const std::vector<BYTE>& data, std::vector<BYTE>& signatureOut) override;

    // İmzayı doğrula
    bool VerifySignature(const std::vector<BYTE>& data, const std::vector<BYTE>& signature) override;

    bool SignHashedData(const std::vector<BYTE>& digest, std::vector<BYTE>& signatureOut) override;

    bool VerifyHashedData(const std::vector<BYTE>& digest, const std::vector<BYTE>& signature) override;

    bool ExportPublicKeyRaw(std::vector<BYTE>& modulusOut, UINT32& exponentOut) override;

    bool ConvertRsaPublicKeyToPem(const std::vector<BYTE>& modulus, UINT32 exponent, std::string& pemOut) override;
    bool ParseRsaPublicKeyFromPem(const std::string& pem, std::vector<BYTE>& modulusOut, UINT32& exponentOut) override;
    bool VerifySignatureWithRawPublicKey(
        const std::vector<BYTE>& data,
        const std::vector<BYTE>& signature,
        const std::vector<BYTE>& modulus,
        UINT32 exponent)override;

protected:


private:
    TPM_HANDLE m_keyHandle;        // TPM üzerinde oluşturulan RSA anahtarın handle'ı
    TPM_ALG_ID m_hashAlg;          // Hash algoritması (örnek: SHA256)

    bool m_keyGenerated;           // Anahtar oluşturulmuş mu

    TPMT_PUBLIC m_publicArea;  // <--- bunu sınıfa ekle
};