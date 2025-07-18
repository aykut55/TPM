#pragma once

#include "TpmBaseClass.h"
#include "TpmSharedDevice.h"

#define USE_OPENSSL_LIBS    0

#if USE_OPENSSL_LIBS
    #include <openssl/rsa.h>
    #include <openssl/pem.h>
    #include <openssl/bn.h>
#endif

//#include "TpmSlotDefinitions.h"

using namespace TpmCpp;

namespace TpmSignatureNS
{
    //constexpr UINT32 BASE_SLOT_INDEX = 0x01510000;
    //constexpr UINT32 SLOT_COUNT = 8;
    //constexpr UINT32 SLOT_SIZE = 1024; // 1KB
}

class CTpmSignature : public CTpmBaseClass
{
public:
    virtual ~CTpmSignature();
             CTpmSignature(CTpmSharedDevice* sharedDevice = nullptr);

    CTpmSharedDevice*        GetTpmSharedDevice(void);
    bool                     Release(void);
    bool                     Initialize(void);

    // İmzalama işlemi
    virtual bool SignData(const std::vector<BYTE>& data, std::vector<BYTE>& signatureOut) = 0;

    // Doğrulama işlemi
    virtual bool VerifySignature(const std::vector<BYTE>& data, const std::vector<BYTE>& signature) = 0;

    // Yeni eklenen sanal fonksiyonlar:
    virtual bool SignHashedData(const std::vector<BYTE>& digest, std::vector<BYTE>& signatureOut) = 0;

    virtual bool VerifyHashedData(const std::vector<BYTE>& digest, const std::vector<BYTE>& signature) = 0;

    // Anahtar üretimi
    virtual bool GenerateKeyPair() = 0;

    virtual bool GenerateKeyPairEx(
        UINT16 keyBits,
        TPM_ALG_ID hashAlg,
        UINT32 publicExponent = 0,
        const std::vector<BYTE>& authValue = {}
    ) 
    {
        return false;
    }

    virtual bool GenerateKeyPairEx(
        const std::vector<BYTE>& keyBytes,
        TPM_ALG_ID hashAlg,
        const std::vector<BYTE>& authValue
    )
    {
        return false;
    }

    virtual bool ExportPublicKeyRaw(std::vector<BYTE>& modulusOut, UINT32& exponentOut)
    {
        return false;
    }

    virtual bool ConvertRsaPublicKeyToPem(const std::vector<BYTE>& modulus, UINT32 exponent, std::string& pemOut)
    {
        return false;
    }

    virtual bool ParseRsaPublicKeyFromPem(const std::string& pem, std::vector<BYTE>& modulusOut, UINT32& exponentOut)
    {
        return false;
    }

    virtual bool VerifySignatureWithRawPublicKey(
        const std::vector<BYTE>& data,
        const std::vector<BYTE>& signature,
        const std::vector<BYTE>& modulus,
        UINT32 exponent)
    {
        return false;
    }
/*
    virtual bool            Sign(const std::vector<BYTE>& data, std::vector<BYTE>& signature) = 0;
    virtual bool            Verify(const std::vector<BYTE>& data, const std::vector<BYTE>& signature) = 0;
    void                    SetKeyHandle(const TPM_HANDLE& keyHandle) { m_keyHandle = keyHandle; }
    void                    SetHashAlg(TPM_ALG_ID alg) { m_hashAlg = alg; }
*/
    // Base64 encode/decode
    static std::string EncodeBase64(const std::vector<BYTE>& data);
    static std::vector<BYTE> DecodeBase64(const std::string& encoded);

    // Hex encode/decode
    static std::string EncodeHex(const std::vector<BYTE>& data, bool upperCase = false);
    static std::vector<BYTE> DecodeHex(const std::string& hexStr);


protected:
    //TPM_HANDLE m_keyHandle;
    //TPM_ALG_ID m_hashAlg = TPM_ALG_ID::SHA256;  // default hash alg
    //std::string m_lastError;

private:
    bool m_useSharedTpmDevice;
    CTpmSharedDevice* m_sharedTpmDevice;
};