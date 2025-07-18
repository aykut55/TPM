#include "TpmSignatureHMAC.h"

#include <string>       // std::string
#include <iostream>     // std::cout
#include <sstream>      // std::stringstream

CTpmSignatureHMAC::~CTpmSignatureHMAC()
{
    if (m_keyGenerated && m_keyHandle != TPM_RH_NULL)
    {
        try {
            tpm->FlushContext(m_keyHandle);
        }
        catch (...) {
            std::cerr << "[CTpmSignatureHMAC] FlushContext failed.\n";
        }
    }
}

CTpmSignatureHMAC::CTpmSignatureHMAC(CTpmSharedDevice* sharedDevice)
    : CTpmSignature(sharedDevice), m_keyHandle(TPM_RH_NULL), m_hashAlg(TPM_ALG_ID::SHA256), m_keyGenerated(false)
{

}

bool CTpmSignatureHMAC::GenerateKeyPair()
{
    try
    {
        // 1. HMAC key olarak kullanılacak sabit veri (örnek)
        ByteVec hmacKey = { 5, 4, 3, 2, 1, 0 };  // Bu key sabit. Dilersen constructor’dan verilebilir hale getirebiliriz.

        // 2. HMAC key için public template
        TPMT_PUBLIC publicTemplate(
            TPM_ALG_ID::SHA256, // NameAlg
            TPMA_OBJECT::sign | TPMA_OBJECT::fixedParent | TPMA_OBJECT::fixedTPM | TPMA_OBJECT::userWithAuth,
            TPM2B_DIGEST(), // No auth policy
            TPMS_KEYEDHASH_PARMS(
                TPMS_SCHEME_HMAC(m_hashAlg)  // m_hashAlg: SHA1, SHA256 vs.
            ),
            TPM2B_DIGEST_KEYEDHASH()
        );

        // 3. SensitiveCreate ile dışarıdan key ver
        TPMS_SENSITIVE_CREATE sensCreate(TPM2B_AUTH(), hmacKey); // boş auth + key

        // 4. TPM’de HMAC key oluştur
        auto primary = tpm->CreatePrimary(
            TPM_RH::OWNER,
            sensCreate,
            publicTemplate,
            ByteVec(),  // outsideInfo
            std::vector<TPMS_PCR_SELECTION>()  // creationPCR boş
        );

        // 5. Handle sakla ve flag set et
        m_keyHandle = primary.handle;
        m_keyGenerated = true;

        return true;
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[CTpmSignatureHMAC] GenerateKeyPair exception: " << ex.what() << "\n";
        return false;
    }
}

bool CTpmSignatureHMAC::GenerateKeyPairEx(
    const std::vector<BYTE>& keyBytes,
    TPM_ALG_ID hashAlg,
    const std::vector<BYTE>& authValue
)
{
    try
    {
        if (!tpm)
        {
            std::cerr << "[CTpmSignatureHMAC] TPM device not initialized.\n";
            return false;
        }

        // PUBLIC alan: HMAC için anahtar özellikleri
        TPMT_PUBLIC pubTemplate(
            TPM_ALG_ID::SHA256,  // NameAlg (objeyi tanımlayan hash alg)
            TPMA_OBJECT::sign | TPMA_OBJECT::fixedParent |
            TPMA_OBJECT::fixedTPM | TPMA_OBJECT::userWithAuth,
            {}, // authPolicy boş
            TPMS_KEYEDHASH_PARMS(TPMS_SCHEME_HMAC(hashAlg)),
            TPM2B_DIGEST_KEYEDHASH()
        );

        // SENSITIVE alan: TPM içine verilecek kullanıcı anahtarı
        TPMS_SENSITIVE_CREATE sensCreate(
            TPM2B_AUTH(authValue),   // Kullanıcı auth (opsiyonel)
            keyBytes                 // HMAC key material
        );

        // TPM üzerinde Primary HMAC Key oluştur
        auto primary = tpm->CreatePrimary(
            TPM_RH::OWNER,
            sensCreate,
            pubTemplate,
            {},     // outsideInfo boş
            {}      // PCR boş
        );

        m_keyHandle = primary.handle;
        m_hashAlg = hashAlg;
        m_keyGenerated = true;

        return true;
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[CTpmSignatureHMAC] GenerateKeyPairEx exception: " << ex.what() << "\n";
        return false;
    }
}

bool CTpmSignatureHMAC::SignData(const std::vector<BYTE>& data, std::vector<BYTE>& signatureOut)
{
    if (!m_keyGenerated)
    {
        std::cerr << "[CTpmSignatureHMAC] Key not generated.\n";
        return false;
    }

    try
    {
        // TPM ile HMAC üret
        signatureOut = tpm->HMAC(m_keyHandle, data, m_hashAlg);
        return true;
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[CTpmSignatureHMAC] SignData exception: " << ex.what() << "\n";
        return false;
    }
}

bool CTpmSignatureHMAC::VerifySignature(const std::vector<BYTE>& data, const std::vector<BYTE>& signature)
{
    try
    {
        // Aynı algoritmayı kullanarak yeni HMAC üret
        std::vector<BYTE> computedSignature;
        if (!SignData(data, computedSignature))
        {
            std::cerr << "[CTpmSignatureHMAC] Failed to compute signature for verification.\n";
            return false;
        }

        // Byte-by-byte karşılaştırma
        return computedSignature == signature;
    }
    catch (...)
    {
        std::cerr << "[CTpmSignatureHMAC] Exception during verification.\n";
        return false;
    }
}

bool CTpmSignatureHMAC::SignHashedData(const std::vector<BYTE>& digest, std::vector<BYTE>& signatureOut)
{
    if (!m_keyGenerated)
    {
        std::cerr << "[CTpmSignatureHMAC] Key not generated.\n";
        return false;
    }

    try
    {
        // HMAC imzasını üret (Sign komutu digest üzerinden yapılabilir)
        auto sig = tpm->Sign(m_keyHandle, digest, TPMS_NULL_SIG_SCHEME(), TPMT_TK_HASHCHECK());

        // Sonuç TPM_HASH ya da benzeri olmalı
        TPM_HASH* hmacSig = dynamic_cast<TPM_HASH*>(&*sig);
        if (!hmacSig)
        {
            std::cerr << "[CTpmSignatureHMAC] Invalid signature type.\n";
            return false;
        }

        signatureOut = hmacSig->digest;
        return true;
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[CTpmSignatureHMAC] SignHashedData exception: " << ex.what() << "\n";
        return false;
    }
}

bool CTpmSignatureHMAC::VerifyHashedData(const std::vector<BYTE>& digest, const std::vector<BYTE>& signature)
{
    if (!m_keyGenerated)
    {
        std::cerr << "[CTpmSignatureHMAC] Key not generated.\n";
        return false;
    }

    try
    {
        // TPM ile HMAC oluştur
        auto sig = tpm->Sign(m_keyHandle, digest, TPMS_NULL_SIG_SCHEME(), TPMT_TK_HASHCHECK());

        TPM_HASH* hmacSig = dynamic_cast<TPM_HASH*>(&*sig);
        if (!hmacSig)
        {
            std::cerr << "[CTpmSignatureHMAC] Invalid signature type.\n";
            return false;
        }

        // Karşılaştır
        if (hmacSig->digest == signature)
            return true;

        std::cerr << "[CTpmSignatureHMAC] Signature mismatch.\n";
        return false;
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[CTpmSignatureHMAC] VerifyHashedData exception: " << ex.what() << "\n";
        return false;
    }
}
