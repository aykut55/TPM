#include "TpmSignatureRSA.h"

#include <string>       // std::string
#include <iostream>     // std::cout
#include <sstream>      // std::stringstream

CTpmSignatureRSA::~CTpmSignatureRSA()
{
    try
    {
        if (m_keyGenerated && m_keyHandle.handle != 0)
        {
            tpm->FlushContext(m_keyHandle);
        }
    }
    catch (...)
    {
        std::cerr << "[CTpmSignatureRSA] Exception during destructor\n";
    }
}

CTpmSignatureRSA::CTpmSignatureRSA(CTpmSharedDevice* sharedDevice)
    : CTpmSignature(sharedDevice), m_keyHandle(TPM_RH_NULL), m_hashAlg(TPM_ALG_ID::SHA256), m_keyGenerated(false)
{

}

// Anahtar çifti üret
bool CTpmSignatureRSA::GenerateKeyPair()
{
    try
    {
/*
        TPMT_PUBLIC pub(
            TPM_ALG_ID::SHA256,
            TPMA_OBJECT::sign | TPMA_OBJECT::userWithAuth | TPMA_OBJECT::sensitiveDataOrigin,
            {},
            TPMS_RSA_PARMS(
                TPMT_SYM_DEF_OBJECT(), TPMS_NULL_ASYM_SCHEME(), 2048, 0
            ),
            TPM2B_PUBLIC_KEY_RSA()
        );
        TPMS_SENSITIVE_CREATE sens;
        CreatePrimaryResponse resp = tpm->CreatePrimary(
            TPM_RH::OWNER, sens, pub, {}, {}
        );
*/
        // Primary RSA anahtar için parametreleri hazırla
        TPMT_PUBLIC publicTemplate(
            TPM_ALG_ID::SHA256,                      // NameAlg
            TPMA_OBJECT::sign | TPMA_OBJECT:: userWithAuth | TPMA_OBJECT::sensitiveDataOrigin,
            {},                                      // No auth policy
            TPMS_RSA_PARMS(
                TPMT_SYM_DEF_OBJECT(),               // No symmetric algorithm
                TPMS_SCHEME_RSASSA(TPM_ALG_ID::SHA256),
                2048,                                // Key size
                0                                    // Public exponent (0 = default 65537)
            ),
            TPM2B_PUBLIC_KEY_RSA()
        );

        TPMS_SENSITIVE_CREATE sensCreate = {};
        sensCreate.userAuth = TPM2B_AUTH();                // Boş auth
        sensCreate.data = ByteVec();

        // outsideInfo ve PCR boş olabilir
        ByteVec outsideInfo;  // std::vector<BYTE>
        std::vector<TPMS_PCR_SELECTION> creationPCR;  // Boş PCR listesi

        // Primary oluştur
        CreatePrimaryResponse primary = tpm->CreatePrimary(
            TPM_RH::OWNER,
            sensCreate,
            publicTemplate,
            outsideInfo,
            creationPCR
        );

        m_keyHandle = primary.handle;
        m_publicArea = primary.outPublic;  // <-- burada kaydediyoruz
        m_keyGenerated = true;

        return true;
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[CTpmSignatureRSA] GenerateKeyPair exception: " << ex.what() << "\n";
        return false;
    }
}

bool CTpmSignatureRSA::GenerateKeyPairEx(
    UINT16 keyBits,
    TPM_ALG_ID hashAlg,
    UINT32 publicExponent,
    const std::vector<BYTE>& authValue)
{
    try {
        TPMT_PUBLIC publicTemplate(
            hashAlg,
            TPMA_OBJECT::sign | TPMA_OBJECT::userWithAuth | TPMA_OBJECT::sensitiveDataOrigin,
            {},
            TPMS_RSA_PARMS(
                TPMT_SYM_DEF_OBJECT(),
                TPMS_SCHEME_RSASSA(hashAlg),
                keyBits,
                publicExponent
            ),
            TPM2B_PUBLIC_KEY_RSA()
        );

        TPMS_SENSITIVE_CREATE sensCreate = {};
        sensCreate.userAuth = authValue;
        sensCreate.data = {};

        ByteVec outsideInfo;
        std::vector<TPMS_PCR_SELECTION> creationPCR;

        CreatePrimaryResponse primary = tpm->CreatePrimary(
            TPM_RH::OWNER,
            sensCreate,
            publicTemplate,
            outsideInfo,
            creationPCR
        );

        m_keyHandle = primary.handle;
        m_keyGenerated = true;
        m_hashAlg = hashAlg;
        m_publicArea = primary.outPublic;

        return true;
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[GenerateKeyPairEx] Exception: " << ex.what() << "\n";
        return false;
    }
}

// Veriyi imzala
bool CTpmSignatureRSA::SignData(const std::vector<BYTE>& data, std::vector<BYTE>& signatureOut)
{
    if (!m_keyGenerated)
    {
        std::cerr << "[CTpmSignatureRSA] Key not generated.\n";
        return false;
    }

    try
    {
        // TPM veriyi kendisi hashlemezse, dışarıda hashle
        HashResponse hashResp = tpm->Hash(data, m_hashAlg, TPM_RH::_NULL);

        // TPMT_HA yapısını oluştur ve içine Hash algoritmasını ve hash değerini koy
        TPMT_HA digest;
        digest.hashAlg = m_hashAlg;
        digest.digest = hashResp.outHash;// İmza oluştur

        std::shared_ptr<TPMU_SIGNATURE> sig = tpm->Sign(m_keyHandle, digest, TPMS_NULL_SIG_SCHEME(), TPMT_TK_HASHCHECK());

        if (!sig)
        {
            std::cerr << "[CTpmSignatureRSA] Sign returned null signature\n";
            return false;
        }

        // RSASSA olup olmadığını kontrol et
        if (sig->GetUnionSelector() != TPM_ALG_ID::RSASSA)
        {
            std::cerr << "[CTpmSignatureRSA] Unexpected signature algorithm\n";
            return false;
        }

        // RSASSA imzasını al
        auto rsassaSig = dynamic_pointer_cast<TPMS_SIGNATURE_RSASSA>(sig);
        if (!rsassaSig)
        {
            std::cerr << "[CTpmSignatureRSA] Failed to cast signature to RSASSA\n";
            return false;
        }

        // İmzayı dışa al
        signatureOut = rsassaSig->sig;

        return true;
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[CTpmSignatureRSA] Sign exception: " << ex.what() << std::endl;
        return false;
    }
}

// İmzayı doğrula
bool CTpmSignatureRSA::VerifySignature(const std::vector<BYTE>& data, const std::vector<BYTE>& signature)
{
    if (!m_keyGenerated)
    {
        std::cerr << "[CTpmSignatureRSA] Key not generated.\n";
        return false;
    }

    try
    {
        // 1. Veriyi TPM ile hashle
        HashResponse hashResp = tpm->Hash(data, m_hashAlg, TPM_RH::_NULL);
        TPM2B_DIGEST digest(hashResp.outHash);  // TPM2B_DIGEST constructor

        // 2. RSASSA imza yapısını oluştur (TPMU_SIGNATURE alt türü)
        auto rsassaSig = std::make_shared<TPMS_SIGNATURE_RSASSA>();
        rsassaSig->hash = m_hashAlg;
        rsassaSig->sig = signature;

        // 3. TPMU_SIGNATURE işaretçisi (base class)
        std::shared_ptr<TPMU_SIGNATURE> sigUnion = std::static_pointer_cast<TPMU_SIGNATURE>(rsassaSig);

        // 4. TPM ile doğrula
        tpm->VerifySignature(m_keyHandle, digest, *sigUnion);

        return true;  // Doğrulama başarılı
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[CTpmSignatureRSA] VerifySignature exception: " << ex.what() << "\n";
        return false;
    }
}

bool CTpmSignatureRSA::ExportPublicKeyRaw(std::vector<BYTE>& modulusOut, UINT32& exponentOut)
{
    if (!m_keyGenerated)
    {
        std::cerr << "[CTpmSignatureRSA] Key not generated.\n";
        return false;
    }

    try
    {
        auto rsaParms = dynamic_cast<TPMS_RSA_PARMS*>(m_publicArea.parameters.get());
        auto rsaKey = dynamic_cast<TPM2B_PUBLIC_KEY_RSA*>(m_publicArea.unique.get());

        if (!rsaParms || !rsaKey)
        {
            std::cerr << "[CTpmSignatureRSA] Public area is not RSA.\n";
            return false;
        }

        // Extract
        exponentOut = rsaParms->exponent == 0 ? 65537 : rsaParms->exponent;
        modulusOut = rsaKey->buffer;

        return true;
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[CTpmSignatureRSA] ExportPublicKeyRaw exception: " << ex.what() << "\n";
        return false;
    }
}

bool CTpmSignatureRSA::SignHashedData(const std::vector<BYTE>& digest, std::vector<BYTE>& signatureOut)
{
    if (!m_keyGenerated)
    {
        std::cerr << "[CTpmSignatureRSA] Key not generated.\n";
        return false;
    }

    try
    {
        // TPM imza yapısı oluştur
        TPM2B_DIGEST digestInput(digest);  // Zaten hashlenmiş veri

        // İmza oluştur (null scheme kullanabiliriz, çünkü template SHA256 ile tanımlandı)
        auto sigPtr = tpm->Sign(m_keyHandle, digestInput, TPMS_NULL_SIG_SCHEME(), TPMT_TK_HASHCHECK());

        // RSASSA imzasını çıkar
        auto* rsassaSig = dynamic_cast<TPMS_SIGNATURE_RSASSA*>(sigPtr.get());
        if (!rsassaSig)
        {
            std::cerr << "[CTpmSignatureRSA] Failed to extract RSASSA signature.\n";
            return false;
        }

        signatureOut = rsassaSig->sig;
        return true;
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[CTpmSignatureRSA] SignHashedData exception: " << ex.what() << "\n";
        return false;
    }
}

bool CTpmSignatureRSA::VerifyHashedData(const std::vector<BYTE>& digest, const std::vector<BYTE>& signature)
{
    if (!m_keyGenerated)
    {
        std::cerr << "[CTpmSignatureRSA] Key not generated.\n";
        return false;
    }

    try
    {
        // TPM imza yapısı oluştur
        TPM2B_DIGEST digestInput(digest);

        auto rsassaSig = std::make_shared<TPMS_SIGNATURE_RSASSA>();
        rsassaSig->hash = m_hashAlg;
        rsassaSig->sig = signature;

        std::shared_ptr<TPMU_SIGNATURE> sigUnion = std::static_pointer_cast<TPMU_SIGNATURE>(rsassaSig);

        // TPM ile doğrulama
        tpm->VerifySignature(m_keyHandle, digestInput, *sigUnion);

        return true;
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[CTpmSignatureRSA] VerifyHashedData exception: " << ex.what() << "\n";
        return false;
    }
}


bool CTpmSignatureRSA::ConvertRsaPublicKeyToPem(const std::vector<BYTE>& modulus, UINT32 exponent, std::string& pemOut)
{
    bool success = false;

#if USE_OPENSSL_LIBS

    RSA* rsa = nullptr;
    BIO* bio = nullptr;

    try
    {
        rsa = RSA_new();
        if (!rsa) throw std::runtime_error("RSA_new failed");

        // 1. Exponent BIGNUM
        BIGNUM* e = BN_new();
        if (!e) throw std::runtime_error("BN_new failed");
        BN_set_word(e, exponent);

        // 2. Modulus BIGNUM
        BIGNUM* n = BN_bin2bn(modulus.data(), static_cast<int>(modulus.size()), nullptr);
        if (!n) throw std::runtime_error("BN_bin2bn failed");

        if (RSA_set0_key(rsa, n, e, nullptr) != 1)
            throw std::runtime_error("RSA_set0_key failed");

        // 3. EVP yapısına sar
        EVP_PKEY* evpKey = EVP_PKEY_new();
        if (!evpKey || EVP_PKEY_assign_RSA(evpKey, rsa) != 1)
            throw std::runtime_error("EVP_PKEY_assign_RSA failed");

        rsa = nullptr; // ownership artık EVP'de

        // 4. BIO oluştur
        bio = BIO_new(BIO_s_mem());
        if (!bio) throw std::runtime_error("BIO_new failed");

        // 5. PEM formatına yaz
        if (!PEM_write_bio_PUBKEY(bio, evpKey))
            throw std::runtime_error("PEM_write_bio_PUBKEY failed");

        // 6. Stringe al
        char* data = nullptr;
        long len = BIO_get_mem_data(bio, &data);
        if (len <= 0) throw std::runtime_error("BIO_get_mem_data failed");

        pemOut.assign(data, len);
        success = true;

        EVP_PKEY_free(evpKey);
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[ConvertRsaPublicKeyToPem] Exception: " << ex.what() << std::endl;
    }

    if (bio) BIO_free(bio);
    if (rsa) RSA_free(rsa); // Eğer EVP'ye verildiyse bu zaten null olur

#endif

    return success;
}

bool CTpmSignatureRSA::ParseRsaPublicKeyFromPem(const std::string& pem, std::vector<BYTE>& modulusOut, UINT32& exponentOut)
{
#if USE_OPENSSL_LIBS
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (!bio)
    {
        std::cerr << "[ParseRsaPublicKeyFromPem] Failed to create BIO.\n";
        return false;
    }

    RSA* rsa = PEM_read_bio_RSA_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!rsa)
    {
        std::cerr << "[ParseRsaPublicKeyFromPem] Failed to read RSA public key.\n";
        return false;
    }

    // Modulus
    const BIGNUM* n = nullptr;
    const BIGNUM* e = nullptr;
    RSA_get0_key(rsa, &n, &e, nullptr);

    if (!n || !e)
    {
        std::cerr << "[ParseRsaPublicKeyFromPem] RSA key missing components.\n";
        RSA_free(rsa);
        return false;
    }

    // Convert BIGNUMs to BYTE arrays
    int modLen = BN_num_bytes(n);
    modulusOut.resize(modLen);
    BN_bn2bin(n, modulusOut.data());

    exponentOut = static_cast<UINT32>(BN_get_word(e));

    RSA_free(rsa);
    return true;
#else
    std::cerr << "[ParseRsaPublicKeyFromPem] OpenSSL not available.\n";
    return false;
#endif
}

bool CTpmSignatureRSA::VerifySignatureWithRawPublicKey(
    const std::vector<BYTE>& data,
    const std::vector<BYTE>& signature,
    const std::vector<BYTE>& modulus,
    UINT32 exponent)
{
#if USE_OPENSSL_LIBS
    bool result = false;

    RSA* rsa = RSA_new();
    if (!rsa)
    {
        std::cerr << "[VerifySignatureWithRawPublicKey] RSA_new failed.\n";
        return false;
    }

    BIGNUM* n = BN_bin2bn(modulus.data(), static_cast<int>(modulus.size()), nullptr);
    BIGNUM* e = BN_new();
    BN_set_word(e, exponent);

    RSA_set0_key(rsa, n, e, nullptr); // n and e ownership transferred to RSA

    // Hash data (SHA256)
    BYTE hash[32];
    CTpmHash hashHelper;
    std::vector<BYTE> hashVec;
    hashHelper.HashBuffer(TPM_ALG_ID::SHA256, data, hashVec);
    memcpy(hash, hashVec.data(), 32);

    // Verify
    int verifyResult = RSA_verify(NID_sha256, hash, 32, signature.data(), static_cast<unsigned int>(signature.size()), rsa);
    RSA_free(rsa);

    if (verifyResult == 1)
    {
        std::cout << "[VerifySignatureWithRawPublicKey] Signature valid.\n";
        result = true;
    }
    else
    {
        std::cerr << "[VerifySignatureWithRawPublicKey] Signature invalid.\n";
        result = false;
    }

    return result;
#else
    std::cerr << "[VerifySignatureWithRawPublicKey] OpenSSL not available.\n";
    return false;
#endif
}
