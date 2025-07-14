#include "TpmCrypto.h"

#include <string>       // std::string
#include <iostream>     // std::cout
#include <sstream>      // std::stringstream
#include <fstream>      // std::ofstream
#include <vector>       // ...

#define null  {}

CTpmCrypto::~CTpmCrypto()
{
    try
    {
        UnloadAndClearAesKey();

        if (m_useSharedTpmDevice)
        {

        }
        else
        {
            delete m_sharedTpmDevice;
            m_sharedTpmDevice = nullptr;

            std::stringstream ss;
            ss << "local CTpmSharedDevice succesfully deleted." << std::endl;
            Log(ss.str());
        }
    }
    catch (...)
    {
        std::stringstream ss;
        ss << "Destructor unknown exception." << std::endl;
        Log(ss.str(), true);
    }
}

CTpmCrypto::CTpmCrypto(CTpmSharedDevice* sharedDevice)
    : m_useSharedTpmDevice(sharedDevice != nullptr), m_sharedTpmDevice(sharedDevice)
{
    try
    {
        if (m_useSharedTpmDevice)
        {
            m_sharedTpmDevice = sharedDevice;
            std::stringstream ss;
            ss << "[CTpmCrypto] uses shared CTpmSharedDevice\n";
            Log(ss.str());
        }
        else
        {
            m_sharedTpmDevice = new CTpmSharedDevice();
            std::stringstream ss;
            ss << "[CTpmCrypto] uses local  CTpmSharedDevice\n";
            Log(ss.str());
        }

        tpm = m_sharedTpmDevice->GetTpm();
        device = m_sharedTpmDevice->GetDevice();
    }
    catch (...)
    {
        std::stringstream ss;
        ss << "Constructor unknown exception." << std::endl;
        Log(ss.str(), true);
    }
}

CTpmSharedDevice* CTpmCrypto::GetTpmSharedDevice(void)
{
    return m_sharedTpmDevice;
}

bool CTpmCrypto::Release(void)
{
    bool fncReturn = false;

    try
    {
        if (m_useSharedTpmDevice)
        {

        }
        else
        {
            delete m_sharedTpmDevice;
            m_sharedTpmDevice = nullptr;
        }

        fncReturn = true;
    }
    catch (const std::exception& ex)
    {
        std::stringstream ss;
        ss << "Release exception: " << ex.what() << std::endl;
        Log(ss.str(), true);
        fncReturn = false;
    }
    catch (...)
    {
        std::stringstream ss;
        ss << "Release unknown exception." << std::endl;
        Log(ss.str(), true);
        fncReturn = false;
    }

    return fncReturn;
}

bool CTpmCrypto::Initialize(void)
{
    bool fncReturn = false;

    try
    {
        m_aesKeyHandle = TPM_HANDLE();

        if (!this->ResetAesKey())
        {
            std::cerr << "AES key reset failed: " << this->GetLastError() << std::endl;
            fncReturn = false;
        }
        else
        {
            fncReturn = true;
        }
    }
    catch (const std::exception& ex)
    {
        std::stringstream ss;
        ss << "Initialize exception: " << ex.what() << std::endl;
        Log(ss.str(), true);
        fncReturn = false;
    }
    catch (...)
    {
        std::stringstream ss;
        ss << "Initialize unknown exception." << std::endl;
        Log(ss.str(), true);
        fncReturn = false;
    }

    return fncReturn;
}

bool CTpmCrypto::GenerateAndLoadAesKey()
{
    try
    {
        if (!tpm)
        {
            m_lastError = "TPM not initialized.";
            return false;
        }
/*
        //
        // 1. Create primary (RSA root key)
        //
        TPMT_SYM_DEF_OBJECT symDef(TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB);
        TPMT_RSA_SCHEME rsaScheme(TPM_ALG_ID::_NULL, TPM_ALG_ID::SHA256);
         
        TPMS_RSA_PARMS rsaParams(symDef, rsaScheme, 2048, 0);

        TPMT_PUBLIC primaryTemplate(
            TPM_ALG_ID::SHA256,
            TPMA_OBJECT::decrypt | TPMA_OBJECT::restricted | TPMA_OBJECT::fixedParent |
            TPMA_OBJECT::fixedTPM | TPMA_OBJECT::sensitiveDataOrigin | TPMA_OBJECT::userWithAuth,
            {},
            rsaParams,
            TPM2B_PUBLIC_KEY_RSA()
        );

        TPMS_SENSITIVE_CREATE inSensitive; // boş sensitive alan
        ByteVec outsideInfo;               // boş outsideInfo
        std::vector<TPMS_PCR_SELECTION> creationPCR; // boş PCR seçimi

        CreatePrimaryResponse primaryResp = tpm->CreatePrimary(
            TPM_RH::OWNER,
            inSensitive,
            primaryTemplate,
            outsideInfo,
            creationPCR
        );

        TPM_HANDLE primaryHandle = primaryResp.handle;

        //
        // 2. Create AES key (SymCipher)
        //
        TPMT_PUBLIC aesTemplate(
            TPM_ALG_ID::SHA256,
            TPMA_OBJECT::decrypt | TPMA_OBJECT::userWithAuth | TPMA_OBJECT::sensitiveDataOrigin,
            {},
            TPMS_SYMCIPHER_PARMS(TPMT_SYM_DEF_OBJECT(TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB)),
            TPM2B_DIGEST_SYMCIPHER()
        );

        auto aesKey = tpm->Create(
            primaryHandle,
            TPMS_SENSITIVE_CREATE(), // empty
            aesTemplate,
            {},
            {}
        );

        m_aesKeyHandle = tpm->Load(primaryHandle, aesKey.outPrivate, aesKey.outPublic);

        tpm->FlushContext(primaryHandle);

        std::cout << "[CTpmCrypto] AES key created and loaded successfully." << std::endl;
        return true;
*/
        TPM_HANDLE primaryHandle = MakeStoragePrimary(nullptr);

        // Make an AES key
        TPMT_PUBLIC inPublic(TPM_ALG_ID::SHA256,
            TPMA_OBJECT::decrypt | TPMA_OBJECT::sign | TPMA_OBJECT::userWithAuth
            | TPMA_OBJECT::sensitiveDataOrigin,
            null,
            TPMS_SYMCIPHER_PARMS(TpmCryptoNS::Aes128Cfb),
            TPM2B_DIGEST_SYMCIPHER());

        auto aesKey = tpm->Create(primaryHandle, null, inPublic, null, null);

        m_aesKeyHandle = tpm->Load(primaryHandle, aesKey.outPrivate, aesKey.outPublic);

        tpm->FlushContext(primaryHandle);

        std::cout << "[CTpmCrypto] AES key created and loaded successfully." << std::endl;

        return true;
    }
    catch (const std::exception& ex)
    {
        m_lastError = std::string("GenerateAndLoadAesKey failed: ") + ex.what();
        std::cerr << m_lastError << std::endl;
        return false;
    }
}

bool CTpmCrypto::UnloadAndClearAesKey()
{
    try
    {
        if (!tpm)
        {
            m_lastError = "TPM not initialized.";
            return false;
        }

        if (m_aesKeyHandle.handle != 0 && m_aesKeyHandle.handle != TPM_RH_NULL)
        {
            tpm->FlushContext(m_aesKeyHandle);
            m_aesKeyHandle = TPM_HANDLE(); // invalidate
            std::cout << "[CTpmCrypto] AES key unloaded and cleared successfully." << std::endl;
            return true;
        }
        else
        {
            std::cout << "[CTpmCrypto] AES key handle was already empty." << std::endl;
            return true;
        }
    }
    catch (const std::exception& ex)
    {
        m_lastError = std::string("UnloadAndClearAesKey exception: ") + ex.what();
        std::cerr << m_lastError << std::endl;
        return false;
    }
}

bool CTpmCrypto::ResetAesKey()
{
    if (!UnloadAndClearAesKey())
    {
        m_lastError = "ResetAesKey: failed to unload existing key.";
        return false;
    }

    if (!GenerateAndLoadAesKey())
    {
        m_lastError = "ResetAesKey: failed to generate/load new key.";
        return false;
    }

    std::cout << "[CTpmCrypto] AES key reset successfully." << std::endl;
    return true;
}



bool CTpmCrypto::EncryptByte(BYTE value, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> plain = { value };
    return EncryptData(plain, encryptedOut);
}

bool CTpmCrypto::DecryptByte(const std::vector<BYTE>& encryptedData, BYTE& valueOut)
{
    std::vector<BYTE> plain;
    if (!DecryptData(encryptedData, plain) || plain.size() != 1)
        return false;

    valueOut = plain[0];
    return true;
}

bool CTpmCrypto::EncryptChar(char value, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> plain = { static_cast<BYTE>(value) };
    return EncryptData(plain, encryptedOut);
}

bool CTpmCrypto::DecryptChar(const std::vector<BYTE>& encryptedData, char& valueOut)
{
    std::vector<BYTE> plain;
    if (!DecryptData(encryptedData, plain) || plain.size() != 1)
        return false;

    valueOut = static_cast<char>(plain[0]);
    return true;
}

bool CTpmCrypto::EncryptInt(int value, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> plain(sizeof(int));
    std::memcpy(plain.data(), &value, sizeof(int));
    return EncryptData(plain, encryptedOut);
}

bool CTpmCrypto::DecryptInt(const std::vector<BYTE>& encryptedData, int& valueOut)
{
    std::vector<BYTE> plain;
    if (!DecryptData(encryptedData, plain) || plain.size() != sizeof(int))
        return false;

    std::memcpy(&valueOut, plain.data(), sizeof(int));
    return true;
}

bool CTpmCrypto::EncryptFloat(float value, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> plain(sizeof(float));
    std::memcpy(plain.data(), &value, sizeof(float));
    return EncryptData(plain, encryptedOut);
}

bool CTpmCrypto::DecryptFloat(const std::vector<BYTE>& encryptedData, float& valueOut)
{
    std::vector<BYTE> plain;
    if (!DecryptData(encryptedData, plain) || plain.size() != sizeof(float))
        return false;

    std::memcpy(&valueOut, plain.data(), sizeof(float));
    return true;
}

bool CTpmCrypto::EncryptDouble(double value, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> plain(sizeof(double));
    std::memcpy(plain.data(), &value, sizeof(double));
    return EncryptData(plain, encryptedOut);
}

bool CTpmCrypto::DecryptDouble(const std::vector<BYTE>& encryptedData, double& valueOut)
{
    std::vector<BYTE> plain;
    if (!DecryptData(encryptedData, plain) || plain.size() != sizeof(double))
        return false;

    std::memcpy(&valueOut, plain.data(), sizeof(double));
    return true;
}

bool CTpmCrypto::EncryptString(const std::string& str, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> plain(str.begin(), str.end());
    return EncryptData(plain, encryptedOut);
}

bool CTpmCrypto::DecryptString(const std::vector<BYTE>& encryptedData, std::string& strOut)
{
    std::vector<BYTE> plain;
    if (!DecryptData(encryptedData, plain))
        return false;

    strOut = std::string(plain.begin(), plain.end());
    return true;
}

bool CTpmCrypto::EncryptByteArray(const std::vector<BYTE>& values, std::vector<BYTE>& encryptedOut)
{
    return EncryptData(values, encryptedOut);
}

bool CTpmCrypto::DecryptByteArray(const std::vector<BYTE>& encryptedData, std::vector<BYTE>& valuesOut)
{
    return DecryptData(encryptedData, valuesOut);
}

bool CTpmCrypto::EncryptCharArray(const std::vector<char>& values, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> plain(values.begin(), values.end());
    return EncryptData(plain, encryptedOut);
}

bool CTpmCrypto::DecryptCharArray(const std::vector<BYTE>& encryptedData, std::vector<char>& valuesOut)
{
    std::vector<BYTE> plain;
    if (!DecryptData(encryptedData, plain))
        return false;

    valuesOut.assign(plain.begin(), plain.end());
    return true;
}

bool CTpmCrypto::EncryptIntArray(const std::vector<int>& values, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> plain(values.size() * sizeof(int));
    std::memcpy(plain.data(), values.data(), plain.size());
    return EncryptData(plain, encryptedOut);
}

bool CTpmCrypto::DecryptIntArray(const std::vector<BYTE>& encryptedData, std::vector<int>& valuesOut)
{
    std::vector<BYTE> plain;
    if (!DecryptData(encryptedData, plain) || (plain.size() % sizeof(int)) != 0)
        return false;

    size_t count = plain.size() / sizeof(int);
    valuesOut.resize(count);
    std::memcpy(valuesOut.data(), plain.data(), plain.size());
    return true;
}

bool CTpmCrypto::EncryptFloatArray(const std::vector<float>& values, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> plain(values.size() * sizeof(float));
    std::memcpy(plain.data(), values.data(), plain.size());
    return EncryptData(plain, encryptedOut);
}

bool CTpmCrypto::DecryptFloatArray(const std::vector<BYTE>& encryptedData, std::vector<float>& valuesOut)
{
    std::vector<BYTE> plain;
    if (!DecryptData(encryptedData, plain) || (plain.size() % sizeof(float)) != 0)
        return false;

    size_t count = plain.size() / sizeof(float);
    valuesOut.resize(count);
    std::memcpy(valuesOut.data(), plain.data(), plain.size());
    return true;
}

bool CTpmCrypto::EncryptDoubleArray(const std::vector<double>& values, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> plain(values.size() * sizeof(double));
    std::memcpy(plain.data(), values.data(), plain.size());
    return EncryptData(plain, encryptedOut);
}

bool CTpmCrypto::DecryptDoubleArray(const std::vector<BYTE>& encryptedData, std::vector<double>& valuesOut)
{
    std::vector<BYTE> plain;
    if (!DecryptData(encryptedData, plain) || (plain.size() % sizeof(double)) != 0)
        return false;

    size_t count = plain.size() / sizeof(double);
    valuesOut.resize(count);
    std::memcpy(valuesOut.data(), plain.data(), plain.size());
    return true;
}

bool CTpmCrypto::EncryptStringArray(const std::vector<std::string>& values, std::vector<BYTE>& encryptedOut)
{
    std::ostringstream oss;
    for (size_t i = 0; i < values.size(); ++i)
    {
        if (i > 0) oss << '\n';  // newline-separated
        oss << values[i];
    }
    std::string joined = oss.str();
    std::vector<BYTE> plain(joined.begin(), joined.end());
    return EncryptData(plain, encryptedOut);
}

bool CTpmCrypto::DecryptStringArray(const std::vector<BYTE>& encryptedData, std::vector<std::string>& valuesOut)
{
    std::vector<BYTE> plain;
    if (!DecryptData(encryptedData, plain))
        return false;

    std::string joined(plain.begin(), plain.end());
    std::istringstream iss(joined);
    std::string line;
    while (std::getline(iss, line))
        valuesOut.push_back(line);

    return true;
}

bool CTpmCrypto::EncryptFile(const std::string& inputFile, const std::string& outputFile)
{
    try
    {
        std::ifstream in(inputFile.c_str(), std::ios::binary);
        if (!in)
        {
            std::cerr << "[CTpmCrypto] EncryptFile: Cannot open input file." << std::endl;
            return false;
        }

        std::vector<BYTE> plain((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        in.close();

        std::vector<BYTE> encrypted;
        if (!EncryptData(plain, encrypted))
        {
            std::cerr << "[CTpmCrypto] EncryptFile: EncryptData failed." << std::endl;
            return false;
        }

        std::ofstream out(outputFile.c_str(), std::ios::binary);
        if (!out)
        {
            std::cerr << "[CTpmCrypto] EncryptFile: Cannot open output file." << std::endl;
            return false;
        }

        out.write(reinterpret_cast<const char*>(encrypted.data()), encrypted.size());
        out.close();

        return true;
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[CTpmCrypto] EncryptFile exception: " << ex.what() << std::endl;
        return false;
    }
}

bool CTpmCrypto::DecryptFile(const std::string& inputFile, const std::string& outputFile)
{
    try
    {
        std::ifstream in(inputFile.c_str(), std::ios::binary);
        if (!in)
        {
            std::cerr << "[CTpmCrypto] DecryptFile: Cannot open input file." << std::endl;
            return false;
        }

        std::vector<BYTE> encrypted((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        in.close();

        std::vector<BYTE> decrypted;
        if (!DecryptData(encrypted, decrypted))
        {
            std::cerr << "[CTpmCrypto] DecryptFile: DecryptData failed." << std::endl;
            return false;
        }

        std::ofstream out(outputFile.c_str(), std::ios::binary);
        if (!out)
        {
            std::cerr << "[CTpmCrypto] DecryptFile: Cannot open output file." << std::endl;
            return false;
        }

        out.write(reinterpret_cast<const char*>(decrypted.data()), decrypted.size());
        out.close();

        return true;
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[CTpmCrypto] DecryptFile exception: " << ex.what() << std::endl;
        return false;
    }
}

bool CTpmCrypto::EncryptFileChunked(const std::string& inputFile, const std::string& outputFile, size_t chunkSize)
{
    try
    {
        std::ifstream in(inputFile, std::ios::binary);
        if (!in.is_open())
        {
            m_lastError = "Cannot open input file for reading.";
            return false;
        }

        std::ofstream out(outputFile, std::ios::binary);
        if (!out.is_open())
        {
            m_lastError = "Cannot open output file for writing.";
            return false;
        }

        std::vector<BYTE> buffer(chunkSize);
        while (in)
        {
            in.read(reinterpret_cast<char*>(buffer.data()), chunkSize);
            std::streamsize bytesRead = in.gcount();
            if (bytesRead <= 0)
                break;

            std::vector<BYTE> chunk(buffer.begin(), buffer.begin() + bytesRead);
            std::vector<BYTE> encryptedChunk;
            if (!EncryptData(chunk, encryptedChunk))
            {
                m_lastError = "Chunk encryption failed: " + GetLastError();
                return false;
            }

            // write encrypted size and data
            uint32_t encSize = static_cast<uint32_t>(encryptedChunk.size());
            out.write(reinterpret_cast<const char*>(&encSize), sizeof(encSize));
            out.write(reinterpret_cast<const char*>(encryptedChunk.data()), encSize);
        }

        in.close();
        out.close();
        return true;
    }
    catch (const std::exception& ex)
    {
        m_lastError = std::string("EncryptFileChunked exception: ") + ex.what();
        return false;
    }
}

bool CTpmCrypto::DecryptFileChunked(const std::string& inputFile, const std::string& outputFile)
{
    try
    {
        std::ifstream in(inputFile, std::ios::binary);
        if (!in.is_open())
        {
            m_lastError = "Cannot open encrypted input file.";
            return false;
        }

        std::ofstream out(outputFile, std::ios::binary);
        if (!out.is_open())
        {
            m_lastError = "Cannot open output file for writing.";
            return false;
        }

        while (in)
        {
            uint32_t chunkSize = 0;
            in.read(reinterpret_cast<char*>(&chunkSize), sizeof(chunkSize));
            if (in.gcount() != sizeof(chunkSize))
                break;

            std::vector<BYTE> encryptedChunk(chunkSize);
            in.read(reinterpret_cast<char*>(encryptedChunk.data()), chunkSize);
            if (in.gcount() != chunkSize)
            {
                m_lastError = "Failed to read full encrypted chunk.";
                return false;
            }

            std::vector<BYTE> decryptedChunk;
            if (!DecryptData(encryptedChunk, decryptedChunk))
            {
                m_lastError = "Chunk decryption failed: " + GetLastError();
                return false;
            }

            out.write(reinterpret_cast<const char*>(decryptedChunk.data()), decryptedChunk.size());
        }

        in.close();
        out.close();
        return true;
    }
    catch (const std::exception& ex)
    {
        m_lastError = std::string("DecryptFileChunked exception: ") + ex.what();
        return false;
    }
}


bool CTpmCrypto::EncryptData(const std::vector<BYTE>& plain, std::vector<BYTE>& encrypted)
{
    try
    {
        if (plain.empty())
        {
            m_lastError = "EncryptData: input is empty.";
            return false;
        }

        return EncryptDecryptInternal(plain, encrypted, true); // true = encrypt
    }
    catch (const std::exception& ex)
    {
        m_lastError = std::string("EncryptData exception: ") + ex.what();
        return false;
    }
}

bool CTpmCrypto::DecryptData(const std::vector<BYTE>& encrypted, std::vector<BYTE>& plain)
{
    try
    {
        if (encrypted.empty())
        {
            m_lastError = "DecryptData: input is empty.";
            return false;
        }

        return EncryptDecryptInternal(encrypted, plain, false); // false = decrypt
    }
    catch (const std::exception& ex)
    {
        m_lastError = std::string("DecryptData exception: ") + ex.what();
        return false;
    }
}

bool CTpmCrypto::EncryptDecryptInternal(const std::vector<BYTE>& inData, std::vector<BYTE>& outData, bool encrypt)
{
    try
    {
        if (!tpm || !m_aesKeyHandle)
        {
            m_lastError = "TPM not initialized or AES key not loaded.";
            return false;
        }

        //TPM2B_IV iv(16); // 16-byte null IV
        ByteVec iv(16);
        std::fill(iv.begin(), iv.end(), 0);  // Hepsini sıfırla

        auto result = tpm->EncryptDecrypt(
            m_aesKeyHandle,
            encrypt ? (BYTE)0 : (BYTE)1,
            TPM_ALG_ID::CFB,
            iv,
            inData
        );

        outData = result.outData;
        return true;
    }
    catch (const std::exception& ex)
    {
        m_lastError = std::string("EncryptDecryptInternal exception: ") + ex.what();
        std::cerr << m_lastError << std::endl;
        return false;
    }
}



TPM_HANDLE CTpmCrypto::MakeStoragePrimary(AUTH_SESSION* sess)
{
    TPMT_PUBLIC storagePrimaryTemplate(TPM_ALG_ID::SHA1,
        TPMA_OBJECT::decrypt | TPMA_OBJECT::restricted
        | TPMA_OBJECT::fixedParent | TPMA_OBJECT::fixedTPM
        | TPMA_OBJECT::sensitiveDataOrigin | TPMA_OBJECT::userWithAuth,
        null,           // No policy
        TPMS_RSA_PARMS(TpmCryptoNS::Aes128Cfb, TPMS_NULL_ASYM_SCHEME(), 2048, 65537),
        TPM2B_PUBLIC_KEY_RSA());
    // Create the key
    if (sess)
        (*tpm)[*sess];
    return tpm->CreatePrimary(TPM_RH::OWNER, null, storagePrimaryTemplate, null, null)
        .handle;
}

void CTpmCrypto::EncryptDecryptSample()
{
    Announce("EncryptDecryptSample");

    TPM_HANDLE prim = MakeStoragePrimary(nullptr);

    // Make an AES key
    TPMT_PUBLIC inPublic(TPM_ALG_ID::SHA256,
        TPMA_OBJECT::decrypt | TPMA_OBJECT::sign | TPMA_OBJECT::userWithAuth
        | TPMA_OBJECT::sensitiveDataOrigin,
        null,
        TPMS_SYMCIPHER_PARMS(TpmCryptoNS::Aes128Cfb),
        TPM2B_DIGEST_SYMCIPHER());

    auto aesKey = tpm->Create(prim, null, inPublic, null, null);

    TPM_HANDLE aesHandle = tpm->Load(prim, aesKey.outPrivate, aesKey.outPublic);

    ByteVec toEncrypt{ 1, 2, 3, 4, 5, 4, 3, 2, 12, 3, 4, 5 };
    ByteVec iv(16);

    auto encrypted = tpm->EncryptDecrypt(aesHandle, (BYTE)0, TPM_ALG_ID::CFB, iv, toEncrypt);
    auto decrypted = tpm->EncryptDecrypt(aesHandle, (BYTE)1, TPM_ALG_ID::CFB, iv, encrypted.outData);

    cout << "AES encryption" << endl <<
        "in:  " << toEncrypt << endl <<
        "enc: " << encrypted.outData << endl <<
        "dec: " << decrypted.outData << endl;

    _ASSERT(decrypted.outData == toEncrypt);

    tpm->FlushContext(prim);
    tpm->FlushContext(aesHandle);
}

bool CTpmCrypto::EncryptDataWithPassword(const std::vector<BYTE>& plain, const std::string& password, std::vector<BYTE>& encrypted)
{
    return EncryptDecryptInternalWithPassword(plain, password, encrypted, true);
}

bool CTpmCrypto::DecryptDataWithPassword(const std::vector<BYTE>& encrypted, const std::string& password, std::vector<BYTE>& plain)
{
    return EncryptDecryptInternalWithPassword(encrypted, password, plain, false);
}

bool CTpmCrypto::EncryptDecryptInternalWithPassword(const std::vector<BYTE>& inData, const std::string& password, std::vector<BYTE>& outData, bool encrypt)
{
    try
    {
        if (!tpm)
        {
            std::cerr << "[CTpmCrypto] TPM not initialized.\n";
            return false;
        }

        if (!m_aesKeyHandle)
        {
            std::cerr << "[CTpmCrypto] AES key handle not loaded.\n";
            return false;
        }

        // Set auth using password (PIN) for the AES key handle
        m_aesKeyHandle.SetAuth(std::vector<BYTE>(password.begin(), password.end()));

        ByteVec iv(16, 0); // Zero IV
        auto result = tpm->EncryptDecrypt(
            m_aesKeyHandle,
            encrypt ? (BYTE)0 : (BYTE)1,
            TPM_ALG_ID::CFB,
            iv,
            inData
        );

        outData = result.outData;
        return true;
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[CTpmCrypto] EncryptDecryptInternalWithPassword exception: " << ex.what() << std::endl;
        return false;
    }
}

bool CTpmCrypto::EncryptByteWithPassword(BYTE value, const std::string& password, std::vector<BYTE>& encryptedOut)
{
    return EncryptDataWithPassword(std::vector<BYTE>{ value }, password, encryptedOut);
}

bool CTpmCrypto::EncryptCharWithPassword(char value, const std::string& password, std::vector<BYTE>& encryptedOut)
{
    return EncryptDataWithPassword(std::vector<BYTE>{ static_cast<BYTE>(value) }, password, encryptedOut);
}

bool CTpmCrypto::EncryptIntWithPassword(int value, const std::string& password, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> bytes(sizeof(int));
    std::memcpy(bytes.data(), &value, sizeof(int));
    return EncryptDataWithPassword(bytes, password, encryptedOut);
}

bool CTpmCrypto::EncryptFloatWithPassword(float value, const std::string& password, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> bytes(sizeof(float));
    std::memcpy(bytes.data(), &value, sizeof(float));
    return EncryptDataWithPassword(bytes, password, encryptedOut);
}

bool CTpmCrypto::EncryptDoubleWithPassword(double value, const std::string& password, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> bytes(sizeof(double));
    std::memcpy(bytes.data(), &value, sizeof(double));
    return EncryptDataWithPassword(bytes, password, encryptedOut);
}

bool CTpmCrypto::EncryptStringWithPassword(const std::string& str, const std::string& password, std::vector<BYTE>& encryptedOut)
{
    return EncryptDataWithPassword(std::vector<BYTE>(str.begin(), str.end()), password, encryptedOut);
}

bool CTpmCrypto::DecryptByteWithPassword(const std::vector<BYTE>& encryptedData, const std::string& password, BYTE& valueOut)
{
    std::vector<BYTE> plain;
    if (!DecryptDataWithPassword(encryptedData, password, plain) || plain.size() < 1)
        return false;
    valueOut = plain[0];
    return true;
}

bool CTpmCrypto::DecryptCharWithPassword(const std::vector<BYTE>& encryptedData, const std::string& password, char& valueOut)
{
    std::vector<BYTE> plain;
    if (!DecryptDataWithPassword(encryptedData, password, plain) || plain.size() < 1)
        return false;
    valueOut = static_cast<char>(plain[0]);
    return true;
}

bool CTpmCrypto::DecryptIntWithPassword(const std::vector<BYTE>& encryptedData, const std::string& password, int& valueOut)
{
    std::vector<BYTE> plain;
    if (!DecryptDataWithPassword(encryptedData, password, plain) || plain.size() != sizeof(int))
        return false;
    std::memcpy(&valueOut, plain.data(), sizeof(int));
    return true;
}

bool CTpmCrypto::DecryptFloatWithPassword(const std::vector<BYTE>& encryptedData, const std::string& password, float& valueOut)
{
    std::vector<BYTE> plain;
    if (!DecryptDataWithPassword(encryptedData, password, plain) || plain.size() != sizeof(float))
        return false;
    std::memcpy(&valueOut, plain.data(), sizeof(float));
    return true;
}

bool CTpmCrypto::DecryptDoubleWithPassword(const std::vector<BYTE>& encryptedData, const std::string& password, double& valueOut)
{
    std::vector<BYTE> plain;
    if (!DecryptDataWithPassword(encryptedData, password, plain) || plain.size() != sizeof(double))
        return false;
    std::memcpy(&valueOut, plain.data(), sizeof(double));
    return true;
}

bool CTpmCrypto::DecryptStringWithPassword(const std::vector<BYTE>& encryptedData, const std::string& password, std::string& strOut)
{
    std::vector<BYTE> plain;
    if (!DecryptDataWithPassword(encryptedData, password, plain))
        return false;
    strOut = std::string(plain.begin(), plain.end());
    return true;
}

bool CTpmCrypto::EncryptByteArrayWithPassword(const std::vector<BYTE>& values, const std::string& password, std::vector<BYTE>& encryptedOut)
{
    try
    {
        return EncryptDataWithPassword(values, password, encryptedOut);
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[EncryptByteArrayWithPassword] Exception: " << ex.what() << std::endl;
        return false;
    }
}


bool CTpmCrypto::EncryptCharArrayWithPassword(const std::vector<char>& values, const std::string& password, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> input(values.begin(), values.end());
    return EncryptDataWithPassword(input, password, encryptedOut);
}

bool CTpmCrypto::EncryptIntArrayWithPassword(const std::vector<int>& values, const std::string& password, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> input;
    for (int val : values)
    {
        BYTE* p = reinterpret_cast<BYTE*>(&val);
        input.insert(input.end(), p, p + sizeof(int));
    }
    return EncryptDataWithPassword(input, password, encryptedOut);
}

bool CTpmCrypto::EncryptFloatArrayWithPassword(const std::vector<float>& values, const std::string& password, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> input;
    for (float val : values)
    {
        BYTE* p = reinterpret_cast<BYTE*>(&val);
        input.insert(input.end(), p, p + sizeof(float));
    }
    return EncryptDataWithPassword(input, password, encryptedOut);
}

bool CTpmCrypto::EncryptDoubleArrayWithPassword(const std::vector<double>& values, const std::string& password, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> input;
    for (double val : values)
    {
        BYTE* p = reinterpret_cast<BYTE*>(&val);
        input.insert(input.end(), p, p + sizeof(double));
    }
    return EncryptDataWithPassword(input, password, encryptedOut);
}

bool CTpmCrypto::EncryptStringArrayWithPassword(const std::vector<std::string>& values, const std::string& password, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> input;
    for (const auto& str : values)
    {
        input.insert(input.end(), str.begin(), str.end());
        input.push_back('\0'); // null-terminate each string
    }
    return EncryptDataWithPassword(input, password, encryptedOut);
}

bool CTpmCrypto::DecryptByteArrayWithPassword(const std::vector<BYTE>& encryptedData, const std::string& password, std::vector<BYTE>& valuesOut)
{
    try
    {
        return DecryptDataWithPassword(encryptedData, password, valuesOut);
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[DecryptByteArrayWithPassword] Exception: " << ex.what() << std::endl;
        return false;
    }
}

bool CTpmCrypto::DecryptCharArrayWithPassword(const std::vector<BYTE>& encryptedData, const std::string& password, std::vector<char>& valuesOut)
{
    std::vector<BYTE> decrypted;
    if (!DecryptDataWithPassword(encryptedData, password, decrypted))
        return false;

    valuesOut.assign(decrypted.begin(), decrypted.end());
    return true;
}

bool CTpmCrypto::DecryptIntArrayWithPassword(const std::vector<BYTE>& encryptedData, const std::string& password, std::vector<int>& valuesOut)
{
    std::vector<BYTE> decrypted;
    if (!DecryptDataWithPassword(encryptedData, password, decrypted))
        return false;

    if (decrypted.size() % sizeof(int) != 0)
        return false;

    size_t count = decrypted.size() / sizeof(int);
    valuesOut.resize(count);
    memcpy(valuesOut.data(), decrypted.data(), decrypted.size());
    return true;
}

bool CTpmCrypto::DecryptFloatArrayWithPassword(const std::vector<BYTE>& encryptedData, const std::string& password, std::vector<float>& valuesOut)
{
    std::vector<BYTE> decrypted;
    if (!DecryptDataWithPassword(encryptedData, password, decrypted))
        return false;

    if (decrypted.size() % sizeof(float) != 0)
        return false;

    size_t count = decrypted.size() / sizeof(float);
    valuesOut.resize(count);
    memcpy(valuesOut.data(), decrypted.data(), decrypted.size());
    return true;
}

bool CTpmCrypto::DecryptDoubleArrayWithPassword(const std::vector<BYTE>& encryptedData, const std::string& password, std::vector<double>& valuesOut)
{
    std::vector<BYTE> decrypted;
    if (!DecryptDataWithPassword(encryptedData, password, decrypted))
        return false;

    if (decrypted.size() % sizeof(double) != 0)
        return false;

    size_t count = decrypted.size() / sizeof(double);
    valuesOut.resize(count);
    memcpy(valuesOut.data(), decrypted.data(), decrypted.size());
    return true;
}

bool CTpmCrypto::DecryptStringArrayWithPassword(const std::vector<BYTE>& encryptedData, const std::string& password, std::vector<std::string>& valuesOut)
{
    std::vector<BYTE> decrypted;
    if (!DecryptDataWithPassword(encryptedData, password, decrypted))
        return false;

    valuesOut.clear();
    std::string current;
    for (BYTE b : decrypted)
    {
        if (b == '\0')
        {
            valuesOut.push_back(current);
            current.clear();
        }
        else
        {
            current += static_cast<char>(b);
        }
    }

    if (!current.empty()) // kalan varsa
        valuesOut.push_back(current);

    return true;
}

bool CTpmCrypto::EncryptFileWithPassword(const std::string& inputFile, const std::string& outputFile, const std::string& password)
{
    try
    {
        std::ifstream in(inputFile, std::ios::binary);
        if (!in)
        {
            std::cerr << "[EncryptFileWithPassword] Failed to open input file: " << inputFile << std::endl;
            return false;
        }

        std::vector<BYTE> plain((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        in.close();

        std::vector<BYTE> encrypted;
        if (!EncryptDataWithPassword(plain, password, encrypted))
        {
            std::cerr << "[EncryptFileWithPassword] Encryption failed." << std::endl;
            return false;
        }

        std::ofstream out(outputFile, std::ios::binary);
        if (!out)
        {
            std::cerr << "[EncryptFileWithPassword] Failed to open output file: " << outputFile << std::endl;
            return false;
        }

        out.write(reinterpret_cast<const char*>(encrypted.data()), encrypted.size());
        out.close();

        return true;
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[EncryptFileWithPassword] Exception: " << ex.what() << std::endl;
        return false;
    }
}

bool CTpmCrypto::DecryptFileWithPassword(const std::string& inputFile, const std::string& outputFile, const std::string& password)
{
    try
    {
        std::ifstream in(inputFile, std::ios::binary);
        if (!in)
        {
            std::cerr << "[DecryptFileWithPassword] Failed to open input file: " << inputFile << std::endl;
            return false;
        }

        std::vector<BYTE> encrypted((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        in.close();

        std::vector<BYTE> decrypted;
        if (!DecryptDataWithPassword(encrypted, password, decrypted))
        {
            std::cerr << "[DecryptFileWithPassword] Decryption failed." << std::endl;
            return false;
        }

        std::ofstream out(outputFile, std::ios::binary);
        if (!out)
        {
            std::cerr << "[DecryptFileWithPassword] Failed to open output file: " << outputFile << std::endl;
            return false;
        }

        out.write(reinterpret_cast<const char*>(decrypted.data()), decrypted.size());
        out.close();

        return true;
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[DecryptFileWithPassword] Exception: " << ex.what() << std::endl;
        return false;
    }
}

bool CTpmCrypto::IsTooLargeForTpm(const std::vector<BYTE>& data)
{
    return data.size() > TpmCryptoNS::TPM_AES_MAX_SIZE;
}

bool CTpmCrypto::IsTooLargeForTpm(const std::streamsize dataSize)
{
    return dataSize > TpmCryptoNS::TPM_AES_MAX_SIZE;
}

bool CTpmCrypto::IsTooLargeForTpm(const uint64_t dataSize)
{
    return dataSize > TpmCryptoNS::TPM_AES_MAX_SIZE;
}

std::streamsize CTpmCrypto::GetFileSize(const std::string& filePath)
{
    std::streamsize fileSize = 0;

    std::ifstream in(filePath, std::ios::binary | std::ios::ate);
    if (!in)
        return -1; // hata durumunda -1 döner

    fileSize = in.tellg();  // byte cinsinden dosya boyutu

    in.close();

    return fileSize;
}

uint64_t CTpmCrypto::GetFileSize2(const std::string& filePath)
{
    uint64_t fileSize = 0;

    std::ifstream in(filePath, std::ios::binary | std::ios::ate);
    if (!in)
        return 0; // Hata durumunda 0 döner (istersen -1 yerine uint64_t için özel sabit belirleyebiliriz)

    fileSize = static_cast<uint64_t>(in.tellg());  // byte cinsinden dosya boyutu

    in.close();

    return fileSize;
}

bool CTpmCrypto::EncryptDataChunked(const std::vector<BYTE>& plain, std::vector<BYTE>& encrypted)
{
    encrypted.clear();

    const size_t CHUNK_SIZE = 1024;  // TPM AES limit
    size_t offset = 0;

    while (offset < plain.size())
    {
        size_t currentChunkSize = std::min(CHUNK_SIZE, plain.size() - offset);
        std::vector<BYTE> chunk(plain.begin() + offset, plain.begin() + offset + currentChunkSize);
        std::vector<BYTE> encryptedChunk;

        if (!EncryptData(chunk, encryptedChunk))
        {
            m_lastError = "EncryptDataChunked: failed on a chunk";
            return false;
        }

        // Chunk size + chunk data
        uint32_t chunkSize = static_cast<uint32_t>(encryptedChunk.size());
        encrypted.insert(encrypted.end(),
            reinterpret_cast<BYTE*>(&chunkSize),
            reinterpret_cast<BYTE*>(&chunkSize) + sizeof(uint32_t));
        encrypted.insert(encrypted.end(), encryptedChunk.begin(), encryptedChunk.end());

        offset += currentChunkSize;
    }

    return true;
}

bool CTpmCrypto::DecryptDataChunked(const std::vector<BYTE>& encrypted, std::vector<BYTE>& plain)
{
    plain.clear();

    size_t offset = 0;

    while (offset + sizeof(uint32_t) <= encrypted.size())
    {
        // Chunk length
        uint32_t chunkSize = 0;
        std::memcpy(&chunkSize, encrypted.data() + offset, sizeof(uint32_t));
        offset += sizeof(uint32_t);

        if (offset + chunkSize > encrypted.size())
        {
            m_lastError = "DecryptDataChunked: corrupted data (chunk size overrun)";
            return false;
        }

        std::vector<BYTE> encryptedChunk(encrypted.begin() + offset, encrypted.begin() + offset + chunkSize);
        std::vector<BYTE> decryptedChunk;

        if (!DecryptData(encryptedChunk, decryptedChunk))
        {
            m_lastError = "DecryptDataChunked: failed on a chunk";
            return false;
        }

        plain.insert(plain.end(), decryptedChunk.begin(), decryptedChunk.end());
        offset += chunkSize;
    }

    return true;
}

bool CTpmCrypto::EncryptFileWithPasswordChunked(const std::string& inputFile, const std::string& outputFile, const std::string& password)
{
    std::ifstream in(inputFile, std::ios::binary);
    if (!in)
    {
        m_lastError = "EncryptFileWithPasswordChunked: cannot open input file";
        return false;
    }

    std::ofstream out(outputFile, std::ios::binary);
    if (!out)
    {
        m_lastError = "EncryptFileWithPasswordChunked: cannot open output file";
        return false;
    }

    const size_t CHUNK_SIZE = 1024;
    std::vector<BYTE> buffer(CHUNK_SIZE);

    while (in)
    {
        in.read(reinterpret_cast<char*>(buffer.data()), CHUNK_SIZE);
        std::streamsize bytesRead = in.gcount();
        if (bytesRead <= 0) break;

        std::vector<BYTE> chunk(buffer.begin(), buffer.begin() + bytesRead);
        std::vector<BYTE> encryptedChunk;

        if (!EncryptDataWithPassword(chunk, password, encryptedChunk))
        {
            m_lastError = "EncryptFileWithPasswordChunked: encryption failed on chunk";
            return false;
        }

        uint32_t size = static_cast<uint32_t>(encryptedChunk.size());
        out.write(reinterpret_cast<const char*>(&size), sizeof(size));
        out.write(reinterpret_cast<const char*>(encryptedChunk.data()), size);
    }

    return true;
}

bool CTpmCrypto::DecryptFileWithPasswordChunked(const std::string& inputFile, const std::string& outputFile, const std::string& password)
{
    std::ifstream in(inputFile, std::ios::binary);
    if (!in)
    {
        m_lastError = "DecryptFileWithPasswordChunked: cannot open input file";
        return false;
    }

    std::ofstream out(outputFile, std::ios::binary);
    if (!out)
    {
        m_lastError = "DecryptFileWithPasswordChunked: cannot open output file";
        return false;
    }

    while (in)
    {
        uint32_t chunkSize = 0;
        in.read(reinterpret_cast<char*>(&chunkSize), sizeof(chunkSize));
        if (in.gcount() != sizeof(chunkSize)) break;

        std::vector<BYTE> encryptedChunk(chunkSize);
        in.read(reinterpret_cast<char*>(encryptedChunk.data()), chunkSize);
        if (in.gcount() != chunkSize)
        {
            m_lastError = "DecryptFileWithPasswordChunked: corrupted or incomplete chunk";
            return false;
        }

        std::vector<BYTE> decryptedChunk;
        if (!DecryptDataWithPassword(encryptedChunk, password, decryptedChunk))
        {
            m_lastError = "DecryptFileWithPasswordChunked: decryption failed on chunk";
            return false;
        }

        out.write(reinterpret_cast<const char*>(decryptedChunk.data()), decryptedChunk.size());
    }

    return true;
}

bool CTpmCrypto::EncryptDataWithPasswordChunked(const std::vector<BYTE>& plain, const std::string& password, std::vector<BYTE>& encrypted)
{
    try
    {
        const size_t CHUNK_SIZE = 1024;
        size_t offset = 0;
        encrypted.clear();

        while (offset < plain.size())
        {
            size_t currentChunkSize = std::min(CHUNK_SIZE, plain.size() - offset);
            std::vector<BYTE> chunk(plain.begin() + offset, plain.begin() + offset + currentChunkSize);
            std::vector<BYTE> encryptedChunk;

            if (!EncryptDataWithPassword(chunk, password, encryptedChunk))
            {
                m_lastError = "EncryptDataWithPasswordChunked: encryption failed on chunk";
                return false;
            }

            uint32_t size = static_cast<uint32_t>(encryptedChunk.size());
            encrypted.insert(encrypted.end(), reinterpret_cast<BYTE*>(&size), reinterpret_cast<BYTE*>(&size) + sizeof(size));
            encrypted.insert(encrypted.end(), encryptedChunk.begin(), encryptedChunk.end());

            offset += currentChunkSize;
        }

        return true;
    }
    catch (const std::exception& ex)
    {
        m_lastError = std::string("EncryptDataWithPasswordChunked exception: ") + ex.what();
        return false;
    }
}

bool CTpmCrypto::DecryptDataWithPasswordChunked(const std::vector<BYTE>& encrypted, const std::string& password, std::vector<BYTE>& plain)
{
    try
    {
        size_t offset = 0;
        plain.clear();

        while (offset + sizeof(uint32_t) <= encrypted.size())
        {
            uint32_t chunkSize = 0;
            std::memcpy(&chunkSize, &encrypted[offset], sizeof(uint32_t));
            offset += sizeof(uint32_t);

            if (offset + chunkSize > encrypted.size())
            {
                m_lastError = "DecryptDataWithPasswordChunked: corrupted or incomplete chunk";
                return false;
            }

            std::vector<BYTE> encryptedChunk(encrypted.begin() + offset, encrypted.begin() + offset + chunkSize);
            std::vector<BYTE> decryptedChunk;

            if (!DecryptDataWithPassword(encryptedChunk, password, decryptedChunk))
            {
                m_lastError = "DecryptDataWithPasswordChunked: decryption failed on chunk";
                return false;
            }

            plain.insert(plain.end(), decryptedChunk.begin(), decryptedChunk.end());
            offset += chunkSize;
        }

        return true;
    }
    catch (const std::exception& ex)
    {
        m_lastError = std::string("DecryptDataWithPasswordChunked exception: ") + ex.what();
        return false;
    }
}

bool CTpmCrypto::CompareFiles(const std::string& file1, const std::string& file2)
{
    std::ifstream f1(file1, std::ios::binary);
    std::ifstream f2(file2, std::ios::binary);

    if (!f1 || !f2)
        return false;

    std::istreambuf_iterator<char> begin1(f1), end1;
    std::istreambuf_iterator<char> begin2(f2), end2;

    return std::vector<char>(begin1, end1) == std::vector<char>(begin2, end2);
}

void CTpmCrypto::BuildTestFile(const std::string& inputFile)
{
    std::ofstream out(inputFile, std::ios::binary);
    for (int i = 0; i < 50000; ++i)  // ~50 KB örnek veri
    {
        char val = static_cast<char>(i % 256);
        out.write(&val, 1);
    }
}

bool CTpmCrypto::GenerateAndLoadAesKeyWithPassword(const std::string& password)
{
    try
    {
        if (!tpm)
        {
            m_lastError = "TPM not initialized.";
            std::cerr << m_lastError << std::endl;
            return false;
        }

        // 1. Storage primary key oluştur
        TPM_HANDLE prim = MakeStoragePrimary(nullptr);

        // 2. Password'ü auth olarak ayarla
        TPMS_SENSITIVE_CREATE inSensitive;
        inSensitive.userAuth = std::vector<BYTE>(password.begin(), password.end());

        // 3. AES anahtar şablonu
        TPMT_PUBLIC inPublic(
            TPM_ALG_ID::SHA256,
            TPMA_OBJECT::decrypt | TPMA_OBJECT::sign | TPMA_OBJECT::userWithAuth |
            TPMA_OBJECT::sensitiveDataOrigin,
            null,
            TPMS_SYMCIPHER_PARMS(TpmCryptoNS::Aes128Cfb),
            TPM2B_DIGEST_SYMCIPHER()
        );

        // 4. AES anahtarı oluştur
        auto aesKey = tpm->Create(prim, inSensitive, inPublic, null, null);

        // 5. Load işlemi ve şifreyi handle'a bağla
        m_aesKeyHandle = tpm->Load(prim, aesKey.outPrivate, aesKey.outPublic);
        m_aesKeyHandle.SetAuth(std::vector<BYTE>(password.begin(), password.end()));

        std::cout << "[CTpmCrypto] AES key with password created and loaded successfully." << std::endl;
        return true;
    }
    catch (const std::exception& ex)
    {
        m_lastError = std::string("GenerateAndLoadAesKeyWithPassword failed: ") + ex.what();
        std::cerr << m_lastError << std::endl;
        return false;
    }
}

bool CTpmCrypto::GenerateAndLoadAesKeyWithPassword(const std::string& password, bool usePersistentKey)
{
    try
    {
        if (!tpm)
        {
            m_lastError = "TPM not initialized.";
            std::cerr << m_lastError << std::endl;
            return false;
        }

        TPM_HANDLE prim = MakeStoragePrimary(nullptr);
        TPM_HANDLE persistentHandle(0x81000001); // Chosen persistent handle

        // NV üzerinden kullanılacaksa önce orada var mı kontrol et
        if (usePersistentKey)
        {
            try
            {
                m_aesKeyHandle = persistentHandle;
                tpm->ReadPublic(m_aesKeyHandle); // Test if handle exists
                m_aesKeyHandle.SetAuth(std::vector<BYTE>(password.begin(), password.end()));
                std::cout << "[CTpmCrypto] AES key loaded from persistent storage." << std::endl;
                return true;
            }
            catch (...)
            {
                std::cout << "[CTpmCrypto] No persistent AES key found, generating..." << std::endl;
            }
        }

        // AES anahtarı oluştur
        TPMS_SENSITIVE_CREATE inSensitive;
        inSensitive.userAuth = std::vector<BYTE>(password.begin(), password.end());

        TPMT_PUBLIC inPublic(
            TPM_ALG_ID::SHA256,
            TPMA_OBJECT::decrypt | TPMA_OBJECT::sign | TPMA_OBJECT::userWithAuth |
            TPMA_OBJECT::sensitiveDataOrigin,
            null,
            TPMS_SYMCIPHER_PARMS(TpmCryptoNS::Aes128Cfb),
            TPM2B_DIGEST_SYMCIPHER()
        );

        auto aesKey = tpm->Create(prim, inSensitive, inPublic, null, null);
        TPM_HANDLE tempHandle = tpm->Load(prim, aesKey.outPrivate, aesKey.outPublic);
        tempHandle.SetAuth(std::vector<BYTE>(password.begin(), password.end()));

        // Eğer kalıcı olsun denmişse persist et
        if (usePersistentKey)
        {
            // Önce var olan varsa sil
            try { tpm->EvictControl(TPM_RH::OWNER, persistentHandle, persistentHandle); }
            catch (...) {}
            tpm->EvictControl(TPM_RH::OWNER, tempHandle, persistentHandle);
            m_aesKeyHandle = persistentHandle;
            m_aesKeyHandle.SetAuth(std::vector<BYTE>(password.begin(), password.end()));
        }
        else
        {
            m_aesKeyHandle = tempHandle;
            m_aesKeyHandle.SetAuth(std::vector<BYTE>(password.begin(), password.end()));
        }

        std::cout << "[CTpmCrypto] AES key generated and " <<
            (usePersistentKey ? "stored persistently." : "loaded temporarily.") << std::endl;

        return true;
    }
    catch (const std::exception& ex)
    {
        m_lastError = std::string("GenerateAndLoadAesKeyWithPassword failed: ") + ex.what();
        std::cerr << m_lastError << std::endl;
        return false;
    }
}

bool CTpmCrypto::UnloadAndClearAesKeyWithPassword()
{
    try
    {
        if (!tpm)
        {
            m_lastError = "TPM not initialized.";
            return false;
        }

        if (m_aesKeyHandle.handle != 0 && m_aesKeyHandle.handle != TPM_RH_NULL)
        {
            try
            {
                tpm->FlushContext(m_aesKeyHandle);
                std::cout << "[CTpmCrypto] AES key handle flushed." << std::endl;
            }
            catch (const std::exception& ex)
            {
                std::cerr << "[UnloadAndClearAesKeyWithPassword] FlushContext failed: " << ex.what() << std::endl;
                m_lastError = "FlushContext failed.";
                // yine de devam et
            }

            m_aesKeyHandle = TPM_HANDLE(); // sıfırla
        }
        else
        {
            std::cout << "[CTpmCrypto] AES key handle was already empty." << std::endl;
        }

        return true;
    }
    catch (const std::exception& ex)
    {
        m_lastError = std::string("UnloadAndClearAesKeyWithPassword exception: ") + ex.what();
        std::cerr << m_lastError << std::endl;
        return false;
    }
}

bool CTpmCrypto::RemovePersistentAesKey(UINT32 persistentHandleValue)
{
    try
    {
        TPM_HANDLE handle(persistentHandleValue);
        tpm->EvictControl(TPM_RH::OWNER, handle, handle);
        return true;
    }
    catch (...)
    {
        return false;
    }
}

bool CTpmCrypto::IsAesKeyHandleLoaded() const
{
    return m_aesKeyHandle.handle != 0;
}

bool CTpmCrypto::ClearAllAesKeys()
{
    bool result = true;
    if (IsAesKeyHandleLoaded()) {
        result &= RemovePersistentAesKey();  // NV alanını sil
        result &= UnloadAndClearAesKey();   // RAM'deki handle'ı sil
    }
    return result;
}

std::vector<BYTE> CTpmCrypto::ComputePasswordHash(const std::string& password) 
{
    std::vector<BYTE> hash(32, 0); // SHA-256 output is 32 bytes

    try {
        std::vector<BYTE> input(password.begin(), password.end());
        hash = Crypto::Hash(TPM_ALG_ID::SHA256, input, 0, input.size());
        //TPMT_HA hashObj = Crypto::Hash(TPM_ALG_ID::SHA256, input, 0, input.size());
        //hash = hashObj.digest;
    }
    catch (...) {
        std::cerr << "[ComputePasswordHash] Exception during password hash computation." << std::endl;
    }

    return hash;
}

bool CTpmCrypto::StorePasswordHashToNv(const std::vector<BYTE>& hash) 
{
#if 1
    try {
        tpm->NV_UndefineSpace(TPM_RH::OWNER, TpmCryptoNS::NV_INDEX_PASSWORD_HASH);
    }
    catch (...) {
        // Zaten tanımlı değilse sorun değil
    }    
    
    TPM2B_AUTH auth = {};
    TPM2B_NV_PUBLIC nvPub;
    nvPub.nvPublic.nvIndex = TPM_HANDLE(TpmCryptoNS::NV_INDEX_PASSWORD_HASH); // Veya sabit değer
    nvPub.nvPublic.nameAlg = TPM_ALG_ID::SHA256;
    nvPub.nvPublic.attributes =
        TPMA_NV::AUTHWRITE | TPMA_NV::AUTHREAD | TPMA_NV::OWNERWRITE | TPMA_NV::OWNERREAD;
    nvPub.nvPublic.authPolicy = TPM2B_DIGEST(); // Boş policy
    nvPub.nvPublic.dataSize = static_cast<UINT16>(hash.size());


    tpm->NV_DefineSpace(TPM_RH::OWNER, auth, nvPub.nvPublic);
    tpm->NV_Write(TPM_HANDLE(TpmCryptoNS::NV_INDEX_PASSWORD_HASH), TPM_HANDLE(TpmCryptoNS::NV_INDEX_PASSWORD_HASH), hash, 0);
#endif
    return true;
}

bool CTpmCrypto::ReadPasswordHashFromNv(std::vector<BYTE>& hashOut) {
    try {
        auto data = tpm->NV_Read(TPM_RH::OWNER, TPM_HANDLE(TpmCryptoNS::NV_INDEX_PASSWORD_HASH), 32, 0);
        hashOut = data;
        return true;
    }
    catch (...) {
        std::cerr << "[ReadPasswordHashFromNv] Failed to read hash from NV." << std::endl;
        return false;
    }
}

bool CTpmCrypto::IsPasswordValidForCurrentAesKey(const std::string& password) {
    std::vector<BYTE> expectedHash;
    if (!ReadPasswordHashFromNv(expectedHash))
        return false;

    auto currentHash = ComputePasswordHash(password);
    return currentHash == expectedHash;
}
