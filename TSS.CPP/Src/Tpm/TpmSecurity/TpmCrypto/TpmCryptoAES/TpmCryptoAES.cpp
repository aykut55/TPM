#include "TpmCryptoAES.h"

#include <string>       // std::string
#include <iostream>     // std::cout
#include <sstream>      // std::stringstream
#include <fstream>      // std::ofstream
#include <vector>       // ...

#define null  {}

CTpmCryptoAES::~CTpmCryptoAES()
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

CTpmCryptoAES::CTpmCryptoAES(CTpmSharedDevice* sharedDevice)
    : m_useSharedTpmDevice(sharedDevice != nullptr), m_sharedTpmDevice(sharedDevice)
{
    try
    {
        if (m_useSharedTpmDevice)
        {
            m_sharedTpmDevice = sharedDevice;
            std::stringstream ss;
            ss << "[CTpmCryptoAES] uses shared CTpmSharedDevice\n";
            Log(ss.str());
        }
        else
        {
            m_sharedTpmDevice = new CTpmSharedDevice();
            std::stringstream ss;
            ss << "[CTpmCryptoAES] uses local  CTpmSharedDevice\n";
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

CTpmSharedDevice* CTpmCryptoAES::GetTpmSharedDevice(void)
{
    return m_sharedTpmDevice;
}

bool CTpmCryptoAES::Release(void)
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

bool CTpmCryptoAES::Initialize(void)
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

// ***********************************************************************************************************************

bool CTpmCryptoAES::EncryptDataChunked(const std::vector<BYTE>& plain, std::vector<BYTE>& encrypted)
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

bool CTpmCryptoAES::DecryptDataChunked(const std::vector<BYTE>& encrypted, std::vector<BYTE>& plain)
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

bool CTpmCryptoAES::EncryptData(const std::vector<BYTE>& plain, std::vector<BYTE>& encrypted)
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

bool CTpmCryptoAES::DecryptData(const std::vector<BYTE>& encrypted, std::vector<BYTE>& plain)
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

bool CTpmCryptoAES::EncryptDecryptInternal(const std::vector<BYTE>& inData, std::vector<BYTE>& outData, bool encrypt)
{
    try
    {
        if (!tpm || !m_aesKeyHandle)
        {
            m_lastError = "TPM not initialized or AES key not loaded.";
            return false;
        }

        // TPM2B_IV iv(16); // 16-byte null IV
        // iv.buffer = std::vector<BYTE>(16, 0);
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

// ***********************************************************************************************************************

bool CTpmCryptoAES::EncryptDataWithPasswordChunked(const std::string& password, const std::vector<BYTE>& plain, std::vector<BYTE>& encrypted)
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

            if (!EncryptDataWithPassword(password, chunk, encryptedChunk))
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

bool CTpmCryptoAES::DecryptDataWithPasswordChunked(const std::string& password, const std::vector<BYTE>& encrypted, std::vector<BYTE>& plain)
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

            if (!DecryptDataWithPassword(password, encryptedChunk, decryptedChunk))
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

bool CTpmCryptoAES::EncryptDataWithPassword(const std::string& password, const std::vector<BYTE>& plain, std::vector<BYTE>& encrypted)
{
    bool checkPasswordValidty = false;
    bool generateAndLoadAesKeyWithPasswordAsNeeded = false;

    if (checkPasswordValidty)
    {
        if (!IsPasswordValidForCurrentAesKey(password))
        {
            if (generateAndLoadAesKeyWithPasswordAsNeeded)
            {
                if (!GenerateAndLoadAesKeyWithPassword(password))
                {
                    m_lastError = "EncryptDataWithPassword: GenerateAndLoadAesKeyWithPassword() is failed for current password.";
                    return false;
                }
            }
            else
            {
                m_lastError = "EncryptDataWithPassword: Password is invalid for current AES key.";
                return false;
            }
        }
    }

    return EncryptDecryptInternalWithPassword(password, plain, encrypted, true);
}

bool CTpmCryptoAES::DecryptDataWithPassword(const std::string& password, const std::vector<BYTE>& encrypted, std::vector<BYTE>& plain)
{
    bool checkPasswordValidty = false;
    bool generateAndLoadAesKeyWithPasswordAsNeeded = false;

    if (checkPasswordValidty)
    {
        if (!IsPasswordValidForCurrentAesKey(password))
        {
            if (generateAndLoadAesKeyWithPasswordAsNeeded)
            {
                if (!GenerateAndLoadAesKeyWithPassword(password))
                {
                    m_lastError = "DecryptDataWithPassword: GenerateAndLoadAesKeyWithPassword() is failed for current password.";
                    return false;
                }
            }
            else
            {
                m_lastError = "DecryptDataWithPassword: Password is invalid for current AES key.";
                return false;
            }

        }
    }

    return EncryptDecryptInternalWithPassword(password, encrypted, plain, false);
}

bool CTpmCryptoAES::EncryptDecryptInternalWithPassword(const std::string& password, const std::vector<BYTE>& inData, std::vector<BYTE>& outData, bool encrypt)
{
    try
    {
        if (!tpm)
        {
            std::cerr << "[CTpmCryptoAES] TPM not initialized.\n";
            return false;
        }

        if (!m_aesKeyHandle)
        {
            std::cerr << "[CTpmCryptoAES] AES key handle not loaded.\n";
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
        std::cerr << "[CTpmCryptoAES] EncryptDecryptInternalWithPassword exception: " << ex.what() << std::endl;
        return false;
    }
}

// ***********************************************************************************************************************

























bool CTpmCryptoAES::GenerateAndLoadAesKey()
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

        std::cout << "[CTpmCryptoAES] AES key created and loaded successfully." << std::endl;
        return true;
*/
        TPM_HANDLE primaryHandle = MakeStoragePrimary(nullptr);

        // Make an AES key
        TPMT_PUBLIC inPublic(TPM_ALG_ID::SHA256,
            TPMA_OBJECT::decrypt | TPMA_OBJECT::sign | TPMA_OBJECT::userWithAuth
            | TPMA_OBJECT::sensitiveDataOrigin,
            null,
            TPMS_SYMCIPHER_PARMS(TpmCryptoAESNS::Aes128Cfb),
            TPM2B_DIGEST_SYMCIPHER());

        auto aesKey = tpm->Create(primaryHandle, null, inPublic, null, null);

        m_aesKeyHandle = tpm->Load(primaryHandle, aesKey.outPrivate, aesKey.outPublic);

        tpm->FlushContext(primaryHandle);

        std::cout << "[CTpmCryptoAES] AES key created and loaded successfully." << std::endl;

        return true;
    }
    catch (const std::exception& ex)
    {
        m_lastError = std::string("GenerateAndLoadAesKey failed: ") + ex.what();
        std::cerr << m_lastError << std::endl;
        return false;
    }
}

bool CTpmCryptoAES::UnloadAndClearAesKey()
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
            std::cout << "[CTpmCryptoAES] AES key unloaded and cleared successfully." << std::endl;
            return true;
        }
        else
        {
            std::cout << "[CTpmCryptoAES] AES key handle was already empty." << std::endl;
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

bool CTpmCryptoAES::ResetAesKey()
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

    std::cout << "[CTpmCryptoAES] AES key reset successfully." << std::endl;
    return true;
}



bool CTpmCryptoAES::EncryptByte(BYTE value, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> plain = { value };
    return EncryptData(plain, encryptedOut);
}

bool CTpmCryptoAES::DecryptByte(const std::vector<BYTE>& encryptedData, BYTE& valueOut)
{
    std::vector<BYTE> plain;
    if (!DecryptData(encryptedData, plain) || plain.size() != 1)
        return false;

    valueOut = plain[0];
    return true;
}

bool CTpmCryptoAES::EncryptChar(char value, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> plain = { static_cast<BYTE>(value) };
    return EncryptData(plain, encryptedOut);
}

bool CTpmCryptoAES::DecryptChar(const std::vector<BYTE>& encryptedData, char& valueOut)
{
    std::vector<BYTE> plain;
    if (!DecryptData(encryptedData, plain) || plain.size() != 1)
        return false;

    valueOut = static_cast<char>(plain[0]);
    return true;
}

bool CTpmCryptoAES::EncryptInt(int value, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> plain(sizeof(int));
    std::memcpy(plain.data(), &value, sizeof(int));
    return EncryptData(plain, encryptedOut);
}

bool CTpmCryptoAES::DecryptInt(const std::vector<BYTE>& encryptedData, int& valueOut)
{
    std::vector<BYTE> plain;
    if (!DecryptData(encryptedData, plain) || plain.size() != sizeof(int))
        return false;

    std::memcpy(&valueOut, plain.data(), sizeof(int));
    return true;
}

bool CTpmCryptoAES::EncryptFloat(float value, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> plain(sizeof(float));
    std::memcpy(plain.data(), &value, sizeof(float));
    return EncryptData(plain, encryptedOut);
}

bool CTpmCryptoAES::DecryptFloat(const std::vector<BYTE>& encryptedData, float& valueOut)
{
    std::vector<BYTE> plain;
    if (!DecryptData(encryptedData, plain) || plain.size() != sizeof(float))
        return false;

    std::memcpy(&valueOut, plain.data(), sizeof(float));
    return true;
}

bool CTpmCryptoAES::EncryptDouble(double value, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> plain(sizeof(double));
    std::memcpy(plain.data(), &value, sizeof(double));
    return EncryptData(plain, encryptedOut);
}

bool CTpmCryptoAES::DecryptDouble(const std::vector<BYTE>& encryptedData, double& valueOut)
{
    std::vector<BYTE> plain;
    if (!DecryptData(encryptedData, plain) || plain.size() != sizeof(double))
        return false;

    std::memcpy(&valueOut, plain.data(), sizeof(double));
    return true;
}

bool CTpmCryptoAES::EncryptString(const std::string& str, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> plain(str.begin(), str.end());
    return EncryptData(plain, encryptedOut);
}

bool CTpmCryptoAES::DecryptString(const std::vector<BYTE>& encryptedData, std::string& strOut)
{
    std::vector<BYTE> plain;
    if (!DecryptData(encryptedData, plain))
        return false;

    strOut = std::string(plain.begin(), plain.end());
    return true;
}

bool CTpmCryptoAES::EncryptByteArray(const std::vector<BYTE>& values, std::vector<BYTE>& encryptedOut)
{
    return EncryptData(values, encryptedOut);
}

bool CTpmCryptoAES::DecryptByteArray(const std::vector<BYTE>& encryptedData, std::vector<BYTE>& valuesOut)
{
    return DecryptData(encryptedData, valuesOut);
}

bool CTpmCryptoAES::EncryptCharArray(const std::vector<char>& values, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> plain(values.begin(), values.end());
    return EncryptData(plain, encryptedOut);
}

bool CTpmCryptoAES::DecryptCharArray(const std::vector<BYTE>& encryptedData, std::vector<char>& valuesOut)
{
    std::vector<BYTE> plain;
    if (!DecryptData(encryptedData, plain))
        return false;

    valuesOut.assign(plain.begin(), plain.end());
    return true;
}

bool CTpmCryptoAES::EncryptIntArray(const std::vector<int>& values, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> plain(values.size() * sizeof(int));
    std::memcpy(plain.data(), values.data(), plain.size());
    return EncryptData(plain, encryptedOut);
}

bool CTpmCryptoAES::DecryptIntArray(const std::vector<BYTE>& encryptedData, std::vector<int>& valuesOut)
{
    std::vector<BYTE> plain;
    if (!DecryptData(encryptedData, plain) || (plain.size() % sizeof(int)) != 0)
        return false;

    size_t count = plain.size() / sizeof(int);
    valuesOut.resize(count);
    std::memcpy(valuesOut.data(), plain.data(), plain.size());
    return true;
}

bool CTpmCryptoAES::EncryptFloatArray(const std::vector<float>& values, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> plain(values.size() * sizeof(float));
    std::memcpy(plain.data(), values.data(), plain.size());
    return EncryptData(plain, encryptedOut);
}

bool CTpmCryptoAES::DecryptFloatArray(const std::vector<BYTE>& encryptedData, std::vector<float>& valuesOut)
{
    std::vector<BYTE> plain;
    if (!DecryptData(encryptedData, plain) || (plain.size() % sizeof(float)) != 0)
        return false;

    size_t count = plain.size() / sizeof(float);
    valuesOut.resize(count);
    std::memcpy(valuesOut.data(), plain.data(), plain.size());
    return true;
}

bool CTpmCryptoAES::EncryptDoubleArray(const std::vector<double>& values, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> plain(values.size() * sizeof(double));
    std::memcpy(plain.data(), values.data(), plain.size());
    return EncryptData(plain, encryptedOut);
}

bool CTpmCryptoAES::DecryptDoubleArray(const std::vector<BYTE>& encryptedData, std::vector<double>& valuesOut)
{
    std::vector<BYTE> plain;
    if (!DecryptData(encryptedData, plain) || (plain.size() % sizeof(double)) != 0)
        return false;

    size_t count = plain.size() / sizeof(double);
    valuesOut.resize(count);
    std::memcpy(valuesOut.data(), plain.data(), plain.size());
    return true;
}

bool CTpmCryptoAES::EncryptStringArray(const std::vector<std::string>& values, std::vector<BYTE>& encryptedOut)
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

bool CTpmCryptoAES::DecryptStringArray(const std::vector<BYTE>& encryptedData, std::vector<std::string>& valuesOut)
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

bool CTpmCryptoAES::EncryptFile(const std::string& inputFile, const std::string& outputFile)
{
    try
    {
        std::ifstream in(inputFile.c_str(), std::ios::binary);
        if (!in)
        {
            std::cerr << "[CTpmCryptoAES] EncryptFile: Cannot open input file." << std::endl;
            return false;
        }

        std::vector<BYTE> plain((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        in.close();

        std::vector<BYTE> encrypted;
        if (!EncryptData(plain, encrypted))
        {
            std::cerr << "[CTpmCryptoAES] EncryptFile: EncryptData failed." << std::endl;
            return false;
        }

        std::ofstream out(outputFile.c_str(), std::ios::binary);
        if (!out)
        {
            std::cerr << "[CTpmCryptoAES] EncryptFile: Cannot open output file." << std::endl;
            return false;
        }

        out.write(reinterpret_cast<const char*>(encrypted.data()), encrypted.size());
        out.close();

        return true;
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[CTpmCryptoAES] EncryptFile exception: " << ex.what() << std::endl;
        return false;
    }
}

bool CTpmCryptoAES::DecryptFile(const std::string& inputFile, const std::string& outputFile)
{
    try
    {
        std::ifstream in(inputFile.c_str(), std::ios::binary);
        if (!in)
        {
            std::cerr << "[CTpmCryptoAES] DecryptFile: Cannot open input file." << std::endl;
            return false;
        }

        std::vector<BYTE> encrypted((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        in.close();

        std::vector<BYTE> decrypted;
        if (!DecryptData(encrypted, decrypted))
        {
            std::cerr << "[CTpmCryptoAES] DecryptFile: DecryptData failed." << std::endl;
            return false;
        }

        std::ofstream out(outputFile.c_str(), std::ios::binary);
        if (!out)
        {
            std::cerr << "[CTpmCryptoAES] DecryptFile: Cannot open output file." << std::endl;
            return false;
        }

        out.write(reinterpret_cast<const char*>(decrypted.data()), decrypted.size());
        out.close();

        return true;
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[CTpmCryptoAES] DecryptFile exception: " << ex.what() << std::endl;
        return false;
    }
}

bool CTpmCryptoAES::EncryptFileChunked(const std::string& inputFile, const std::string& outputFile, size_t chunkSize)
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

bool CTpmCryptoAES::DecryptFileChunked(const std::string& inputFile, const std::string& outputFile)
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







TPM_HANDLE CTpmCryptoAES::MakeStoragePrimary(AUTH_SESSION* sess)
{
    TPMT_PUBLIC storagePrimaryTemplate(TPM_ALG_ID::SHA1,
        TPMA_OBJECT::decrypt | TPMA_OBJECT::restricted
        | TPMA_OBJECT::fixedParent | TPMA_OBJECT::fixedTPM
        | TPMA_OBJECT::sensitiveDataOrigin | TPMA_OBJECT::userWithAuth,
        null,           // No policy
        TPMS_RSA_PARMS(TpmCryptoAESNS::Aes128Cfb, TPMS_NULL_ASYM_SCHEME(), 2048, 65537),
        TPM2B_PUBLIC_KEY_RSA());
    // Create the key
    if (sess)
        (*tpm)[*sess];
    return tpm->CreatePrimary(TPM_RH::OWNER, null, storagePrimaryTemplate, null, null)
        .handle;
}

void CTpmCryptoAES::EncryptDecryptSample()
{
    Announce("EncryptDecryptSample");

    TPM_HANDLE prim = MakeStoragePrimary(nullptr);

    // Make an AES key
    TPMT_PUBLIC inPublic(TPM_ALG_ID::SHA256,
        TPMA_OBJECT::decrypt | TPMA_OBJECT::sign | TPMA_OBJECT::userWithAuth
        | TPMA_OBJECT::sensitiveDataOrigin,
        null,
        TPMS_SYMCIPHER_PARMS(TpmCryptoAESNS::Aes128Cfb),
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




bool CTpmCryptoAES::EncryptByteWithPassword(BYTE value, const std::string& password, std::vector<BYTE>& encryptedOut)
{
    return EncryptDataWithPassword(password, std::vector<BYTE>{ value }, encryptedOut);
}

bool CTpmCryptoAES::EncryptCharWithPassword(char value, const std::string& password, std::vector<BYTE>& encryptedOut)
{
    return EncryptDataWithPassword(password, std::vector<BYTE>{ static_cast<BYTE>(value) }, encryptedOut);
}

bool CTpmCryptoAES::EncryptIntWithPassword(int value, const std::string& password, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> bytes(sizeof(int));
    std::memcpy(bytes.data(), &value, sizeof(int));
    return EncryptDataWithPassword(password, bytes, encryptedOut);
}

bool CTpmCryptoAES::EncryptFloatWithPassword(float value, const std::string& password, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> bytes(sizeof(float));
    std::memcpy(bytes.data(), &value, sizeof(float));
    return EncryptDataWithPassword(password, bytes, encryptedOut);
}

bool CTpmCryptoAES::EncryptDoubleWithPassword(double value, const std::string& password, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> bytes(sizeof(double));
    std::memcpy(bytes.data(), &value, sizeof(double));
    return EncryptDataWithPassword(password, bytes, encryptedOut);
}

bool CTpmCryptoAES::EncryptStringWithPassword(const std::string& str, const std::string& password, std::vector<BYTE>& encryptedOut)
{
    return EncryptDataWithPassword(password, std::vector<BYTE>(str.begin(), str.end()), encryptedOut);
}

bool CTpmCryptoAES::DecryptByteWithPassword(const std::vector<BYTE>& encryptedData, const std::string& password, BYTE& valueOut)
{
    std::vector<BYTE> plain;
    if (!DecryptDataWithPassword(password, encryptedData, plain) || plain.size() < 1)
        return false;
    valueOut = plain[0];
    return true;
}

bool CTpmCryptoAES::DecryptCharWithPassword(const std::vector<BYTE>& encryptedData, const std::string& password, char& valueOut)
{
    std::vector<BYTE> plain;
    if (!DecryptDataWithPassword(password, encryptedData, plain) || plain.size() < 1)
        return false;
    valueOut = static_cast<char>(plain[0]);
    return true;
}

bool CTpmCryptoAES::DecryptIntWithPassword(const std::vector<BYTE>& encryptedData, const std::string& password, int& valueOut)
{
    std::vector<BYTE> plain;
    if (!DecryptDataWithPassword(password, encryptedData, plain) || plain.size() != sizeof(int))
        return false;
    std::memcpy(&valueOut, plain.data(), sizeof(int));
    return true;
}

bool CTpmCryptoAES::DecryptFloatWithPassword(const std::vector<BYTE>& encryptedData, const std::string& password, float& valueOut)
{
    std::vector<BYTE> plain;
    if (!DecryptDataWithPassword(password, encryptedData, plain) || plain.size() != sizeof(float))
        return false;
    std::memcpy(&valueOut, plain.data(), sizeof(float));
    return true;
}

bool CTpmCryptoAES::DecryptDoubleWithPassword(const std::vector<BYTE>& encryptedData, const std::string& password, double& valueOut)
{
    std::vector<BYTE> plain;
    if (!DecryptDataWithPassword(password, encryptedData, plain) || plain.size() != sizeof(double))
        return false;
    std::memcpy(&valueOut, plain.data(), sizeof(double));
    return true;
}

bool CTpmCryptoAES::DecryptStringWithPassword(const std::vector<BYTE>& encryptedData, const std::string& password, std::string& strOut)
{
    std::vector<BYTE> plain;
    if (!DecryptDataWithPassword(password, encryptedData, plain))
        return false;
    strOut = std::string(plain.begin(), plain.end());
    return true;
}

bool CTpmCryptoAES::EncryptByteArrayWithPassword(const std::vector<BYTE>& values, const std::string& password, std::vector<BYTE>& encryptedOut)
{
    try
    {
        return EncryptDataWithPassword(password, values, encryptedOut);
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[EncryptByteArrayWithPassword] Exception: " << ex.what() << std::endl;
        return false;
    }
}


bool CTpmCryptoAES::EncryptCharArrayWithPassword(const std::vector<char>& values, const std::string& password, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> input(values.begin(), values.end());
    return EncryptDataWithPassword(password, input, encryptedOut);
}

bool CTpmCryptoAES::EncryptIntArrayWithPassword(const std::vector<int>& values, const std::string& password, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> input;
    for (int val : values)
    {
        BYTE* p = reinterpret_cast<BYTE*>(&val);
        input.insert(input.end(), p, p + sizeof(int));
    }
    return EncryptDataWithPassword(password, input, encryptedOut);
}

bool CTpmCryptoAES::EncryptFloatArrayWithPassword(const std::vector<float>& values, const std::string& password, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> input;
    for (float val : values)
    {
        BYTE* p = reinterpret_cast<BYTE*>(&val);
        input.insert(input.end(), p, p + sizeof(float));
    }
    return EncryptDataWithPassword(password, input, encryptedOut);
}

bool CTpmCryptoAES::EncryptDoubleArrayWithPassword(const std::vector<double>& values, const std::string& password, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> input;
    for (double val : values)
    {
        BYTE* p = reinterpret_cast<BYTE*>(&val);
        input.insert(input.end(), p, p + sizeof(double));
    }
    return EncryptDataWithPassword(password, input, encryptedOut);
}

bool CTpmCryptoAES::EncryptStringArrayWithPassword(const std::vector<std::string>& values, const std::string& password, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> input;
    for (const auto& str : values)
    {
        input.insert(input.end(), str.begin(), str.end());
        input.push_back('\0'); // null-terminate each string
    }
    return EncryptDataWithPassword(password, input, encryptedOut);
}

bool CTpmCryptoAES::DecryptByteArrayWithPassword(const std::vector<BYTE>& encryptedData, const std::string& password, std::vector<BYTE>& valuesOut)
{
    try
    {
        return DecryptDataWithPassword(password, encryptedData, valuesOut);
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[DecryptByteArrayWithPassword] Exception: " << ex.what() << std::endl;
        return false;
    }
}

bool CTpmCryptoAES::DecryptCharArrayWithPassword(const std::vector<BYTE>& encryptedData, const std::string& password, std::vector<char>& valuesOut)
{
    std::vector<BYTE> decrypted;
    if (!DecryptDataWithPassword(password, encryptedData, decrypted))
        return false;

    valuesOut.assign(decrypted.begin(), decrypted.end());
    return true;
}

bool CTpmCryptoAES::DecryptIntArrayWithPassword(const std::vector<BYTE>& encryptedData, const std::string& password, std::vector<int>& valuesOut)
{
    std::vector<BYTE> decrypted;
    if (!DecryptDataWithPassword(password, encryptedData, decrypted))
        return false;

    if (decrypted.size() % sizeof(int) != 0)
        return false;

    size_t count = decrypted.size() / sizeof(int);
    valuesOut.resize(count);
    memcpy(valuesOut.data(), decrypted.data(), decrypted.size());
    return true;
}

bool CTpmCryptoAES::DecryptFloatArrayWithPassword(const std::vector<BYTE>& encryptedData, const std::string& password, std::vector<float>& valuesOut)
{
    std::vector<BYTE> decrypted;
    if (!DecryptDataWithPassword(password, encryptedData, decrypted))
        return false;

    if (decrypted.size() % sizeof(float) != 0)
        return false;

    size_t count = decrypted.size() / sizeof(float);
    valuesOut.resize(count);
    memcpy(valuesOut.data(), decrypted.data(), decrypted.size());
    return true;
}

bool CTpmCryptoAES::DecryptDoubleArrayWithPassword(const std::vector<BYTE>& encryptedData, const std::string& password, std::vector<double>& valuesOut)
{
    std::vector<BYTE> decrypted;
    if (!DecryptDataWithPassword(password, encryptedData, decrypted))
        return false;

    if (decrypted.size() % sizeof(double) != 0)
        return false;

    size_t count = decrypted.size() / sizeof(double);
    valuesOut.resize(count);
    memcpy(valuesOut.data(), decrypted.data(), decrypted.size());
    return true;
}

bool CTpmCryptoAES::DecryptStringArrayWithPassword(const std::vector<BYTE>& encryptedData, const std::string& password, std::vector<std::string>& valuesOut)
{
    std::vector<BYTE> decrypted;
    if (!DecryptDataWithPassword(password, encryptedData, decrypted))
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

bool CTpmCryptoAES::EncryptFileWithPassword(const std::string& inputFile, const std::string& outputFile, const std::string& password)
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
        if (!EncryptDataWithPassword(password, plain, encrypted))
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

bool CTpmCryptoAES::DecryptFileWithPassword(const std::string& inputFile, const std::string& outputFile, const std::string& password)
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
        if (!DecryptDataWithPassword(password, encrypted, decrypted))
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

bool CTpmCryptoAES::IsTooLargeForTpm(const std::vector<BYTE>& data)
{
    return data.size() > TpmCryptoAESNS::TPM_AES_MAX_SIZE;
}

bool CTpmCryptoAES::IsTooLargeForTpm(const std::streamsize dataSize)
{
    return dataSize > TpmCryptoAESNS::TPM_AES_MAX_SIZE;
}

bool CTpmCryptoAES::IsTooLargeForTpm(const uint64_t dataSize)
{
    return dataSize > TpmCryptoAESNS::TPM_AES_MAX_SIZE;
}

std::streamsize CTpmCryptoAES::GetFileSize(const std::string& filePath)
{
    std::streamsize fileSize = 0;

    std::ifstream in(filePath, std::ios::binary | std::ios::ate);
    if (!in)
        return -1; // hata durumunda -1 döner

    fileSize = in.tellg();  // byte cinsinden dosya boyutu

    in.close();

    return fileSize;
}

uint64_t CTpmCryptoAES::GetFileSize2(const std::string& filePath)
{
    uint64_t fileSize = 0;

    std::ifstream in(filePath, std::ios::binary | std::ios::ate);
    if (!in)
        return 0; // Hata durumunda 0 döner (istersen -1 yerine uint64_t için özel sabit belirleyebiliriz)

    fileSize = static_cast<uint64_t>(in.tellg());  // byte cinsinden dosya boyutu

    in.close();

    return fileSize;
}


bool CTpmCryptoAES::EncryptFileWithPasswordChunked(const std::string& inputFile, const std::string& outputFile, const std::string& password)
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

        if (!EncryptDataWithPassword(password, chunk, encryptedChunk))
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

bool CTpmCryptoAES::DecryptFileWithPasswordChunked(const std::string& inputFile, const std::string& outputFile, const std::string& password)
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
        if (!DecryptDataWithPassword(password, encryptedChunk, decryptedChunk))
        {
            m_lastError = "DecryptFileWithPasswordChunked: decryption failed on chunk";
            return false;
        }

        out.write(reinterpret_cast<const char*>(decryptedChunk.data()), decryptedChunk.size());
    }

    return true;
}


bool CTpmCryptoAES::CompareFiles(const std::string& file1, const std::string& file2)
{
    std::ifstream f1(file1, std::ios::binary);
    std::ifstream f2(file2, std::ios::binary);

    if (!f1 || !f2)
        return false;

    std::istreambuf_iterator<char> begin1(f1), end1;
    std::istreambuf_iterator<char> begin2(f2), end2;

    return std::vector<char>(begin1, end1) == std::vector<char>(begin2, end2);
}

void CTpmCryptoAES::BuildTestFile(const std::string& inputFile, const int inputFileSizeByte)
{
    std::ofstream out(inputFile, std::ios::binary);
    for (int i = 0; i < inputFileSizeByte; ++i)  
    {
        char val = static_cast<char>(i % 256);
        out.write(&val, 1);
    }
}

bool CTpmCryptoAES::GenerateAndLoadAesKeyWithPassword(const std::string& password)
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
            TPMS_SYMCIPHER_PARMS(TpmCryptoAESNS::Aes128Cfb),
            TPM2B_DIGEST_SYMCIPHER()
        );

        // 4. AES anahtarı oluştur
        auto aesKey = tpm->Create(prim, inSensitive, inPublic, null, null);

        // 5. Load işlemi ve şifreyi handle'a bağla
        m_aesKeyHandle = tpm->Load(prim, aesKey.outPrivate, aesKey.outPublic);
        m_aesKeyHandle.SetAuth(std::vector<BYTE>(password.begin(), password.end()));

        std::cout << "[CTpmCryptoAES] AES key with password created and loaded successfully." << std::endl;
        return true;
    }
    catch (const std::exception& ex)
    {
        m_lastError = std::string("GenerateAndLoadAesKeyWithPassword failed: ") + ex.what();
        std::cerr << m_lastError << std::endl;
        return false;
    }
}

bool CTpmCryptoAES::GenerateAndLoadAesKeyWithPassword(const std::string& password, bool usePersistentKey)
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
                std::cout << "[CTpmCryptoAES] AES key loaded from persistent storage." << std::endl;
                return true;
            }
            catch (...)
            {
                std::cout << "[CTpmCryptoAES] No persistent AES key found, generating..." << std::endl;
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
            TPMS_SYMCIPHER_PARMS(TpmCryptoAESNS::Aes128Cfb),
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

        std::cout << "[CTpmCryptoAES] AES key generated and " <<
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

bool CTpmCryptoAES::UnloadAndClearAesKeyWithPassword()
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
                std::cout << "[CTpmCryptoAES] AES key handle flushed." << std::endl;
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
            std::cout << "[CTpmCryptoAES] AES key handle was already empty." << std::endl;
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

bool CTpmCryptoAES::RemovePersistentAesKey(UINT32 persistentHandleValue)
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

bool CTpmCryptoAES::IsAesKeyHandleLoaded() const
{
    // hangisi kullanilacak, gpt'ye sor!!!

    return m_aesKeyHandle.handle != 0;

    return m_aesKeyHandle.handle != 0 && m_aesKeyHandle.handle != TPM_RH_NULL;
}

bool CTpmCryptoAES::ClearAllAesKeys()
{
    bool result = true;
    if (IsAesKeyHandleLoaded()) {
        result &= RemovePersistentAesKey();  // NV alanını sil
        result &= UnloadAndClearAesKey();   // RAM'deki handle'ı sil
    }
    return result;
}

std::vector<BYTE> CTpmCryptoAES::ComputePasswordHash(const std::string& password) 
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

bool CTpmCryptoAES::StorePasswordHashToNv(const std::vector<BYTE>& hash) 
{
#if 1
    try {
        tpm->NV_UndefineSpace(TPM_RH::OWNER, TpmCryptoAESNS::NV_INDEX_PASSWORD_HASH);
    }
    catch (...) {
        // Zaten tanımlı değilse sorun değil
    }    
    
    TPM2B_AUTH auth = {};
    TPM2B_NV_PUBLIC nvPub;
    nvPub.nvPublic.nvIndex = TPM_HANDLE(TpmCryptoAESNS::NV_INDEX_PASSWORD_HASH); // Veya sabit değer
    nvPub.nvPublic.nameAlg = TPM_ALG_ID::SHA256;
    nvPub.nvPublic.attributes =
        TPMA_NV::AUTHWRITE | TPMA_NV::AUTHREAD | TPMA_NV::OWNERWRITE | TPMA_NV::OWNERREAD;
    nvPub.nvPublic.authPolicy = TPM2B_DIGEST(); // Boş policy
    nvPub.nvPublic.dataSize = static_cast<UINT16>(hash.size());


    tpm->NV_DefineSpace(TPM_RH::OWNER, auth, nvPub.nvPublic);
    tpm->NV_Write(TPM_HANDLE(TpmCryptoAESNS::NV_INDEX_PASSWORD_HASH), TPM_HANDLE(TpmCryptoAESNS::NV_INDEX_PASSWORD_HASH), hash, 0);
#endif
    return true;
}

bool CTpmCryptoAES::ReadPasswordHashFromNv(std::vector<BYTE>& hashOut) {
    try {
        auto data = tpm->NV_Read(TPM_RH::OWNER, TPM_HANDLE(TpmCryptoAESNS::NV_INDEX_PASSWORD_HASH), 32, 0);
        hashOut = data;
        return true;
    }
    catch (...) {
        std::cerr << "[ReadPasswordHashFromNv] Failed to read hash from NV." << std::endl;
        return false;
    }
}

bool CTpmCryptoAES::IsPasswordValidForCurrentAesKey(const std::string& password) {
    std::vector<BYTE> expectedHash;
    if (!ReadPasswordHashFromNv(expectedHash))
        return false;

    auto currentHash = ComputePasswordHash(password);
    return currentHash == expectedHash;
}







bool CTpmCryptoAES::EncryptIntChunked(int value, std::vector<BYTE>& encryptedOut)
{
    try
    {
        // Int'i BYTE vektörüne dönüştür
        std::vector<BYTE> plain(sizeof(int));
        std::memcpy(plain.data(), &value, sizeof(int));

        // Chunked AES şifreleme
        return EncryptDataChunked(plain, encryptedOut);
    }
    catch (...)
    {
        return false;
    }
}

bool CTpmCryptoAES::DecryptIntChunked(const std::vector<BYTE>& encryptedData, int& valueOut)
{
    try
    {
        std::vector<BYTE> decrypted;
        if (!DecryptDataChunked(encryptedData, decrypted))
            return false;

        if (decrypted.size() != sizeof(int))
            return false;

        std::memcpy(&valueOut, decrypted.data(), sizeof(int));
        return true;
    }
    catch (...)
    {
        return false;
    }
}

bool CTpmCryptoAES::EncryptFloatChunked(float value, std::vector<BYTE>& encryptedOut)
{
    try
    {
        std::vector<BYTE> plain(sizeof(float));
        std::memcpy(plain.data(), &value, sizeof(float));
        return EncryptDataChunked(plain, encryptedOut);
    }
    catch (...)
    {
        return false;
    }
}

bool CTpmCryptoAES::DecryptFloatChunked(const std::vector<BYTE>& encryptedData, float& valueOut)
{
    try
    {
        std::vector<BYTE> decrypted;
        if (!DecryptDataChunked(encryptedData, decrypted))
            return false;

        if (decrypted.size() != sizeof(float))
            return false;

        std::memcpy(&valueOut, decrypted.data(), sizeof(float));
        return true;
    }
    catch (...)
    {
        return false;
    }
}

bool CTpmCryptoAES::EncryptDoubleChunked(double value, std::vector<BYTE>& encryptedOut)
{
    try
    {
        std::vector<BYTE> plain(sizeof(double));
        std::memcpy(plain.data(), &value, sizeof(double));
        return EncryptDataChunked(plain, encryptedOut);
    }
    catch (...)
    {
        return false;
    }
}

bool CTpmCryptoAES::DecryptDoubleChunked(const std::vector<BYTE>& encryptedData, double& valueOut)
{
    try
    {
        std::vector<BYTE> decrypted;
        if (!DecryptDataChunked(encryptedData, decrypted))
            return false;

        if (decrypted.size() != sizeof(double))
            return false;

        std::memcpy(&valueOut, decrypted.data(), sizeof(double));
        return true;
    }
    catch (...)
    {
        return false;
    }
}

bool CTpmCryptoAES::EncryptByteChunked(BYTE value, std::vector<BYTE>& encryptedOut)
{
    try
    {
        std::vector<BYTE> plain(1, value);
        return EncryptDataChunked(plain, encryptedOut);
    }
    catch (...)
    {
        return false;
    }
}

bool CTpmCryptoAES::DecryptByteChunked(const std::vector<BYTE>& encryptedData, BYTE& valueOut)
{
    try
    {
        std::vector<BYTE> decrypted;
        if (!DecryptDataChunked(encryptedData, decrypted))
            return false;

        if (decrypted.size() != 1)
            return false;

        valueOut = decrypted[0];
        return true;
    }
    catch (...)
    {
        return false;
    }
}

bool CTpmCryptoAES::EncryptCharChunked(char value, std::vector<BYTE>& encryptedOut)
{
    try
    {
        std::vector<BYTE> plain(1);
        plain[0] = static_cast<BYTE>(value);
        return EncryptDataChunked(plain, encryptedOut);
    }
    catch (...)
    {
        return false;
    }
}

bool CTpmCryptoAES::DecryptCharChunked(const std::vector<BYTE>& encryptedData, char& valueOut)
{
    try
    {
        std::vector<BYTE> decrypted;
        if (!DecryptDataChunked(encryptedData, decrypted))
            return false;

        if (decrypted.size() != 1)
            return false;

        valueOut = static_cast<char>(decrypted[0]);
        return true;
    }
    catch (...)
    {
        return false;
    }
}

bool CTpmCryptoAES::EncryptStringChunked(const std::string& str, std::vector<BYTE>& encryptedOut)
{
    try
    {
        const BYTE* data = reinterpret_cast<const BYTE*>(str.data());
        std::vector<BYTE> plain(data, data + str.size());
        return EncryptDataChunked(plain, encryptedOut);
    }
    catch (...)
    {
        return false;
    }
}

bool CTpmCryptoAES::DecryptStringChunked(const std::vector<BYTE>& encryptedData, std::string& strOut)
{
    try
    {
        std::vector<BYTE> decrypted;
        if (!DecryptDataChunked(encryptedData, decrypted))
            return false;

        strOut.assign(decrypted.begin(), decrypted.end());
        return true;
    }
    catch (...)
    {
        return false;
    }
}

bool CTpmCryptoAES::EncryptIntArrayChunked(const std::vector<int>& values, std::vector<BYTE>& encryptedOut)
{
    try
    {
        std::vector<BYTE> plain(values.size() * sizeof(int));
        std::memcpy(plain.data(), values.data(), plain.size());
        return EncryptDataChunked(plain, encryptedOut);
    }
    catch (...)
    {
        return false;
    }
}

bool CTpmCryptoAES::EncryptFloatArrayChunked(const std::vector<float>& values, std::vector<BYTE>& encryptedOut)
{
    try
    {
        std::vector<BYTE> plain(values.size() * sizeof(float));
        std::memcpy(plain.data(), values.data(), plain.size());
        return EncryptDataChunked(plain, encryptedOut);
    }
    catch (...)
    {
        return false;
    }
}
bool CTpmCryptoAES::EncryptDoubleArrayChunked(const std::vector<double>& values, std::vector<BYTE>& encryptedOut)
{
    try
    {
        std::vector<BYTE> plain(values.size() * sizeof(double));
        std::memcpy(plain.data(), values.data(), plain.size());
        return EncryptDataChunked(plain, encryptedOut);
    }
    catch (...)
    {
        return false;
    }
}
bool CTpmCryptoAES::EncryptByteArrayChunked(const std::vector<BYTE>& values, std::vector<BYTE>& encryptedOut)
{
    try
    {
        return EncryptDataChunked(values, encryptedOut);
    }
    catch (...)
    {
        return false;
    }
}
bool CTpmCryptoAES::EncryptCharArrayChunked(const std::vector<char>& values, std::vector<BYTE>& encryptedOut)
{
    try
    {
        std::vector<BYTE> plain(values.begin(), values.end());
        return EncryptDataChunked(plain, encryptedOut);
    }
    catch (...)
    {
        return false;
    }
}
bool CTpmCryptoAES::EncryptStringArrayChunked(const std::vector<std::string>& values, std::vector<BYTE>& encryptedOut)
{
    try
    {
        std::vector<BYTE> plain;

        for (const auto& str : values)
        {
            uint32_t len = static_cast<uint32_t>(str.size());
            plain.insert(plain.end(), reinterpret_cast<BYTE*>(&len), reinterpret_cast<BYTE*>(&len) + sizeof(len));
            plain.insert(plain.end(), str.begin(), str.end());
        }

        return EncryptDataChunked(plain, encryptedOut);
    }
    catch (...)
    {
        return false;
    }
}
bool CTpmCryptoAES::DecryptIntArrayChunked(const std::vector<BYTE>& encryptedData, std::vector<int>& valuesOut)
{
    try
    {
        std::vector<BYTE> decrypted;
        if (!DecryptDataChunked(encryptedData, decrypted))
            return false;

        if (decrypted.size() % sizeof(int) != 0)
            return false;

        size_t count = decrypted.size() / sizeof(int);
        valuesOut.resize(count);
        std::memcpy(valuesOut.data(), decrypted.data(), decrypted.size());
        return true;
    }
    catch (...)
    {
        return false;
    }
}
bool CTpmCryptoAES::DecryptFloatArrayChunked(const std::vector<BYTE>& encryptedData, std::vector<float>& valuesOut)
{
    try
    {
        std::vector<BYTE> decrypted;
        if (!DecryptDataChunked(encryptedData, decrypted))
            return false;

        if (decrypted.size() % sizeof(float) != 0)
            return false;

        size_t count = decrypted.size() / sizeof(float);
        valuesOut.resize(count);
        std::memcpy(valuesOut.data(), decrypted.data(), decrypted.size());
        return true;
    }
    catch (...)
    {
        return false;
    }
}
bool CTpmCryptoAES::DecryptDoubleArrayChunked(const std::vector<BYTE>& encryptedData, std::vector<double>& valuesOut)
{
    try
    {
        std::vector<BYTE> decrypted;
        if (!DecryptDataChunked(encryptedData, decrypted))
            return false;

        if (decrypted.size() % sizeof(double) != 0)
            return false;

        size_t count = decrypted.size() / sizeof(double);
        valuesOut.resize(count);
        std::memcpy(valuesOut.data(), decrypted.data(), decrypted.size());
        return true;
    }
    catch (...)
    {
        return false;
    }
}
bool CTpmCryptoAES::DecryptByteArrayChunked(const std::vector<BYTE>& encryptedData, std::vector<BYTE>& valuesOut)
{
    try
    {
        return DecryptDataChunked(encryptedData, valuesOut);
    }
    catch (...)
    {
        return false;
    }
}
bool CTpmCryptoAES::DecryptCharArrayChunked(const std::vector<BYTE>& encryptedData, std::vector<char>& valuesOut)
{
    try
    {
        std::vector<BYTE> decrypted;
        if (!DecryptDataChunked(encryptedData, decrypted))
            return false;

        valuesOut.assign(decrypted.begin(), decrypted.end());
        return true;
    }
    catch (...)
    {
        return false;
    }
}
bool CTpmCryptoAES::DecryptStringArrayChunked(const std::vector<BYTE>& encryptedData, std::vector<std::string>& valuesOut)
{
    try
    {
        std::vector<BYTE> decrypted;
        if (!DecryptDataChunked(encryptedData, decrypted))
            return false;

        valuesOut.clear();
        size_t pos = 0;

        while (pos + sizeof(uint32_t) <= decrypted.size())
        {
            uint32_t len = 0;
            std::memcpy(&len, &decrypted[pos], sizeof(uint32_t));
            pos += sizeof(uint32_t);

            if (pos + len > decrypted.size())
                return false;

            std::string str(decrypted.begin() + pos, decrypted.begin() + pos + len);
            valuesOut.push_back(str);
            pos += len;
        }

        return true;
    }
    catch (...)
    {
        return false;
    }
}

bool CTpmCryptoAES::EncryptIntWithPasswordChunked(const std::string& password, int value, std::vector<BYTE>& encryptedOut)
{
    try {
        std::vector<BYTE> plain(sizeof(int));
        std::memcpy(plain.data(), &value, sizeof(int));
        return EncryptDataWithPasswordChunked(password, plain, encryptedOut);
    }
    catch (...) {
        return false;
    }
}
bool CTpmCryptoAES::EncryptFloatWithPasswordChunked(const std::string& password, float value, std::vector<BYTE>& encryptedOut)
{
    try {
        std::vector<BYTE> plain(sizeof(float));
        std::memcpy(plain.data(), &value, sizeof(float));
        return EncryptDataWithPasswordChunked(password, plain, encryptedOut);
    }
    catch (...) {
        return false;
    }
}
bool CTpmCryptoAES::EncryptDoubleWithPasswordChunked(const std::string& password, double value, std::vector<BYTE>& encryptedOut)
{
    try {
        std::vector<BYTE> plain(sizeof(double));
        std::memcpy(plain.data(), &value, sizeof(double));
        return EncryptDataWithPasswordChunked(password, plain, encryptedOut);
    }
    catch (...) {
        return false;
    }
}
bool CTpmCryptoAES::EncryptByteWithPasswordChunked(const std::string& password, BYTE value, std::vector<BYTE>& encryptedOut)
{
    try {
        std::vector<BYTE> plain(1, value);
        return EncryptDataWithPasswordChunked(password, plain, encryptedOut);
    }
    catch (...) {
        return false;
    }
}
bool CTpmCryptoAES::EncryptCharWithPasswordChunked(const std::string& password, char value, std::vector<BYTE>& encryptedOut)
{
    try {
        std::vector<BYTE> plain(1, static_cast<BYTE>(value));
        return EncryptDataWithPasswordChunked(password, plain, encryptedOut);
    }
    catch (...) {
        return false;
    }
}
bool CTpmCryptoAES::EncryptStringWithPasswordChunked(const std::string& password, const std::string& str, std::vector<BYTE>& encryptedOut)
{
    try {
        const BYTE* data = reinterpret_cast<const BYTE*>(str.data());
        std::vector<BYTE> plain(data, data + str.size());
        return EncryptDataWithPasswordChunked(password, plain, encryptedOut);
    }
    catch (...) {
        return false;
    }
}
bool CTpmCryptoAES::DecryptIntWithPasswordChunked(const std::string& password, const std::vector<BYTE>& encryptedData, int& valueOut)
{
    try {
        std::vector<BYTE> decrypted;
        if (!DecryptDataWithPasswordChunked(password, encryptedData, decrypted) || decrypted.size() != sizeof(int))
            return false;
        std::memcpy(&valueOut, decrypted.data(), sizeof(int));
        return true;
    }
    catch (...) {
        return false;
    }
}
bool CTpmCryptoAES::DecryptFloatWithPasswordChunked(const std::string& password, const std::vector<BYTE>& encryptedData, float& valueOut)
{
    try {
        std::vector<BYTE> decrypted;
        if (!DecryptDataWithPasswordChunked(password, encryptedData, decrypted) || decrypted.size() != sizeof(float))
            return false;
        std::memcpy(&valueOut, decrypted.data(), sizeof(float));
        return true;
    }
    catch (...) {
        return false;
    }
}
bool CTpmCryptoAES::DecryptDoubleWithPasswordChunked(const std::string& password, const std::vector<BYTE>& encryptedData, double& valueOut)
{
    try {
        std::vector<BYTE> decrypted;
        if (!DecryptDataWithPasswordChunked(password, encryptedData, decrypted) || decrypted.size() != sizeof(double))
            return false;
        std::memcpy(&valueOut, decrypted.data(), sizeof(double));
        return true;
    }
    catch (...) {
        return false;
    }
}
bool CTpmCryptoAES::DecryptByteWithPasswordChunked(const std::string& password, const std::vector<BYTE>& encryptedData, BYTE& valueOut)
{
    try {
        std::vector<BYTE> decrypted;
        if (!DecryptDataWithPasswordChunked(password, encryptedData, decrypted) || decrypted.size() != 1)
            return false;
        valueOut = decrypted[0];
        return true;
    }
    catch (...) {
        return false;
    }
}
bool CTpmCryptoAES::DecryptCharWithPasswordChunked(const std::string& password, const std::vector<BYTE>& encryptedData, char& valueOut)
{
    try {
        std::vector<BYTE> decrypted;
        if (!DecryptDataWithPasswordChunked(password, encryptedData, decrypted) || decrypted.size() != 1)
            return false;
        valueOut = static_cast<char>(decrypted[0]);
        return true;
    }
    catch (...) {
        return false;
    }
}
bool CTpmCryptoAES::DecryptStringWithPasswordChunked(const std::string& password, const std::vector<BYTE>& encryptedData, std::string& strOut)
{
    try {
        std::vector<BYTE> decrypted;
        if (!DecryptDataWithPasswordChunked(password, encryptedData, decrypted))
            return false;
        strOut.assign(decrypted.begin(), decrypted.end());
        return true;
    }
    catch (...) {
        return false;
    }
}

bool CTpmCryptoAES::EncryptIntArrayWithPasswordChunked(const std::string& password, const std::vector<int>& values, std::vector<BYTE>& encryptedOut)
{
    try {
        std::vector<BYTE> plain(values.size() * sizeof(int));
        std::memcpy(plain.data(), values.data(), plain.size());
        return EncryptDataWithPasswordChunked(password, plain, encryptedOut);
    }
    catch (...) {
        return false;
    }
}
bool CTpmCryptoAES::EncryptFloatArrayWithPasswordChunked(const std::string& password, const std::vector<float>& values, std::vector<BYTE>& encryptedOut)
{
    try {
        std::vector<BYTE> plain(values.size() * sizeof(float));
        std::memcpy(plain.data(), values.data(), plain.size());
        return EncryptDataWithPasswordChunked(password, plain, encryptedOut);
    }
    catch (...) {
        return false;
    }
}
bool CTpmCryptoAES::EncryptDoubleArrayWithPasswordChunked(const std::string& password, const std::vector<double>& values, std::vector<BYTE>& encryptedOut)
{
    try {
        std::vector<BYTE> plain(values.size() * sizeof(double));
        std::memcpy(plain.data(), values.data(), plain.size());
        return EncryptDataWithPasswordChunked(password, plain, encryptedOut);
    }
    catch (...) {
        return false;
    }
}
bool CTpmCryptoAES::EncryptByteArrayWithPasswordChunked(const std::string& password, const std::vector<BYTE>& values, std::vector<BYTE>& encryptedOut)
{
    try {
        return EncryptDataWithPasswordChunked(password, values, encryptedOut);
    }
    catch (...) {
        return false;
    }
}
bool CTpmCryptoAES::EncryptCharArrayWithPasswordChunked(const std::string& password, const std::vector<char>& values, std::vector<BYTE>& encryptedOut)
{
    try {
        std::vector<BYTE> plain(values.begin(), values.end());
        return EncryptDataWithPasswordChunked(password, plain, encryptedOut);
    }
    catch (...) {
        return false;
    }
}
bool CTpmCryptoAES::EncryptStringArrayWithPasswordChunked(const std::string& password, const std::vector<std::string>& values, std::vector<BYTE>& encryptedOut)
{
    try {
        std::vector<BYTE> plain;

        for (const auto& str : values)
        {
            uint32_t len = static_cast<uint32_t>(str.size());
            plain.insert(plain.end(), reinterpret_cast<BYTE*>(&len), reinterpret_cast<BYTE*>(&len) + sizeof(len));
            plain.insert(plain.end(), str.begin(), str.end());
        }

        return EncryptDataWithPasswordChunked(password, plain, encryptedOut);
    }
    catch (...) {
        return false;
    }
}
bool CTpmCryptoAES::DecryptIntArrayWithPasswordChunked(const std::string& password, const std::vector<BYTE>& encryptedData, std::vector<int>& valuesOut)
{
    try {
        std::vector<BYTE> decrypted;
        if (!DecryptDataWithPasswordChunked(password, encryptedData, decrypted) || decrypted.size() % sizeof(int) != 0)
            return false;

        size_t count = decrypted.size() / sizeof(int);
        valuesOut.resize(count);
        std::memcpy(valuesOut.data(), decrypted.data(), decrypted.size());
        return true;
    }
    catch (...) {
        return false;
    }
}
bool CTpmCryptoAES::DecryptFloatArrayWithPasswordChunked(const std::string& password, const std::vector<BYTE>& encryptedData, std::vector<float>& valuesOut)
{
    try {
        std::vector<BYTE> decrypted;
        if (!DecryptDataWithPasswordChunked(password, encryptedData, decrypted) || decrypted.size() % sizeof(float) != 0)
            return false;

        size_t count = decrypted.size() / sizeof(float);
        valuesOut.resize(count);
        std::memcpy(valuesOut.data(), decrypted.data(), decrypted.size());
        return true;
    }
    catch (...) {
        return false;
    }
}
bool CTpmCryptoAES::DecryptDoubleArrayWithPasswordChunked(const std::string& password, const std::vector<BYTE>& encryptedData, std::vector<double>& valuesOut)
{
    try {
        std::vector<BYTE> decrypted;
        if (!DecryptDataWithPasswordChunked(password, encryptedData, decrypted) || decrypted.size() % sizeof(double) != 0)
            return false;

        size_t count = decrypted.size() / sizeof(double);
        valuesOut.resize(count);
        std::memcpy(valuesOut.data(), decrypted.data(), decrypted.size());
        return true;
    }
    catch (...) {
        return false;
    }
}
bool CTpmCryptoAES::DecryptByteArrayWithPasswordChunked(const std::string& password, const std::vector<BYTE>& encryptedData, std::vector<BYTE>& valuesOut)
{
    try {
        return DecryptDataWithPasswordChunked(password, encryptedData, valuesOut);
    }
    catch (...) {
        return false;
    }
}
bool CTpmCryptoAES::DecryptCharArrayWithPasswordChunked(const std::string& password, const std::vector<BYTE>& encryptedData, std::vector<char>& valuesOut)
{
    try {
        std::vector<BYTE> decrypted;
        if (!DecryptDataWithPasswordChunked(password, encryptedData, decrypted))
            return false;

        valuesOut.assign(decrypted.begin(), decrypted.end());
        return true;
    }
    catch (...) {
        return false;
    }
}
bool CTpmCryptoAES::DecryptStringArrayWithPasswordChunked(const std::string& password, const std::vector<BYTE>& encryptedData, std::vector<std::string>& valuesOut)
{
    try {
        std::vector<BYTE> decrypted;
        if (!DecryptDataWithPasswordChunked(password, encryptedData, decrypted))
            return false;

        valuesOut.clear();
        size_t pos = 0;

        while (pos + sizeof(uint32_t) <= decrypted.size())
        {
            uint32_t len = 0;
            std::memcpy(&len, &decrypted[pos], sizeof(uint32_t));
            pos += sizeof(uint32_t);

            if (pos + len > decrypted.size())
                return false;

            std::string str(decrypted.begin() + pos, decrypted.begin() + pos + len);
            valuesOut.push_back(str);
            pos += len;
        }

        return true;
    }
    catch (...) {
        return false;
    }
}
