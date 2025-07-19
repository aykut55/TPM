#include "TpmCryptoRSA.h"

#include <string>       // std::string
#include <iostream>     // std::cout
#include <sstream>      // std::stringstream
#include <fstream>      // std::ofstream
#include <vector>       // ...

#define null  {}

CTpmCryptoRSA::~CTpmCryptoRSA()
{
    try
    {
        if (m_keyHandle != TPM_RH_NULL)
            tpm->FlushContext(m_keyHandle);
    }
    catch (...)
    {
        std::stringstream ss;
        ss << "Destructor unknown exception." << std::endl;
        Log(ss.str(), true);
    }
}

CTpmCryptoRSA::CTpmCryptoRSA(CTpmSharedDevice* sharedDevice)
    : m_useSharedTpmDevice(sharedDevice != nullptr), m_sharedTpmDevice(sharedDevice)
{
    try
    {
        if (m_useSharedTpmDevice)
        {
            m_sharedTpmDevice = sharedDevice;
            std::stringstream ss;
            ss << "[CTpmCryptoRSA] uses shared CTpmSharedDevice\n";
            Log(ss.str());
        }
        else
        {
            m_sharedTpmDevice = new CTpmSharedDevice();
            std::stringstream ss;
            ss << "[CTpmCryptoRSA] uses local  CTpmSharedDevice\n";
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

CTpmSharedDevice* CTpmCryptoRSA::GetTpmSharedDevice(void)
{
    return m_sharedTpmDevice;
}

bool CTpmCryptoRSA::Release(void)
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

bool CTpmCryptoRSA::Initialize(void)
{
    bool fncReturn = false;

    try
    {
        return true;
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

bool CTpmCryptoRSA::EncryptDataChunked(const std::vector<BYTE>& plain, std::vector<BYTE>& encrypted)
{
    encrypted.clear();
    if (!EnsureRsaKeyLoaded())
        return false;

    const size_t keySizeBytes = 256; // 2048-bit RSA
    const size_t maxChunkSize = keySizeBytes - 11; // PKCS1 padding overhead

    try
    {
#if 0
        for (size_t i = 0; i < plain.size(); i += maxChunkSize)
        {
            size_t chunkSize = std::min(maxChunkSize, plain.size() - i);
            std::vector<BYTE> chunk(plain.begin() + i, plain.begin() + i + chunkSize);
            std::vector<BYTE> encChunk = tpm->RSA_Encrypt(m_rsaKeyHandle, chunk, TPMS_NULL_ASYM_SCHEME(), {});
            encrypted.insert(encrypted.end(), encChunk.begin(), encChunk.end());
        }
#else
        std::vector<BYTE> formattedInput = AddLengthPrefix(plain);
        for (size_t i = 0; i < formattedInput.size(); i += maxChunkSize)
        {
            size_t chunkSize = std::min(maxChunkSize, formattedInput.size() - i);
            std::vector<BYTE> chunk(formattedInput.begin() + i, formattedInput.begin() + i + chunkSize);
            std::vector<BYTE> encChunk = tpm->RSA_Encrypt(m_rsaKeyHandle, chunk, TPMS_NULL_ASYM_SCHEME(), {});
            encrypted.insert(encrypted.end(), encChunk.begin(), encChunk.end());
        }
#endif

        return true;
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[CTpmCryptoRSA] EncryptDataChunked exception: " << ex.what() << std::endl;
        return false;
    }
}

bool CTpmCryptoRSA::DecryptDataChunked(const std::vector<BYTE>& encrypted, std::vector<BYTE>& plain)
{
    plain.clear();
    if (!EnsureRsaKeyLoaded())
        return false;

    const size_t keySizeBytes = 256; // RSA-2048 block size

    try
    {
#if 0
        for (size_t i = 0; i < encrypted.size(); i += keySizeBytes)
        {
            if (i + keySizeBytes > encrypted.size())
            {
                std::cerr << "[CTpmCryptoRSA] DecryptDataChunked: Incomplete block\n";
                return false;
            }

            std::vector<BYTE> chunk(encrypted.begin() + i, encrypted.begin() + i + keySizeBytes);
            std::vector<BYTE> decChunk = tpm->RSA_Decrypt(m_rsaKeyHandle, chunk, TPMS_NULL_ASYM_SCHEME(), {});
            plain.insert(plain.end(), decChunk.begin(), decChunk.end());
        }
#else
        std::vector<BYTE> decryptedRaw;
        for (size_t i = 0; i < encrypted.size(); i += keySizeBytes)
        {
            if (i + keySizeBytes > encrypted.size())
            {
                std::cerr << "[CTpmCryptoRSA] DecryptDataChunked: Incomplete block\n";
                return false;
            }

            std::vector<BYTE> chunk(encrypted.begin() + i, encrypted.begin() + i + keySizeBytes);
            std::vector<BYTE> decChunk = tpm->RSA_Decrypt(m_rsaKeyHandle, chunk, TPMS_NULL_ASYM_SCHEME(), {});
            decryptedRaw.insert(decryptedRaw.end(), decChunk.begin(), decChunk.end());
        }
        RemoveLengthPrefix(decryptedRaw, plain);
#endif

        return true;
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[CTpmCryptoRSA] DecryptDataChunked exception: " << ex.what() << std::endl;
        return false;
    }
}

bool CTpmCryptoRSA::EncryptData(const std::vector<BYTE>& plain, std::vector<BYTE>& encrypted)
{
    try
    {
        if (plain.empty())
        {
            m_lastError = "EncryptData: input is empty.";
            return false;
        }

        std::vector<BYTE> formattedInput = AddLengthPrefix(plain);
        return EncryptDecryptInternal(formattedInput, encrypted, true); // true = encrypt
    }
    catch (const std::exception& ex)
    {
        m_lastError = std::string("EncryptData exception: ") + ex.what();
        return false;
    }
}

bool CTpmCryptoRSA::DecryptData(const std::vector<BYTE>& encrypted, std::vector<BYTE>& plain)
{
    try
    {
        if (encrypted.empty())
        {
            m_lastError = "DecryptData: input is empty.";
            return false;
        }

        std::vector<BYTE> decryptedRaw;
        if (!EncryptDecryptInternal(encrypted, decryptedRaw, false))// false = decrypt
            return false;

        return RemoveLengthPrefix(decryptedRaw, plain);
    }
    catch (const std::exception& ex)
    {
        m_lastError = std::string("DecryptData exception: ") + ex.what();
        return false;
    }
}

bool CTpmCryptoRSA::EncryptDecryptInternal(const std::vector<BYTE>& inData, std::vector<BYTE>& outData, bool encrypt)
{
    if (!EnsureRsaKeyLoaded())
        return false;

    try
    {
        if (encrypt)
        {
            outData = tpm->RSA_Encrypt(m_rsaKeyHandle, inData, TPMS_NULL_ASYM_SCHEME(), {});
        }
        else
        {
            outData = tpm->RSA_Decrypt(m_rsaKeyHandle, inData, TPMS_NULL_ASYM_SCHEME(), {});
        }

        return true;
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[CTpmCryptoRSA] EncryptDecryptInternal exception: " << ex.what() << std::endl;
        return false;
    }
}

// ***********************************************************************************************************************

bool CTpmCryptoRSA::EncryptDataWithPasswordChunked(
    const std::string& password,
    const std::vector<BYTE>& plain,
    std::vector<BYTE>& encrypted)
{
    // Bu örnekte chunk yapılmıyor çünkü RSA tek seferde sınırlı veri şifreler
    // Gerekirse ileri aşamada parçalı hale getirilebilir (örneğin AES ile hybrid sistem)
    return EncryptDataWithPassword(password, plain, encrypted);
}

bool CTpmCryptoRSA::DecryptDataWithPasswordChunked(
    const std::string& password,
    const std::vector<BYTE>& encrypted,
    std::vector<BYTE>& plain)
{
    // Aynı şekilde tek parça RSA çözme işlemi yapılıyor
    return DecryptDataWithPassword(password, encrypted, plain);
}

bool CTpmCryptoRSA::EncryptDataWithPassword(
    const std::string& password,
    const std::vector<BYTE>& plain,
    std::vector<BYTE>& encrypted)
{
    // 1. RSA anahtar mevcut mu?
    if (!m_keyLoaded)
    {
        m_lastError = "EncryptDataWithPassword: RSA key is not loaded.";
        return false;
    }

    // 2. Kullanıcı parolasını m_currentAuthValue olarak kaydet
    m_currentAuthValue.assign(password.begin(), password.end());

    // 3. Şifreleme işlemini gerçekleştir
    return EncryptDecryptInternalWithPassword(password, plain, encrypted, true);
}

bool CTpmCryptoRSA::DecryptDataWithPassword(
    const std::string& password,
    const std::vector<BYTE>& encrypted,
    std::vector<BYTE>& plain)
{
    // 1. RSA anahtar yüklü mü?
    if (!m_keyLoaded)
    {
        m_lastError = "DecryptDataWithPassword: RSA key is not loaded.";
        return false;
    }

    // 2. Kullanıcı parolasını kaydet
    m_currentAuthValue.assign(password.begin(), password.end());

    // 3. Decryption işlemini gerçekleştir
    return EncryptDecryptInternalWithPassword(password, encrypted, plain, false);
}

bool CTpmCryptoRSA::EncryptDecryptInternalWithPassword(
    const std::string& password,
    const std::vector<BYTE>& inData,
    std::vector<BYTE>& outData,
    bool encrypt)
{
    try
    {
        // 1. RSA için parola, key oluşturulurken authValue olarak kullanılır
        std::vector<BYTE> authValue(password.begin(), password.end());

        // 2. Şifreleme mi? Şifre çözme mi?
        if (encrypt)
        {
            // --- Şifreleme (Public Key ile) ---
            TPMT_PUBLIC publicTemplate(
                TPM_ALG_ID::SHA256,
                TPMA_OBJECT::decrypt | TPMA_OBJECT::fixedTPM | TPMA_OBJECT::fixedParent | TPMA_OBJECT::userWithAuth,
                {},
                TPMS_RSA_PARMS(
                    TPMT_SYM_DEF_OBJECT(),
                    TPMS_NULL_ASYM_SCHEME(),
                    2048,
                    0
                ),
                TPM2B_PUBLIC_KEY_RSA()
            );

            TPMS_SENSITIVE_CREATE sensCreate({}, authValue);

            // Geçici key oluştur
            auto rsaKey = tpm->CreatePrimary(
                TPM_RH::OWNER,
                sensCreate,
                publicTemplate,
                {},
                {}
            );

            auto cipher = tpm->RSA_Encrypt(
                rsaKey.handle,
                inData,
                TPMS_NULL_ASYM_SCHEME(),
                {}
            );

            outData = cipher;
            tpm->FlushContext(rsaKey.handle);
        }
        else
        {
            // --- Şifre Çözme (Private Key ile) ---
            TPMT_PUBLIC privateTemplate(
                TPM_ALG_ID::SHA256,
                TPMA_OBJECT::decrypt | TPMA_OBJECT::fixedTPM | TPMA_OBJECT::fixedParent | TPMA_OBJECT::userWithAuth | TPMA_OBJECT::sensitiveDataOrigin,
                {},
                TPMS_RSA_PARMS(
                    TPMT_SYM_DEF_OBJECT(),
                    TPMS_NULL_ASYM_SCHEME(),
                    2048,
                    0
                ),
                TPM2B_PUBLIC_KEY_RSA()
            );

            TPMS_SENSITIVE_CREATE sensCreate({}, authValue);

            auto rsaKey = tpm->CreatePrimary(
                TPM_RH::OWNER,
                sensCreate,
                privateTemplate,
                {},
                {}
            );

            auto plain = tpm->RSA_Decrypt(
                rsaKey.handle,
                inData,
                TPMS_NULL_ASYM_SCHEME(),
                {}
            );

            outData = plain;
            tpm->FlushContext(rsaKey.handle);
        }

        return true;
    }
    catch (const std::exception& ex)
    {
        m_lastError = std::string("EncryptDecryptInternalWithPassword exception: ") + ex.what();
        return false;
    }
    catch (...)
    {
        m_lastError = "EncryptDecryptInternalWithPassword unknown exception.";
        return false;
    }
}

// ***********************************************************************************************************************

bool CTpmCryptoRSA::EncryptByte(BYTE value, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> plain = { value };
    return EncryptData(plain, encryptedOut);
}

bool CTpmCryptoRSA::EncryptChar(char value, std::vector<BYTE>& encryptedOut)
{
    return EncryptByte(static_cast<BYTE>(value), encryptedOut);
}

bool CTpmCryptoRSA::EncryptInt(int value, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> plain(sizeof(int));
    std::memcpy(plain.data(), &value, sizeof(int));
    return EncryptData(plain, encryptedOut);
}

bool CTpmCryptoRSA::EncryptFloat(float value, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> plain(sizeof(float));
    std::memcpy(plain.data(), &value, sizeof(float));
    return EncryptData(plain, encryptedOut);
}

bool CTpmCryptoRSA::EncryptDouble(double value, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> plain(sizeof(double));
    std::memcpy(plain.data(), &value, sizeof(double));
    return EncryptData(plain, encryptedOut);
}

bool CTpmCryptoRSA::EncryptString(const std::string& str, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> plain(str.begin(), str.end());
    return EncryptData(plain, encryptedOut);
}

bool CTpmCryptoRSA::DecryptByte(const std::vector<BYTE>& encryptedData, BYTE& valueOut)
{
    std::vector<BYTE> plain;
    if (!DecryptData(encryptedData, plain) || plain.size() != 1)
        return false;
    valueOut = plain[0];
    return true;
}

bool CTpmCryptoRSA::DecryptChar(const std::vector<BYTE>& encryptedData, char& valueOut)
{
    BYTE byteVal = 0;
    if (!DecryptByte(encryptedData, byteVal))
        return false;
    valueOut = static_cast<char>(byteVal);
    return true;
}

bool CTpmCryptoRSA::DecryptInt(const std::vector<BYTE>& encryptedData, int& valueOut)
{
    std::vector<BYTE> plain;
    if (!DecryptData(encryptedData, plain) || plain.size() != sizeof(int))
        return false;
    std::memcpy(&valueOut, plain.data(), sizeof(int));
    return true;
}

bool CTpmCryptoRSA::DecryptFloat(const std::vector<BYTE>& encryptedData, float& valueOut)
{
    std::vector<BYTE> plain;
    if (!DecryptData(encryptedData, plain) || plain.size() != sizeof(float))
        return false;
    std::memcpy(&valueOut, plain.data(), sizeof(float));
    return true;
}

bool CTpmCryptoRSA::DecryptDouble(const std::vector<BYTE>& encryptedData, double& valueOut)
{
    std::vector<BYTE> plain;
    if (!DecryptData(encryptedData, plain) || plain.size() != sizeof(double))
        return false;
    std::memcpy(&valueOut, plain.data(), sizeof(double));
    return true;
}

bool CTpmCryptoRSA::DecryptString(const std::vector<BYTE>& encryptedData, std::string& strOut)
{
    std::vector<BYTE> plain;
    if (!DecryptData(encryptedData, plain))
        return false;
    strOut.assign(plain.begin(), plain.end());
    return true;
}









bool CTpmCryptoRSA::EncryptByteArray(const std::vector<BYTE>& values, std::vector<BYTE>& encryptedOut)
{
    return EncryptData(values, encryptedOut);
}

bool CTpmCryptoRSA::EncryptCharArray(const std::vector<char>& values, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> plain(values.begin(), values.end());
    return EncryptData(plain, encryptedOut);
}

bool CTpmCryptoRSA::EncryptIntArray(const std::vector<int>& values, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> plain(values.size() * sizeof(int));
    std::memcpy(plain.data(), values.data(), plain.size());
    return EncryptData(plain, encryptedOut);
}

bool CTpmCryptoRSA::EncryptFloatArray(const std::vector<float>& values, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> plain(values.size() * sizeof(float));
    std::memcpy(plain.data(), values.data(), plain.size());
    return EncryptData(plain, encryptedOut);
}

bool CTpmCryptoRSA::EncryptDoubleArray(const std::vector<double>& values, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> plain(values.size() * sizeof(double));
    std::memcpy(plain.data(), values.data(), plain.size());
    return EncryptData(plain, encryptedOut);
}

bool CTpmCryptoRSA::EncryptStringArray(const std::vector<std::string>& values, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> plain;
    for (const auto& str : values)
    {
        uint32_t len = static_cast<uint32_t>(str.size());
        plain.insert(plain.end(), reinterpret_cast<BYTE*>(&len), reinterpret_cast<BYTE*>(&len) + sizeof(uint32_t));
        plain.insert(plain.end(), str.begin(), str.end());
    }
    return EncryptData(plain, encryptedOut);
}

bool CTpmCryptoRSA::DecryptByteArray(const std::vector<BYTE>& encryptedData, std::vector<BYTE>& valuesOut)
{
    return DecryptData(encryptedData, valuesOut);
}

bool CTpmCryptoRSA::DecryptCharArray(const std::vector<BYTE>& encryptedData, std::vector<char>& valuesOut)
{
    std::vector<BYTE> plain;
    if (!DecryptData(encryptedData, plain))
        return false;

    valuesOut.assign(plain.begin(), plain.end());
    return true;
}

bool CTpmCryptoRSA::DecryptIntArray(const std::vector<BYTE>& encryptedData, std::vector<int>& valuesOut)
{
    std::vector<BYTE> plain;
    if (!DecryptData(encryptedData, plain) || plain.size() % sizeof(int) != 0)
        return false;

    size_t count = plain.size() / sizeof(int);
    valuesOut.resize(count);
    std::memcpy(valuesOut.data(), plain.data(), plain.size());
    return true;
}

bool CTpmCryptoRSA::DecryptFloatArray(const std::vector<BYTE>& encryptedData, std::vector<float>& valuesOut)
{
    std::vector<BYTE> plain;
    if (!DecryptData(encryptedData, plain) || plain.size() % sizeof(float) != 0)
        return false;

    size_t count = plain.size() / sizeof(float);
    valuesOut.resize(count);
    std::memcpy(valuesOut.data(), plain.data(), plain.size());
    return true;
}

bool CTpmCryptoRSA::DecryptDoubleArray(const std::vector<BYTE>& encryptedData, std::vector<double>& valuesOut)
{
    std::vector<BYTE> plain;
    if (!DecryptData(encryptedData, plain) || plain.size() % sizeof(double) != 0)
        return false;

    size_t count = plain.size() / sizeof(double);
    valuesOut.resize(count);
    std::memcpy(valuesOut.data(), plain.data(), plain.size());
    return true;
}

bool CTpmCryptoRSA::DecryptStringArray(const std::vector<BYTE>& encryptedData, std::vector<std::string>& valuesOut)
{
    std::vector<BYTE> plain;
    if (!DecryptData(encryptedData, plain))
        return false;

    size_t pos = 0;
    valuesOut.clear();

    while (pos + sizeof(uint32_t) <= plain.size())
    {
        uint32_t len = 0;
        std::memcpy(&len, plain.data() + pos, sizeof(uint32_t));
        pos += sizeof(uint32_t);

        if (pos + len > plain.size())
            return false;

        std::string str(plain.begin() + pos, plain.begin() + pos + len);
        valuesOut.push_back(str);
        pos += len;
    }

    return true;
}







bool CTpmCryptoRSA::EncryptFile(const std::string& inputFile, const std::string& outputFile)
{
    std::ifstream in(inputFile, std::ios::binary);
    if (!in)
    {
        m_lastError = "EncryptFile: Failed to open input file: " + inputFile;
        return false;
    }

    std::vector<BYTE> inputData((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();

    std::vector<BYTE> encryptedData;
    if (!EncryptData(inputData, encryptedData))
    {
        m_lastError = "EncryptFile: EncryptData failed.";
        return false;
    }

    std::ofstream out(outputFile, std::ios::binary);
    if (!out)
    {
        m_lastError = "EncryptFile: Failed to open output file: " + outputFile;
        return false;
    }

    out.write(reinterpret_cast<const char*>(encryptedData.data()), encryptedData.size());
    return true;
}

bool CTpmCryptoRSA::DecryptFile(const std::string& inputFile, const std::string& outputFile)
{
    std::ifstream in(inputFile, std::ios::binary);
    if (!in)
    {
        m_lastError = "DecryptFile: Failed to open input file: " + inputFile;
        return false;
    }

    std::vector<BYTE> encryptedData((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();

    std::vector<BYTE> plainData;
    if (!DecryptData(encryptedData, plainData))
    {
        m_lastError = "DecryptFile: DecryptData failed.";
        return false;
    }

    std::ofstream out(outputFile, std::ios::binary);
    if (!out)
    {
        m_lastError = "DecryptFile: Failed to open output file: " + outputFile;
        return false;
    }

    out.write(reinterpret_cast<const char*>(plainData.data()), plainData.size());
    return true;
}

bool CTpmCryptoRSA::EncryptIntChunked(int value, std::vector<BYTE>& encryptedOut)
{
    const BYTE* dataPtr = reinterpret_cast<const BYTE*>(&value);
    std::vector<BYTE> plain(dataPtr, dataPtr + sizeof(int));
    return EncryptDataChunked(plain, encryptedOut);
}

bool CTpmCryptoRSA::EncryptFloatChunked(float value, std::vector<BYTE>& encryptedOut)
{
    const BYTE* dataPtr = reinterpret_cast<const BYTE*>(&value);
    std::vector<BYTE> plain(dataPtr, dataPtr + sizeof(float));
    return EncryptDataChunked(plain, encryptedOut);
}

bool CTpmCryptoRSA::EncryptDoubleChunked(double value, std::vector<BYTE>& encryptedOut)
{
    const BYTE* dataPtr = reinterpret_cast<const BYTE*>(&value);
    std::vector<BYTE> plain(dataPtr, dataPtr + sizeof(double));
    return EncryptDataChunked(plain, encryptedOut);
}

bool CTpmCryptoRSA::EncryptByteChunked(BYTE value, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> plain = { value };
    return EncryptDataChunked(plain, encryptedOut);
}

bool CTpmCryptoRSA::EncryptCharChunked(char value, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> plain = { static_cast<BYTE>(value) };
    return EncryptDataChunked(plain, encryptedOut);
}

bool CTpmCryptoRSA::EncryptStringChunked(const std::string& str, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> plain(str.begin(), str.end());
    return EncryptDataChunked(plain, encryptedOut);
}

bool CTpmCryptoRSA::DecryptIntChunked(const std::vector<BYTE>& encryptedData, int& valueOut)
{
    std::vector<BYTE> plain;
    if (!DecryptDataChunked(encryptedData, plain) || plain.size() != sizeof(int))
        return false;

    valueOut = *reinterpret_cast<const int*>(plain.data());
    return true;
}

bool CTpmCryptoRSA::DecryptFloatChunked(const std::vector<BYTE>& encryptedData, float& valueOut)
{
    std::vector<BYTE> plain;
    if (!DecryptDataChunked(encryptedData, plain) || plain.size() != sizeof(float))
        return false;

    valueOut = *reinterpret_cast<const float*>(plain.data());
    return true;
}

bool CTpmCryptoRSA::DecryptDoubleChunked(const std::vector<BYTE>& encryptedData, double& valueOut)
{
    std::vector<BYTE> plain;
    if (!DecryptDataChunked(encryptedData, plain) || plain.size() != sizeof(double))
        return false;

    valueOut = *reinterpret_cast<const double*>(plain.data());
    return true;
}

bool CTpmCryptoRSA::DecryptByteChunked(const std::vector<BYTE>& encryptedData, BYTE& valueOut)
{
    std::vector<BYTE> plain;
    if (!DecryptDataChunked(encryptedData, plain) || plain.size() != sizeof(BYTE))
        return false;

    valueOut = plain[0];
    return true;
}

bool CTpmCryptoRSA::DecryptCharChunked(const std::vector<BYTE>& encryptedData, char& valueOut)
{
    std::vector<BYTE> plain;
    if (!DecryptDataChunked(encryptedData, plain) || plain.size() != sizeof(char))
        return false;

    valueOut = static_cast<char>(plain[0]);
    return true;
}

bool CTpmCryptoRSA::DecryptStringChunked(const std::vector<BYTE>& encryptedData, std::string& strOut)
{
    std::vector<BYTE> plain;
    if (!DecryptDataChunked(encryptedData, plain))
        return false;

    strOut.assign(plain.begin(), plain.end());
    return true;
}


bool CTpmCryptoRSA::EncryptIntArrayChunked(const std::vector<int>& values, std::vector<BYTE>& encryptedOut)
{
    const BYTE* data = reinterpret_cast<const BYTE*>(values.data());
    return EncryptDataChunked(std::vector<BYTE>(data, data + values.size() * sizeof(int)), encryptedOut);
}

bool CTpmCryptoRSA::EncryptFloatArrayChunked(const std::vector<float>& values, std::vector<BYTE>& encryptedOut)
{
    const BYTE* data = reinterpret_cast<const BYTE*>(values.data());
    return EncryptDataChunked(std::vector<BYTE>(data, data + values.size() * sizeof(float)), encryptedOut);
}

bool CTpmCryptoRSA::EncryptDoubleArrayChunked(const std::vector<double>& values, std::vector<BYTE>& encryptedOut)
{
    const BYTE* data = reinterpret_cast<const BYTE*>(values.data());
    return EncryptDataChunked(std::vector<BYTE>(data, data + values.size() * sizeof(double)), encryptedOut);
}

bool CTpmCryptoRSA::EncryptByteArrayChunked(const std::vector<BYTE>& values, std::vector<BYTE>& encryptedOut)
{
    return EncryptDataChunked(values, encryptedOut);
}

bool CTpmCryptoRSA::EncryptCharArrayChunked(const std::vector<char>& values, std::vector<BYTE>& encryptedOut)
{
    const BYTE* data = reinterpret_cast<const BYTE*>(values.data());
    return EncryptDataChunked(std::vector<BYTE>(data, data + values.size() * sizeof(char)), encryptedOut);
}

bool CTpmCryptoRSA::EncryptStringArrayChunked(const std::vector<std::string>& values, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> combined;
    for (const auto& str : values)
    {
        uint32_t len = static_cast<uint32_t>(str.size());
        const BYTE* lenPtr = reinterpret_cast<const BYTE*>(&len);
        combined.insert(combined.end(), lenPtr, lenPtr + sizeof(uint32_t));
        combined.insert(combined.end(), str.begin(), str.end());
    }
    return EncryptDataChunked(combined, encryptedOut);
}

bool CTpmCryptoRSA::DecryptIntArrayChunked(const std::vector<BYTE>& encryptedData, std::vector<int>& valuesOut)
{
    std::vector<BYTE> plain;
    if (!DecryptDataChunked(encryptedData, plain) || plain.size() % sizeof(int) != 0)
        return false;

    valuesOut.resize(plain.size() / sizeof(int));
    memcpy(valuesOut.data(), plain.data(), plain.size());
    return true;
}

bool CTpmCryptoRSA::DecryptFloatArrayChunked(const std::vector<BYTE>& encryptedData, std::vector<float>& valuesOut)
{
    std::vector<BYTE> plain;
    if (!DecryptDataChunked(encryptedData, plain) || plain.size() % sizeof(float) != 0)
        return false;

    valuesOut.resize(plain.size() / sizeof(float));
    memcpy(valuesOut.data(), plain.data(), plain.size());
    return true;
}

bool CTpmCryptoRSA::DecryptDoubleArrayChunked(const std::vector<BYTE>& encryptedData, std::vector<double>& valuesOut)
{
    std::vector<BYTE> plain;
    if (!DecryptDataChunked(encryptedData, plain) || plain.size() % sizeof(double) != 0)
        return false;

    valuesOut.resize(plain.size() / sizeof(double));
    memcpy(valuesOut.data(), plain.data(), plain.size());
    return true;
}

bool CTpmCryptoRSA::DecryptByteArrayChunked(const std::vector<BYTE>& encryptedData, std::vector<BYTE>& valuesOut)
{
    return DecryptDataChunked(encryptedData, valuesOut);
}

bool CTpmCryptoRSA::DecryptCharArrayChunked(const std::vector<BYTE>& encryptedData, std::vector<char>& valuesOut)
{
    std::vector<BYTE> plain;
    if (!DecryptDataChunked(encryptedData, plain))
        return false;

    valuesOut.assign(plain.begin(), plain.end());
    return true;
}

bool CTpmCryptoRSA::DecryptStringArrayChunked(const std::vector<BYTE>& encryptedData, std::vector<std::string>& valuesOut)
{
    std::vector<BYTE> plain;
    if (!DecryptDataChunked(encryptedData, plain))
        return false;

    valuesOut.clear();
    size_t offset = 0;
    while (offset + sizeof(uint32_t) <= plain.size())
    {
        uint32_t len = *reinterpret_cast<const uint32_t*>(&plain[offset]);
        offset += sizeof(uint32_t);
        if (offset + len > plain.size()) return false;

        valuesOut.emplace_back(plain.begin() + offset, plain.begin() + offset + len);
        offset += len;
    }

    return true;
}


bool CTpmCryptoRSA::EncryptFileChunked(const std::string& inputFile, const std::string& outputFile, size_t chunkSize)
{
    std::ifstream in(inputFile, std::ios::binary);
    std::ofstream out(outputFile, std::ios::binary);

    if (!in || !out)
    {
        m_lastError = "EncryptFileChunked: Cannot open input or output file.";
        return false;
    }

    std::vector<BYTE> buffer(chunkSize);
    while (in)
    {
        in.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(chunkSize));
        std::streamsize bytesRead = in.gcount();
        if (bytesRead <= 0)
            break;

        std::vector<BYTE> chunk(buffer.begin(), buffer.begin() + bytesRead);
        std::vector<BYTE> encryptedChunk;

        if (!EncryptDataChunked(chunk, encryptedChunk))
        {
            m_lastError = "EncryptFileChunked: EncryptDataChunked failed.";
            return false;
        }

        uint32_t chunkLen = static_cast<uint32_t>(encryptedChunk.size());
        out.write(reinterpret_cast<const char*>(&chunkLen), sizeof(chunkLen));
        out.write(reinterpret_cast<const char*>(encryptedChunk.data()), chunkLen);
    }

    return true;
}

bool CTpmCryptoRSA::DecryptFileChunked(const std::string& inputFile, const std::string& outputFile)
{
    std::ifstream in(inputFile, std::ios::binary);
    std::ofstream out(outputFile, std::ios::binary);

    if (!in || !out)
    {
        m_lastError = "DecryptFileChunked: Cannot open input or output file.";
        return false;
    }

    while (in)
    {
        uint32_t chunkLen = 0;
        in.read(reinterpret_cast<char*>(&chunkLen), sizeof(chunkLen));
        if (in.gcount() != sizeof(chunkLen))
            break;

        std::vector<BYTE> encryptedChunk(chunkLen);
        in.read(reinterpret_cast<char*>(encryptedChunk.data()), chunkLen);
        if (in.gcount() != static_cast<std::streamsize>(chunkLen))
        {
            m_lastError = "DecryptFileChunked: Failed to read encrypted chunk.";
            return false;
        }

        std::vector<BYTE> decryptedChunk;
        if (!DecryptDataChunked(encryptedChunk, decryptedChunk))
        {
            m_lastError = "DecryptFileChunked: DecryptDataChunked failed.";
            return false;
        }

        out.write(reinterpret_cast<const char*>(decryptedChunk.data()), decryptedChunk.size());
    }

    return true;
}


bool CTpmCryptoRSA::EncryptIntWithPassword(int value, const std::string& password, std::vector<BYTE>& encryptedOut) {
    const BYTE* ptr = reinterpret_cast<const BYTE*>(&value);
    return EncryptDecryptInternalWithPassword(password, { ptr, ptr + sizeof(int) }, encryptedOut, true);
}

bool CTpmCryptoRSA::EncryptFloatWithPassword(float value, const std::string& password, std::vector<BYTE>& encryptedOut) {
    const BYTE* ptr = reinterpret_cast<const BYTE*>(&value);
    return EncryptDecryptInternalWithPassword(password, { ptr, ptr + sizeof(float) }, encryptedOut, true);
}

bool CTpmCryptoRSA::EncryptDoubleWithPassword(double value, const std::string& password, std::vector<BYTE>& encryptedOut) {
    const BYTE* ptr = reinterpret_cast<const BYTE*>(&value);
    return EncryptDecryptInternalWithPassword(password, { ptr, ptr + sizeof(double) }, encryptedOut, true);
}

bool CTpmCryptoRSA::EncryptByteWithPassword(BYTE value, const std::string& password, std::vector<BYTE>& encryptedOut) {
    return EncryptDecryptInternalWithPassword(password, { value }, encryptedOut, true);
}

bool CTpmCryptoRSA::EncryptCharWithPassword(char value, const std::string& password, std::vector<BYTE>& encryptedOut) {
    return EncryptDecryptInternalWithPassword(password, { static_cast<BYTE>(value) }, encryptedOut, true);
}

bool CTpmCryptoRSA::EncryptStringWithPassword(const std::string& str, const std::string& password, std::vector<BYTE>& encryptedOut) {
    return EncryptDecryptInternalWithPassword(password, { str.begin(), str.end() }, encryptedOut, true);
}



bool CTpmCryptoRSA::DecryptIntWithPassword(const std::vector<BYTE>& encryptedData, const std::string& password, int& valueOut) {
    std::vector<BYTE> plain;
    if (!EncryptDecryptInternalWithPassword(password, encryptedData, plain, false) || plain.size() != sizeof(int))
        return false;
    std::memcpy(&valueOut, plain.data(), sizeof(int));
    return true;
}

bool CTpmCryptoRSA::DecryptFloatWithPassword(const std::vector<BYTE>& encryptedData, const std::string& password, float& valueOut) {
    std::vector<BYTE> plain;
    if (!EncryptDecryptInternalWithPassword(password, encryptedData, plain, false) || plain.size() != sizeof(float))
        return false;
    std::memcpy(&valueOut, plain.data(), sizeof(float));
    return true;
}

bool CTpmCryptoRSA::DecryptDoubleWithPassword(const std::vector<BYTE>& encryptedData, const std::string& password, double& valueOut) {
    std::vector<BYTE> plain;
    if (!EncryptDecryptInternalWithPassword(password, encryptedData, plain, false) || plain.size() != sizeof(double))
        return false;
    std::memcpy(&valueOut, plain.data(), sizeof(double));
    return true;
}

bool CTpmCryptoRSA::DecryptByteWithPassword(const std::vector<BYTE>& encryptedData, const std::string& password, BYTE& valueOut) {
    std::vector<BYTE> plain;
    if (!EncryptDecryptInternalWithPassword(password, encryptedData, plain, false) || plain.size() != 1)
        return false;
    valueOut = plain[0];
    return true;
}

bool CTpmCryptoRSA::DecryptCharWithPassword(const std::vector<BYTE>& encryptedData, const std::string& password, char& valueOut) {
    std::vector<BYTE> plain;
    if (!EncryptDecryptInternalWithPassword(password, encryptedData, plain, false) || plain.size() != 1)
        return false;
    valueOut = static_cast<char>(plain[0]);
    return true;
}

bool CTpmCryptoRSA::DecryptStringWithPassword(const std::vector<BYTE>& encryptedData, const std::string& password, std::string& strOut) {
    std::vector<BYTE> plain;
    if (!EncryptDecryptInternalWithPassword(password, encryptedData, plain, false))
        return false;
    strOut = std::string(plain.begin(), plain.end());
    return true;
}



bool CTpmCryptoRSA::EncryptIntArrayWithPassword(const std::vector<int>& values, const std::string& password, std::vector<BYTE>& encryptedOut) {
    const BYTE* ptr = reinterpret_cast<const BYTE*>(values.data());
    size_t totalSize = values.size() * sizeof(int);
    return EncryptDecryptInternalWithPassword(password, { ptr, ptr + totalSize }, encryptedOut, true);
}

bool CTpmCryptoRSA::EncryptFloatArrayWithPassword(const std::vector<float>& values, const std::string& password, std::vector<BYTE>& encryptedOut) {
    const BYTE* ptr = reinterpret_cast<const BYTE*>(values.data());
    size_t totalSize = values.size() * sizeof(float);
    return EncryptDecryptInternalWithPassword(password, { ptr, ptr + totalSize }, encryptedOut, true);
}

bool CTpmCryptoRSA::EncryptDoubleArrayWithPassword(const std::vector<double>& values, const std::string& password, std::vector<BYTE>& encryptedOut) {
    const BYTE* ptr = reinterpret_cast<const BYTE*>(values.data());
    size_t totalSize = values.size() * sizeof(double);
    return EncryptDecryptInternalWithPassword(password, { ptr, ptr + totalSize }, encryptedOut, true);
}

bool CTpmCryptoRSA::EncryptByteArrayWithPassword(const std::vector<BYTE>& values, const std::string& password, std::vector<BYTE>& encryptedOut) {
    return EncryptDecryptInternalWithPassword(password, values, encryptedOut, true);
}

bool CTpmCryptoRSA::EncryptCharArrayWithPassword(const std::vector<char>& values, const std::string& password, std::vector<BYTE>& encryptedOut) {
    std::vector<BYTE> buffer(values.begin(), values.end());
    return EncryptDecryptInternalWithPassword(password, buffer, encryptedOut, true);
}

bool CTpmCryptoRSA::EncryptStringArrayWithPassword(const std::vector<std::string>& values, const std::string& password, std::vector<BYTE>& encryptedOut) {
    std::vector<BYTE> buffer;
    for (const auto& str : values) {
        buffer.insert(buffer.end(), str.begin(), str.end());
        buffer.push_back('\0');  // Null-terminated strings
    }
    return EncryptDecryptInternalWithPassword(password, buffer, encryptedOut, true);
}


bool CTpmCryptoRSA::DecryptIntArrayWithPassword(const std::vector<BYTE>& encryptedData, const std::string& password, std::vector<int>& valuesOut) {
    std::vector<BYTE> plain;
    if (!EncryptDecryptInternalWithPassword(password, encryptedData, plain, false) || plain.size() % sizeof(int) != 0)
        return false;
    size_t count = plain.size() / sizeof(int);
    valuesOut.resize(count);
    std::memcpy(valuesOut.data(), plain.data(), plain.size());
    return true;
}

bool CTpmCryptoRSA::DecryptFloatArrayWithPassword(const std::vector<BYTE>& encryptedData, const std::string& password, std::vector<float>& valuesOut) {
    std::vector<BYTE> plain;
    if (!EncryptDecryptInternalWithPassword(password, encryptedData, plain, false) || plain.size() % sizeof(float) != 0)
        return false;
    size_t count = plain.size() / sizeof(float);
    valuesOut.resize(count);
    std::memcpy(valuesOut.data(), plain.data(), plain.size());
    return true;
}

bool CTpmCryptoRSA::DecryptDoubleArrayWithPassword(const std::vector<BYTE>& encryptedData, const std::string& password, std::vector<double>& valuesOut) {
    std::vector<BYTE> plain;
    if (!EncryptDecryptInternalWithPassword(password, encryptedData, plain, false) || plain.size() % sizeof(double) != 0)
        return false;
    size_t count = plain.size() / sizeof(double);
    valuesOut.resize(count);
    std::memcpy(valuesOut.data(), plain.data(), plain.size());
    return true;
}

bool CTpmCryptoRSA::DecryptByteArrayWithPassword(const std::vector<BYTE>& encryptedData, const std::string& password, std::vector<BYTE>& valuesOut) {
    return EncryptDecryptInternalWithPassword(password, encryptedData, valuesOut, false);
}

bool CTpmCryptoRSA::DecryptCharArrayWithPassword(const std::vector<BYTE>& encryptedData, const std::string& password, std::vector<char>& valuesOut) {
    std::vector<BYTE> plain;
    if (!EncryptDecryptInternalWithPassword(password, encryptedData, plain, false))
        return false;
    valuesOut.assign(plain.begin(), plain.end());
    return true;
}

bool CTpmCryptoRSA::DecryptStringArrayWithPassword(const std::vector<BYTE>& encryptedData, const std::string& password, std::vector<std::string>& valuesOut) {
    std::vector<BYTE> plain;
    if (!EncryptDecryptInternalWithPassword(password, encryptedData, plain, false))
        return false;

    valuesOut.clear();
    std::string current;
    for (BYTE b : plain) {
        if (b == '\0') {
            valuesOut.push_back(current);
            current.clear();
        }
        else {
            current.push_back(static_cast<char>(b));
        }
    }
    if (!current.empty())
        valuesOut.push_back(current);
    return true;
}


bool CTpmCryptoRSA::EncryptFileWithPassword(const std::string& inputFile, const std::string& outputFile, const std::string& password)
{
    std::ifstream inFile(inputFile, std::ios::binary);
    if (!inFile) {
        m_lastError = "EncryptFileWithPassword: Cannot open input file: " + inputFile;
        return false;
    }

    std::vector<BYTE> inputData((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
    inFile.close();

    std::vector<BYTE> encryptedData;
    if (!EncryptDataWithPassword(password, inputData, encryptedData)) {
        m_lastError = "EncryptFileWithPassword: Encryption failed.";
        return false;
    }

    std::ofstream outFile(outputFile, std::ios::binary);
    if (!outFile) {
        m_lastError = "EncryptFileWithPassword: Cannot open output file: " + outputFile;
        return false;
    }

    outFile.write(reinterpret_cast<const char*>(encryptedData.data()), encryptedData.size());
    outFile.close();
    return true;
}


bool CTpmCryptoRSA::DecryptFileWithPassword(const std::string& inputFile, const std::string& outputFile, const std::string& password)
{
    std::ifstream inFile(inputFile, std::ios::binary);
    if (!inFile) {
        m_lastError = "DecryptFileWithPassword: Cannot open input file: " + inputFile;
        return false;
    }

    std::vector<BYTE> encryptedData((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
    inFile.close();

    std::vector<BYTE> decryptedData;
    if (!DecryptDataWithPassword(password, encryptedData, decryptedData)) {
        m_lastError = "DecryptFileWithPassword: Decryption failed.";
        return false;
    }

    std::ofstream outFile(outputFile, std::ios::binary);
    if (!outFile) {
        m_lastError = "DecryptFileWithPassword: Cannot open output file: " + outputFile;
        return false;
    }

    outFile.write(reinterpret_cast<const char*>(decryptedData.data()), decryptedData.size());
    outFile.close();
    return true;
}

bool CTpmCryptoRSA::EncryptIntWithPasswordChunked(const std::string& password, int value, std::vector<BYTE>& encryptedOut)
{
    const BYTE* ptr = reinterpret_cast<const BYTE*>(&value);
    std::vector<BYTE> buffer(ptr, ptr + sizeof(int));

    return EncryptDataWithPasswordChunked(password, buffer, encryptedOut);
}
bool CTpmCryptoRSA::DecryptIntWithPasswordChunked(const std::string& password, const std::vector<BYTE>& encryptedData, int& valueOut)
{
    std::vector<BYTE> decrypted;
    if (!DecryptDataWithPasswordChunked(password, encryptedData, decrypted))
        return false;

    if (decrypted.size() != sizeof(int))
    {
        m_lastError = "DecryptIntWithPasswordChunked: Invalid decrypted size.";
        return false;
    }

    valueOut = *reinterpret_cast<const int*>(decrypted.data());
    return true;
}
bool CTpmCryptoRSA::EncryptFloatWithPasswordChunked(const std::string& password, float value, std::vector<BYTE>& encryptedOut)
{
    const BYTE* ptr = reinterpret_cast<const BYTE*>(&value);
    std::vector<BYTE> buffer(ptr, ptr + sizeof(float));
    return EncryptDataWithPasswordChunked(password, buffer, encryptedOut);
}
bool CTpmCryptoRSA::DecryptFloatWithPasswordChunked(const std::string& password, const std::vector<BYTE>& encryptedData, float& valueOut)
{
    std::vector<BYTE> decrypted;
    if (!DecryptDataWithPasswordChunked(password, encryptedData, decrypted))
        return false;

    if (decrypted.size() != sizeof(float))
    {
        m_lastError = "DecryptFloatWithPasswordChunked: Invalid decrypted size.";
        return false;
    }

    valueOut = *reinterpret_cast<const float*>(decrypted.data());
    return true;
}
bool CTpmCryptoRSA::EncryptDoubleWithPasswordChunked(const std::string& password, double value, std::vector<BYTE>& encryptedOut)
{
    const BYTE* ptr = reinterpret_cast<const BYTE*>(&value);
    std::vector<BYTE> buffer(ptr, ptr + sizeof(double));
    return EncryptDataWithPasswordChunked(password, buffer, encryptedOut);
}
bool CTpmCryptoRSA::DecryptDoubleWithPasswordChunked(const std::string& password, const std::vector<BYTE>& encryptedData, double& valueOut)
{
    std::vector<BYTE> decrypted;
    if (!DecryptDataWithPasswordChunked(password, encryptedData, decrypted))
        return false;

    if (decrypted.size() != sizeof(double))
    {
        m_lastError = "DecryptDoubleWithPasswordChunked: Invalid decrypted size.";
        return false;
    }

    valueOut = *reinterpret_cast<const double*>(decrypted.data());
    return true;
}
bool CTpmCryptoRSA::EncryptByteWithPasswordChunked(const std::string& password, BYTE value, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> buffer(1, value);
    return EncryptDataWithPasswordChunked(password, buffer, encryptedOut);
}
bool CTpmCryptoRSA::DecryptByteWithPasswordChunked(const std::string& password, const std::vector<BYTE>& encryptedData, BYTE& valueOut)
{
    std::vector<BYTE> decrypted;
    if (!DecryptDataWithPasswordChunked(password, encryptedData, decrypted))
        return false;

    if (decrypted.size() != 1)
    {
        m_lastError = "DecryptByteWithPasswordChunked: Invalid decrypted size.";
        return false;
    }

    valueOut = decrypted[0];
    return true;
}
bool CTpmCryptoRSA::EncryptCharWithPasswordChunked(const std::string& password, char value, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> buffer(1, static_cast<BYTE>(value));
    return EncryptDataWithPasswordChunked(password, buffer, encryptedOut);
}
bool CTpmCryptoRSA::DecryptCharWithPasswordChunked(const std::string& password, const std::vector<BYTE>& encryptedData, char& valueOut)
{
    std::vector<BYTE> decrypted;
    if (!DecryptDataWithPasswordChunked(password, encryptedData, decrypted))
        return false;

    if (decrypted.size() != 1)
    {
        m_lastError = "DecryptCharWithPasswordChunked: Invalid decrypted size.";
        return false;
    }

    valueOut = static_cast<char>(decrypted[0]);
    return true;
}
bool CTpmCryptoRSA::EncryptStringWithPasswordChunked(const std::string& password, const std::string& str, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> buffer(str.begin(), str.end());
    return EncryptDataWithPasswordChunked(password, buffer, encryptedOut);
}
bool CTpmCryptoRSA::DecryptStringWithPasswordChunked(const std::string& password, const std::vector<BYTE>& encryptedData, std::string& strOut)
{
    std::vector<BYTE> decrypted;
    if (!DecryptDataWithPasswordChunked(password, encryptedData, decrypted))
        return false;

    strOut.assign(decrypted.begin(), decrypted.end());
    return true;
}
bool CTpmCryptoRSA::EncryptIntArrayWithPasswordChunked(const std::string& password, const std::vector<int>& values, std::vector<BYTE>& encryptedOut)
{
    const BYTE* ptr = reinterpret_cast<const BYTE*>(values.data());
    std::vector<BYTE> buffer(ptr, ptr + values.size() * sizeof(int));
    return EncryptDataWithPasswordChunked(password, buffer, encryptedOut);
}
bool CTpmCryptoRSA::DecryptIntArrayWithPasswordChunked(const std::string& password, const std::vector<BYTE>& encryptedData, std::vector<int>& valuesOut)
{
    std::vector<BYTE> decrypted;
    if (!DecryptDataWithPasswordChunked(password, encryptedData, decrypted))
        return false;

    if (decrypted.size() % sizeof(int) != 0)
    {
        m_lastError = "DecryptIntArrayWithPasswordChunked: Decrypted size is not multiple of int.";
        return false;
    }

    size_t count = decrypted.size() / sizeof(int);
    valuesOut.resize(count);
    std::memcpy(valuesOut.data(), decrypted.data(), decrypted.size());
    return true;
}


bool CTpmCryptoRSA::EncryptFloatArrayWithPasswordChunked(const std::string& password, const std::vector<float>& values, std::vector<BYTE>& encryptedOut)
{
    const BYTE* ptr = reinterpret_cast<const BYTE*>(values.data());
    std::vector<BYTE> buffer(ptr, ptr + values.size() * sizeof(float));
    return EncryptDataWithPasswordChunked(password, buffer, encryptedOut);
}
bool CTpmCryptoRSA::DecryptFloatArrayWithPasswordChunked(const std::string& password, const std::vector<BYTE>& encryptedData, std::vector<float>& valuesOut)
{
    std::vector<BYTE> decrypted;
    if (!DecryptDataWithPasswordChunked(password, encryptedData, decrypted))
        return false;

    if (decrypted.size() % sizeof(float) != 0)
    {
        m_lastError = "DecryptFloatArrayWithPasswordChunked: Decrypted size is not multiple of float.";
        return false;
    }

    size_t count = decrypted.size() / sizeof(float);
    valuesOut.resize(count);
    std::memcpy(valuesOut.data(), decrypted.data(), decrypted.size());
    return true;
}
bool CTpmCryptoRSA::EncryptDoubleArrayWithPasswordChunked(const std::string& password, const std::vector<double>& values, std::vector<BYTE>& encryptedOut)
{
    const BYTE* ptr = reinterpret_cast<const BYTE*>(values.data());
    std::vector<BYTE> buffer(ptr, ptr + values.size() * sizeof(double));
    return EncryptDataWithPasswordChunked(password, buffer, encryptedOut);
}
bool CTpmCryptoRSA::DecryptDoubleArrayWithPasswordChunked(const std::string& password, const std::vector<BYTE>& encryptedData, std::vector<double>& valuesOut)
{
    std::vector<BYTE> decrypted;
    if (!DecryptDataWithPasswordChunked(password, encryptedData, decrypted))
        return false;

    if (decrypted.size() % sizeof(double) != 0)
    {
        m_lastError = "DecryptDoubleArrayWithPasswordChunked: Decrypted size is not multiple of double.";
        return false;
    }

    size_t count = decrypted.size() / sizeof(double);
    valuesOut.resize(count);
    std::memcpy(valuesOut.data(), decrypted.data(), decrypted.size());
    return true;
}
bool CTpmCryptoRSA::EncryptByteArrayWithPasswordChunked(const std::string& password, const std::vector<BYTE>& values, std::vector<BYTE>& encryptedOut)
{
    return EncryptDataWithPasswordChunked(password, values, encryptedOut);
}
bool CTpmCryptoRSA::DecryptByteArrayWithPasswordChunked(const std::string& password, const std::vector<BYTE>& encryptedData, std::vector<BYTE>& valuesOut)
{
    return DecryptDataWithPasswordChunked(password, encryptedData, valuesOut);
}
bool CTpmCryptoRSA::EncryptCharArrayWithPasswordChunked(const std::string& password, const std::vector<char>& values, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> buffer(values.begin(), values.end());
    return EncryptDataWithPasswordChunked(password, buffer, encryptedOut);
}
bool CTpmCryptoRSA::DecryptCharArrayWithPasswordChunked(const std::string& password, const std::vector<BYTE>& encryptedData, std::vector<char>& valuesOut)
{
    std::vector<BYTE> decrypted;
    if (!DecryptDataWithPasswordChunked(password, encryptedData, decrypted))
        return false;

    valuesOut.assign(decrypted.begin(), decrypted.end());
    return true;
}
bool CTpmCryptoRSA::EncryptStringArrayWithPasswordChunked(const std::string& password, const std::vector<std::string>& values, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> buffer;
    for (const auto& str : values)
    {
        buffer.insert(buffer.end(), str.begin(), str.end());
        buffer.push_back('\0'); // delimiter
    }
    return EncryptDataWithPasswordChunked(password, buffer, encryptedOut);
}
bool CTpmCryptoRSA::DecryptStringArrayWithPasswordChunked(const std::string& password, const std::vector<BYTE>& encryptedData, std::vector<std::string>& valuesOut)
{
    std::vector<BYTE> decrypted;
    if (!DecryptDataWithPasswordChunked(password, encryptedData, decrypted))
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

    if (!current.empty())
        valuesOut.push_back(current);

    return true;
}

bool CTpmCryptoRSA::EncryptFileWithPasswordChunked(const std::string& inputFile, const std::string& outputFile, const std::string& password)
{
    std::ifstream in(inputFile, std::ios::binary);
    if (!in.is_open())
    {
        m_lastError = "EncryptFileWithPasswordChunked: Failed to open input file: " + inputFile;
        return false;
    }

    std::ofstream out(outputFile, std::ios::binary);
    if (!out.is_open())
    {
        m_lastError = "EncryptFileWithPasswordChunked: Failed to open output file: " + outputFile;
        return false;
    }

    const size_t chunkSize = 256;  // RSA için küçük bloklar önerilir
    std::vector<BYTE> buffer(chunkSize);

    while (!in.eof())
    {
        in.read(reinterpret_cast<char*>(buffer.data()), chunkSize);
        std::streamsize bytesRead = in.gcount();
        if (bytesRead <= 0)
            break;

        std::vector<BYTE> chunk(buffer.begin(), buffer.begin() + bytesRead);
        std::vector<BYTE> encryptedChunk;

        if (!EncryptDataWithPassword(password, chunk, encryptedChunk))
        {
            m_lastError = "EncryptFileWithPasswordChunked: Encryption failed for chunk.";
            return false;
        }

        // İlk olarak şifreli bloğun uzunluğunu yaz
        UINT32 chunkLen = static_cast<UINT32>(encryptedChunk.size());
        out.write(reinterpret_cast<const char*>(&chunkLen), sizeof(chunkLen));
        out.write(reinterpret_cast<const char*>(encryptedChunk.data()), encryptedChunk.size());
    }

    return true;
}
bool CTpmCryptoRSA::DecryptFileWithPasswordChunked(const std::string& inputFile, const std::string& outputFile, const std::string& password)
{
    std::ifstream in(inputFile, std::ios::binary);
    if (!in.is_open())
    {
        m_lastError = "DecryptFileWithPasswordChunked: Failed to open input file: " + inputFile;
        return false;
    }

    std::ofstream out(outputFile, std::ios::binary);
    if (!out.is_open())
    {
        m_lastError = "DecryptFileWithPasswordChunked: Failed to open output file: " + outputFile;
        return false;
    }

    while (!in.eof())
    {
        UINT32 chunkLen = 0;
        in.read(reinterpret_cast<char*>(&chunkLen), sizeof(chunkLen));
        if (in.gcount() != sizeof(chunkLen))
            break;  // dosya sonuna ulaşılmış olabilir

        std::vector<BYTE> encryptedChunk(chunkLen);
        in.read(reinterpret_cast<char*>(encryptedChunk.data()), chunkLen);
        if (in.gcount() != chunkLen)
        {
            m_lastError = "DecryptFileWithPasswordChunked: Unexpected EOF while reading chunk.";
            return false;
        }

        std::vector<BYTE> decryptedChunk;
        if (!DecryptDataWithPassword(password, encryptedChunk, decryptedChunk))
        {
            m_lastError = "DecryptFileWithPasswordChunked: Decryption failed for chunk.";
            return false;
        }

        out.write(reinterpret_cast<const char*>(decryptedChunk.data()), decryptedChunk.size());
    }

    return true;
}


TPM_HANDLE CTpmCryptoRSA::MakeStoragePrimary(AUTH_SESSION* sess)
{
    TPMT_PUBLIC storagePrimaryTemplate(TPM_ALG_ID::SHA1,
        TPMA_OBJECT::decrypt | TPMA_OBJECT::restricted
        | TPMA_OBJECT::fixedParent | TPMA_OBJECT::fixedTPM
        | TPMA_OBJECT::sensitiveDataOrigin | TPMA_OBJECT::userWithAuth,
        null,           // No policy
        TPMS_RSA_PARMS(TpmCryptoRSANS::Aes128Cfb, TPMS_NULL_ASYM_SCHEME(), 2048, 65537),
        TPM2B_PUBLIC_KEY_RSA());
    // Create the key
    if (sess)
        (*tpm)[*sess];
    return tpm->CreatePrimary(TPM_RH::OWNER, null, storagePrimaryTemplate, null, null)
        .handle;
}

void CTpmCryptoRSA::EncryptDecryptSample()
{
    Announce("EncryptDecryptSample");

    TPM_HANDLE prim = MakeStoragePrimary(nullptr);

    // Make an AES key
    TPMT_PUBLIC inPublic(TPM_ALG_ID::SHA256,
        TPMA_OBJECT::decrypt | TPMA_OBJECT::sign | TPMA_OBJECT::userWithAuth
        | TPMA_OBJECT::sensitiveDataOrigin,
        null,
        TPMS_SYMCIPHER_PARMS(TpmCryptoRSANS::Aes128Cfb),
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
















bool CTpmCryptoRSA::IsTooLargeForTpm(const std::vector<BYTE>& data)
{
    return data.size() > TpmCryptoRSANS::TPM_AES_MAX_SIZE;
}

bool CTpmCryptoRSA::IsTooLargeForTpm(const std::streamsize dataSize)
{
    return dataSize > TpmCryptoRSANS::TPM_AES_MAX_SIZE;
}

bool CTpmCryptoRSA::IsTooLargeForTpm(const uint64_t dataSize)
{
    return dataSize > TpmCryptoRSANS::TPM_AES_MAX_SIZE;
}

std::streamsize CTpmCryptoRSA::GetFileSize(const std::string& filePath)
{
    std::streamsize fileSize = 0;

    std::ifstream in(filePath, std::ios::binary | std::ios::ate);
    if (!in)
        return -1; // hata durumunda -1 döner

    fileSize = in.tellg();  // byte cinsinden dosya boyutu

    in.close();

    return fileSize;
}

uint64_t CTpmCryptoRSA::GetFileSize2(const std::string& filePath)
{
    uint64_t fileSize = 0;

    std::ifstream in(filePath, std::ios::binary | std::ios::ate);
    if (!in)
        return 0; // Hata durumunda 0 döner (istersen -1 yerine uint64_t için özel sabit belirleyebiliriz)

    fileSize = static_cast<uint64_t>(in.tellg());  // byte cinsinden dosya boyutu

    in.close();

    return fileSize;
}

bool CTpmCryptoRSA::CompareFiles(const std::string& file1, const std::string& file2)
{
    std::ifstream f1(file1, std::ios::binary);
    std::ifstream f2(file2, std::ios::binary);

    if (!f1 || !f2)
        return false;

    std::istreambuf_iterator<char> begin1(f1), end1;
    std::istreambuf_iterator<char> begin2(f2), end2;

    return std::vector<char>(begin1, end1) == std::vector<char>(begin2, end2);
}

void CTpmCryptoRSA::BuildTestFile(const std::string& inputFile, const int inputFileSizeByte)
{
    std::ofstream out(inputFile, std::ios::binary);
    for (int i = 0; i < inputFileSizeByte; ++i)  
    {
        char val = static_cast<char>(i % 256);
        out.write(&val, 1);
    }
}
#if 0
bool CTpmCryptoRSA::GenerateAndLoadAesKeyWithPassword(const std::string& password)
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
            TPMS_SYMCIPHER_PARMS(TpmCryptoRSANS::Aes128Cfb),
            TPM2B_DIGEST_SYMCIPHER()
        );

        // 4. AES anahtarı oluştur
        auto aesKey = tpm->Create(prim, inSensitive, inPublic, null, null);

        // 5. Load işlemi ve şifreyi handle'a bağla
        m_aesKeyHandle = tpm->Load(prim, aesKey.outPrivate, aesKey.outPublic);
        m_aesKeyHandle.SetAuth(std::vector<BYTE>(password.begin(), password.end()));

        std::cout << "[CTpmCryptoRSA] AES key with password created and loaded successfully." << std::endl;
        return true;
    }
    catch (const std::exception& ex)
    {
        m_lastError = std::string("GenerateAndLoadAesKeyWithPassword failed: ") + ex.what();
        std::cerr << m_lastError << std::endl;
        return false;
    }
}

bool CTpmCryptoRSA::GenerateAndLoadAesKeyWithPassword(const std::string& password, bool usePersistentKey)
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
                std::cout << "[CTpmCryptoRSA] AES key loaded from persistent storage." << std::endl;
                return true;
            }
            catch (...)
            {
                std::cout << "[CTpmCryptoRSA] No persistent AES key found, generating..." << std::endl;
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
            TPMS_SYMCIPHER_PARMS(TpmCryptoRSANS::Aes128Cfb),
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

        std::cout << "[CTpmCryptoRSA] AES key generated and " <<
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

bool CTpmCryptoRSA::UnloadAndClearAesKeyWithPassword()
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
                std::cout << "[CTpmCryptoRSA] AES key handle flushed." << std::endl;
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
            std::cout << "[CTpmCryptoRSA] AES key handle was already empty." << std::endl;
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

bool CTpmCryptoRSA::RemovePersistentAesKey(UINT32 persistentHandleValue)
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

bool CTpmCryptoRSA::IsAesKeyHandleLoaded() const
{
    // hangisi kullanilacak, gpt'ye sor!!!

    return m_aesKeyHandle.handle != 0;

    return m_aesKeyHandle.handle != 0 && m_aesKeyHandle.handle != TPM_RH_NULL;
}

bool CTpmCryptoRSA::ClearAllAesKeys()
{
    bool result = true;
    if (IsAesKeyHandleLoaded()) {
        result &= RemovePersistentAesKey();  // NV alanını sil
        result &= UnloadAndClearAesKey();   // RAM'deki handle'ı sil
    }
    return result;
}
#endif

#if 0
std::vector<BYTE> CTpmCryptoRSA::ComputePasswordHash(const std::string& password) 
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

bool CTpmCryptoRSA::StorePasswordHashToNv(const std::vector<BYTE>& hash) 
{
#if 1
    try {
        tpm->NV_UndefineSpace(TPM_RH::OWNER, TpmCryptoRSANS::NV_INDEX_PASSWORD_HASH);
    }
    catch (...) {
        // Zaten tanımlı değilse sorun değil
    }    
    
    TPM2B_AUTH auth = {};
    TPM2B_NV_PUBLIC nvPub;
    nvPub.nvPublic.nvIndex = TPM_HANDLE(TpmCryptoRSANS::NV_INDEX_PASSWORD_HASH); // Veya sabit değer
    nvPub.nvPublic.nameAlg = TPM_ALG_ID::SHA256;
    nvPub.nvPublic.attributes =
        TPMA_NV::AUTHWRITE | TPMA_NV::AUTHREAD | TPMA_NV::OWNERWRITE | TPMA_NV::OWNERREAD;
    nvPub.nvPublic.authPolicy = TPM2B_DIGEST(); // Boş policy
    nvPub.nvPublic.dataSize = static_cast<UINT16>(hash.size());


    tpm->NV_DefineSpace(TPM_RH::OWNER, auth, nvPub.nvPublic);
    tpm->NV_Write(TPM_HANDLE(TpmCryptoRSANS::NV_INDEX_PASSWORD_HASH), TPM_HANDLE(TpmCryptoRSANS::NV_INDEX_PASSWORD_HASH), hash, 0);
#endif
    return true;
}

bool CTpmCryptoRSA::ReadPasswordHashFromNv(std::vector<BYTE>& hashOut) {
    try {
        auto data = tpm->NV_Read(TPM_RH::OWNER, TPM_HANDLE(TpmCryptoRSANS::NV_INDEX_PASSWORD_HASH), 32, 0);
        hashOut = data;
        return true;
    }
    catch (...) {
        std::cerr << "[ReadPasswordHashFromNv] Failed to read hash from NV." << std::endl;
        return false;
    }
}

bool CTpmCryptoRSA::IsPasswordValidForCurrentAesKey(const std::string& password) {
    std::vector<BYTE> expectedHash;
    if (!ReadPasswordHashFromNv(expectedHash))
        return false;

    auto currentHash = ComputePasswordHash(password);
    return currentHash == expectedHash;
}
#endif

#if 0
bool CTpmCryptoRSA::EncryptIntChunked(int value, std::vector<BYTE>& encryptedOut)
{
    const BYTE* dataPtr = reinterpret_cast<const BYTE*>(&value);
    std::vector<BYTE> plain(dataPtr, dataPtr + sizeof(int));
    return EncryptDataChunked(plain, encryptedOut);
}

bool CTpmCryptoRSA::EncryptFloatChunked(float value, std::vector<BYTE>& encryptedOut)
{
    const BYTE* dataPtr = reinterpret_cast<const BYTE*>(&value);
    std::vector<BYTE> plain(dataPtr, dataPtr + sizeof(float));
    return EncryptDataChunked(plain, encryptedOut);
}

bool CTpmCryptoRSA::EncryptDoubleChunked(double value, std::vector<BYTE>& encryptedOut)
{
    const BYTE* dataPtr = reinterpret_cast<const BYTE*>(&value);
    std::vector<BYTE> plain(dataPtr, dataPtr + sizeof(double));
    return EncryptDataChunked(plain, encryptedOut);
}

bool CTpmCryptoRSA::EncryptByteChunked(BYTE value, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> plain = { value };
    return EncryptDataChunked(plain, encryptedOut);
}

bool CTpmCryptoRSA::EncryptCharChunked(char value, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> plain = { static_cast<BYTE>(value) };
    return EncryptDataChunked(plain, encryptedOut);
}

bool CTpmCryptoRSA::EncryptStringChunked(const std::string& str, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> plain(str.begin(), str.end());
    return EncryptDataChunked(plain, encryptedOut);
}

bool CTpmCryptoRSA::DecryptIntChunked(const std::vector<BYTE>& encryptedData, int& valueOut)
{
    std::vector<BYTE> plain;
    if (!DecryptDataChunked(encryptedData, plain) || plain.size() != sizeof(int))
        return false;

    valueOut = *reinterpret_cast<const int*>(plain.data());
    return true;
}

bool CTpmCryptoRSA::DecryptFloatChunked(const std::vector<BYTE>& encryptedData, float& valueOut)
{
    std::vector<BYTE> plain;
    if (!DecryptDataChunked(encryptedData, plain) || plain.size() != sizeof(float))
        return false;

    valueOut = *reinterpret_cast<const float*>(plain.data());
    return true;
}

bool CTpmCryptoRSA::DecryptDoubleChunked(const std::vector<BYTE>& encryptedData, double& valueOut)
{
    std::vector<BYTE> plain;
    if (!DecryptDataChunked(encryptedData, plain) || plain.size() != sizeof(double))
        return false;

    valueOut = *reinterpret_cast<const double*>(plain.data());
    return true;
}

bool CTpmCryptoRSA::DecryptByteChunked(const std::vector<BYTE>& encryptedData, BYTE& valueOut)
{
    std::vector<BYTE> plain;
    if (!DecryptDataChunked(encryptedData, plain) || plain.size() != sizeof(BYTE))
        return false;

    valueOut = plain[0];
    return true;
}

bool CTpmCryptoRSA::DecryptCharChunked(const std::vector<BYTE>& encryptedData, char& valueOut)
{
    std::vector<BYTE> plain;
    if (!DecryptDataChunked(encryptedData, plain) || plain.size() != sizeof(char))
        return false;

    valueOut = static_cast<char>(plain[0]);
    return true;
}

bool CTpmCryptoRSA::DecryptStringChunked(const std::vector<BYTE>& encryptedData, std::string& strOut)
{
    std::vector<BYTE> plain;
    if (!DecryptDataChunked(encryptedData, plain))
        return false;

    strOut.assign(plain.begin(), plain.end());
    return true;
}


bool CTpmCryptoRSA::EncryptIntArrayChunked(const std::vector<int>& values, std::vector<BYTE>& encryptedOut)
{
    const BYTE* data = reinterpret_cast<const BYTE*>(values.data());
    return EncryptDataChunked(std::vector<BYTE>(data, data + values.size() * sizeof(int)), encryptedOut);
}

bool CTpmCryptoRSA::EncryptFloatArrayChunked(const std::vector<float>& values, std::vector<BYTE>& encryptedOut)
{
    const BYTE* data = reinterpret_cast<const BYTE*>(values.data());
    return EncryptDataChunked(std::vector<BYTE>(data, data + values.size() * sizeof(float)), encryptedOut);
}

bool CTpmCryptoRSA::EncryptDoubleArrayChunked(const std::vector<double>& values, std::vector<BYTE>& encryptedOut)
{
    const BYTE* data = reinterpret_cast<const BYTE*>(values.data());
    return EncryptDataChunked(std::vector<BYTE>(data, data + values.size() * sizeof(double)), encryptedOut);
}

bool CTpmCryptoRSA::EncryptByteArrayChunked(const std::vector<BYTE>& values, std::vector<BYTE>& encryptedOut)
{
    return EncryptDataChunked(values, encryptedOut);
}

bool CTpmCryptoRSA::EncryptCharArrayChunked(const std::vector<char>& values, std::vector<BYTE>& encryptedOut)
{
    const BYTE* data = reinterpret_cast<const BYTE*>(values.data());
    return EncryptDataChunked(std::vector<BYTE>(data, data + values.size() * sizeof(char)), encryptedOut);
}

bool CTpmCryptoRSA::EncryptStringArrayChunked(const std::vector<std::string>& values, std::vector<BYTE>& encryptedOut)
{
    std::vector<BYTE> combined;
    for (const auto& str : values)
    {
        uint32_t len = static_cast<uint32_t>(str.size());
        const BYTE* lenPtr = reinterpret_cast<const BYTE*>(&len);
        combined.insert(combined.end(), lenPtr, lenPtr + sizeof(uint32_t));
        combined.insert(combined.end(), str.begin(), str.end());
    }
    return EncryptDataChunked(combined, encryptedOut);
}

bool CTpmCryptoRSA::DecryptIntArrayChunked(const std::vector<BYTE>& encryptedData, std::vector<int>& valuesOut)
{
    std::vector<BYTE> plain;
    if (!DecryptDataChunked(encryptedData, plain) || plain.size() % sizeof(int) != 0)
        return false;

    valuesOut.resize(plain.size() / sizeof(int));
    memcpy(valuesOut.data(), plain.data(), plain.size());
    return true;
}

bool CTpmCryptoRSA::DecryptFloatArrayChunked(const std::vector<BYTE>& encryptedData, std::vector<float>& valuesOut)
{
    std::vector<BYTE> plain;
    if (!DecryptDataChunked(encryptedData, plain) || plain.size() % sizeof(float) != 0)
        return false;

    valuesOut.resize(plain.size() / sizeof(float));
    memcpy(valuesOut.data(), plain.data(), plain.size());
    return true;
}

bool CTpmCryptoRSA::DecryptDoubleArrayChunked(const std::vector<BYTE>& encryptedData, std::vector<double>& valuesOut)
{
    std::vector<BYTE> plain;
    if (!DecryptDataChunked(encryptedData, plain) || plain.size() % sizeof(double) != 0)
        return false;

    valuesOut.resize(plain.size() / sizeof(double));
    memcpy(valuesOut.data(), plain.data(), plain.size());
    return true;
}

bool CTpmCryptoRSA::DecryptByteArrayChunked(const std::vector<BYTE>& encryptedData, std::vector<BYTE>& valuesOut)
{
    return DecryptDataChunked(encryptedData, valuesOut);
}

bool CTpmCryptoRSA::DecryptCharArrayChunked(const std::vector<BYTE>& encryptedData, std::vector<char>& valuesOut)
{
    std::vector<BYTE> plain;
    if (!DecryptDataChunked(encryptedData, plain))
        return false;

    valuesOut.assign(plain.begin(), plain.end());
    return true;
}

bool CTpmCryptoRSA::DecryptStringArrayChunked(const std::vector<BYTE>& encryptedData, std::vector<std::string>& valuesOut)
{
    std::vector<BYTE> plain;
    if (!DecryptDataChunked(encryptedData, plain))
        return false;

    valuesOut.clear();
    size_t offset = 0;
    while (offset + sizeof(uint32_t) <= plain.size())
    {
        uint32_t len = *reinterpret_cast<const uint32_t*>(&plain[offset]);
        offset += sizeof(uint32_t);
        if (offset + len > plain.size()) return false;

        valuesOut.emplace_back(plain.begin() + offset, plain.begin() + offset + len);
        offset += len;
    }

    return true;
}






















bool CTpmCryptoRSA::EncryptIntWithPasswordChunked(const std::string& password, int value, std::vector<BYTE>& encryptedOut)
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
bool CTpmCryptoRSA::EncryptFloatWithPasswordChunked(const std::string& password, float value, std::vector<BYTE>& encryptedOut)
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
bool CTpmCryptoRSA::EncryptDoubleWithPasswordChunked(const std::string& password, double value, std::vector<BYTE>& encryptedOut)
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
bool CTpmCryptoRSA::EncryptByteWithPasswordChunked(const std::string& password, BYTE value, std::vector<BYTE>& encryptedOut)
{
    try {
        std::vector<BYTE> plain(1, value);
        return EncryptDataWithPasswordChunked(password, plain, encryptedOut);
    }
    catch (...) {
        return false;
    }
}
bool CTpmCryptoRSA::EncryptCharWithPasswordChunked(const std::string& password, char value, std::vector<BYTE>& encryptedOut)
{
    try {
        std::vector<BYTE> plain(1, static_cast<BYTE>(value));
        return EncryptDataWithPasswordChunked(password, plain, encryptedOut);
    }
    catch (...) {
        return false;
    }
}
bool CTpmCryptoRSA::EncryptStringWithPasswordChunked(const std::string& password, const std::string& str, std::vector<BYTE>& encryptedOut)
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
bool CTpmCryptoRSA::DecryptIntWithPasswordChunked(const std::string& password, const std::vector<BYTE>& encryptedData, int& valueOut)
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
bool CTpmCryptoRSA::DecryptFloatWithPasswordChunked(const std::string& password, const std::vector<BYTE>& encryptedData, float& valueOut)
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
bool CTpmCryptoRSA::DecryptDoubleWithPasswordChunked(const std::string& password, const std::vector<BYTE>& encryptedData, double& valueOut)
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
bool CTpmCryptoRSA::DecryptByteWithPasswordChunked(const std::string& password, const std::vector<BYTE>& encryptedData, BYTE& valueOut)
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
bool CTpmCryptoRSA::DecryptCharWithPasswordChunked(const std::string& password, const std::vector<BYTE>& encryptedData, char& valueOut)
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
bool CTpmCryptoRSA::DecryptStringWithPasswordChunked(const std::string& password, const std::vector<BYTE>& encryptedData, std::string& strOut)
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

bool CTpmCryptoRSA::EncryptIntArrayWithPasswordChunked(const std::string& password, const std::vector<int>& values, std::vector<BYTE>& encryptedOut)
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
bool CTpmCryptoRSA::EncryptFloatArrayWithPasswordChunked(const std::string& password, const std::vector<float>& values, std::vector<BYTE>& encryptedOut)
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
bool CTpmCryptoRSA::EncryptDoubleArrayWithPasswordChunked(const std::string& password, const std::vector<double>& values, std::vector<BYTE>& encryptedOut)
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
bool CTpmCryptoRSA::EncryptByteArrayWithPasswordChunked(const std::string& password, const std::vector<BYTE>& values, std::vector<BYTE>& encryptedOut)
{
    try {
        return EncryptDataWithPasswordChunked(password, values, encryptedOut);
    }
    catch (...) {
        return false;
    }
}
bool CTpmCryptoRSA::EncryptCharArrayWithPasswordChunked(const std::string& password, const std::vector<char>& values, std::vector<BYTE>& encryptedOut)
{
    try {
        std::vector<BYTE> plain(values.begin(), values.end());
        return EncryptDataWithPasswordChunked(password, plain, encryptedOut);
    }
    catch (...) {
        return false;
    }
}
bool CTpmCryptoRSA::EncryptStringArrayWithPasswordChunked(const std::string& password, const std::vector<std::string>& values, std::vector<BYTE>& encryptedOut)
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
bool CTpmCryptoRSA::DecryptIntArrayWithPasswordChunked(const std::string& password, const std::vector<BYTE>& encryptedData, std::vector<int>& valuesOut)
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
bool CTpmCryptoRSA::DecryptFloatArrayWithPasswordChunked(const std::string& password, const std::vector<BYTE>& encryptedData, std::vector<float>& valuesOut)
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
bool CTpmCryptoRSA::DecryptDoubleArrayWithPasswordChunked(const std::string& password, const std::vector<BYTE>& encryptedData, std::vector<double>& valuesOut)
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
bool CTpmCryptoRSA::DecryptByteArrayWithPasswordChunked(const std::string& password, const std::vector<BYTE>& encryptedData, std::vector<BYTE>& valuesOut)
{
    try {
        return DecryptDataWithPasswordChunked(password, encryptedData, valuesOut);
    }
    catch (...) {
        return false;
    }
}
bool CTpmCryptoRSA::DecryptCharArrayWithPasswordChunked(const std::string& password, const std::vector<BYTE>& encryptedData, std::vector<char>& valuesOut)
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
bool CTpmCryptoRSA::DecryptStringArrayWithPasswordChunked(const std::string& password, const std::vector<BYTE>& encryptedData, std::vector<std::string>& valuesOut)
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
#endif
bool CTpmCryptoRSA::GenerateKeyPair(UINT16 keyBits, UINT32 publicExponent, const std::vector<BYTE>& authValue)
{
    try
    {
        m_authValue = authValue;

        TPMT_PUBLIC publicTemplate(
            TPM_ALG_ID::SHA256,
            TPMA_OBJECT::decrypt | TPMA_OBJECT::userWithAuth | TPMA_OBJECT::sensitiveDataOrigin,
            {},
            TPMS_RSA_PARMS(
                TPMT_SYM_DEF_OBJECT(), TPMS_NULL_ASYM_SCHEME(), keyBits, publicExponent
            ),
            TPM2B_PUBLIC_KEY_RSA()
        );

        TPMS_SENSITIVE_CREATE sensCreate(TPM2B_AUTH(authValue), {});

        CreatePrimaryResponse resp = tpm->CreatePrimary(
            TPM_RH::OWNER, sensCreate, publicTemplate, {}, {}
        );

        m_keyHandle = resp.handle;
        m_publicArea = resp.outPublic;
        m_keyGenerated = true;

        return true;
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[CTpmCryptoRSA] GenerateKeyPair exception: " << ex.what() << "\n";
        return false;
    }
}

bool CTpmCryptoRSA::GenerateKeyPairEx(
    UINT16 keyBits,
    TPM_ALG_ID hashAlg,
    UINT32 publicExponent,
    const std::vector<BYTE>& authValue)
{
    try
    {
        m_currentAuthValue = authValue;

        TPMT_PUBLIC publicTemplate(
            hashAlg,
            TPMA_OBJECT::decrypt | TPMA_OBJECT::sign | TPMA_OBJECT::userWithAuth | TPMA_OBJECT::sensitiveDataOrigin,
            {},
            TPMS_RSA_PARMS(
                TPMT_SYM_DEF_OBJECT(),                             // No symmetric
                TPMS_SCHEME_OAEP(hashAlg),                         // Or RSASSA
                keyBits,
                publicExponent                                     // 0 = default (65537)
            ),
            TPM2B_PUBLIC_KEY_RSA()
        );

        TPMS_SENSITIVE_CREATE sensCreate;
        sensCreate.userAuth = authValue;
        sensCreate.data = ByteVec();

        ByteVec outsideInfo;
        std::vector<TPMS_PCR_SELECTION> creationPCR;

        auto resp = tpm->CreatePrimary(
            TPM_RH::OWNER,
            sensCreate,
            publicTemplate,
            outsideInfo,
            creationPCR
        );

        m_keyHandle = resp.handle;

        Log("RSA key pair generated (bits: " + std::to_string(keyBits) + ")");
        return true;
    }
    catch (const std::exception& ex)
    {
        Log(std::string("GenerateKeyPairEx exception: ") + ex.what(), true);
        return false;
    }
}



bool CTpmCryptoRSA::EnsureRsaKeyLoaded()
{
    if (m_keyLoaded)
        return true;

    try
    {
        TPMT_PUBLIC pub(
            TPM_ALG_ID::SHA256,
            TPMA_OBJECT::decrypt | TPMA_OBJECT::userWithAuth | TPMA_OBJECT::sensitiveDataOrigin,
            {}, // authPolicy
            TPMS_RSA_PARMS(
                TPMT_SYM_DEF_OBJECT(),  // no symmetric algorithm
                TPMS_NULL_ASYM_SCHEME(),
                2048,
                0
            ),
            TPM2B_PUBLIC_KEY_RSA()
        );

        TPMS_SENSITIVE_CREATE sensCreate;
        sensCreate.userAuth = TPM2B_AUTH();  // no auth
        sensCreate.data = ByteVec();         // no seed

        ByteVec outsideInfo;
        std::vector<TPMS_PCR_SELECTION> creationPCR;

        auto resp = tpm->CreatePrimary(
            TPM_RH::OWNER, sensCreate, pub, outsideInfo, creationPCR);

        m_rsaKeyHandle = resp.handle;
        m_keyLoaded = true;
        return true;
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[CTpmCryptoRSA] EnsureRsaKeyLoaded exception: " << ex.what() << std::endl;
        return false;
    }
}

bool CTpmCryptoRSA::IsPasswordValidForCurrentRsaKey(const std::string& password)
{
    std::vector<BYTE> input(password.begin(), password.end());
    return input == m_currentAuthValue;
}

bool CTpmCryptoRSA::FlushKey()
{
    if (!tpm || m_keyHandle == TPM_HANDLE(0))
    {
        m_lastError = "FlushKey: TPM not initialized or no key loaded.";
        return false;
    }

    try
    {
        tpm->FlushContext(m_keyHandle);
        m_keyHandle = TPM_HANDLE(); // Reset handle to null
        m_keyLoaded = false;
        return true;
    }
    catch (const std::exception& ex)
    {
        m_lastError = std::string("FlushKey exception: ") + ex.what();
        return false;
    }
    catch (...)
    {
        m_lastError = "FlushKey: Unknown exception.";
        return false;
    }
}


std::vector<BYTE> CTpmCryptoRSA::AddLengthPrefix(const std::vector<BYTE>& data)
{
    std::vector<BYTE> result;
    uint32_t length = static_cast<uint32_t>(data.size());

    result.push_back((length >> 24) & 0xFF);
    result.push_back((length >> 16) & 0xFF);
    result.push_back((length >> 8) & 0xFF);
    result.push_back(length & 0xFF);

    result.insert(result.end(), data.begin(), data.end());
    return result;
}

bool CTpmCryptoRSA::RemoveLengthPrefix(const std::vector<BYTE>& dataWithLength, std::vector<BYTE>& originalData)
{
    if (dataWithLength.size() < 4) return false;

    uint32_t length =
        (dataWithLength[0] << 24) |
        (dataWithLength[1] << 16) |
        (dataWithLength[2] << 8) |
        dataWithLength[3];

    if (dataWithLength.size() < 4 + length) return false;

    originalData.assign(dataWithLength.begin() + 4, dataWithLength.begin() + 4 + length);
    return true;
}
