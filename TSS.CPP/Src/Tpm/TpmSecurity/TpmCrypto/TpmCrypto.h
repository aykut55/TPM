#pragma once

#include "TpmBaseClass.h"
#include "TpmSharedDevice.h"
#include "TpmSlotDefinitions.h"
#include "TpmTypes.h"

using namespace TpmCpp;

namespace TpmCryptoNS
{
    const TPMT_SYM_DEF_OBJECT Aes128Cfb{ TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB };

    // Donanıma göre değişmekle birlikte, 1024 bayt genelde güvenli sınırdır
    const size_t TPM_AES_MAX_SIZE = 1024;

    constexpr UINT32 NV_INDEX_PASSWORD_HASH = 0x01500020;
}

class CTpmCrypto : public CTpmBaseClass
{
public:
    virtual ~CTpmCrypto();
             CTpmCrypto(CTpmSharedDevice* sharedDevice = nullptr);

    CTpmSharedDevice*        GetTpmSharedDevice(void);
    bool                     Release(void);
    bool                     Initialize(void);

    bool    GenerateAndLoadAesKey();
    bool    UnloadAndClearAesKey();
    bool    ResetAesKey();

    // Encrypt - simple types
    bool EncryptByte(BYTE value, std::vector<BYTE>& encryptedOut);
    bool EncryptChar(char value, std::vector<BYTE>& encryptedOut);
    bool EncryptInt(int value, std::vector<BYTE>& encryptedOut);
    bool EncryptFloat(float value, std::vector<BYTE>& encryptedOut);
    bool EncryptDouble(double value, std::vector<BYTE>& encryptedOut);
    bool EncryptString(const std::string& str, std::vector<BYTE>& encryptedOut);

    // Decrypt - simple types
    bool DecryptByte(const std::vector<BYTE>& encryptedData, BYTE& valueOut);
    bool DecryptChar(const std::vector<BYTE>& encryptedData, char& valueOut);
    bool DecryptInt(const std::vector<BYTE>& encryptedData, int& valueOut);
    bool DecryptFloat(const std::vector<BYTE>& encryptedData, float& valueOut);
    bool DecryptDouble(const std::vector<BYTE>& encryptedData, double& valueOut);
    bool DecryptString(const std::vector<BYTE>& encryptedData, std::string& strOut);

    // Encrypt - array types (eklenen)
    bool EncryptByteArray(const std::vector<BYTE>& values, std::vector<BYTE>& encryptedOut);
    bool EncryptCharArray(const std::vector<char>& values, std::vector<BYTE>& encryptedOut);
    bool EncryptIntArray(const std::vector<int>& values, std::vector<BYTE>& encryptedOut);
    bool EncryptFloatArray(const std::vector<float>& values, std::vector<BYTE>& encryptedOut);
    bool EncryptDoubleArray(const std::vector<double>& values, std::vector<BYTE>& encryptedOut);
    bool EncryptStringArray(const std::vector<std::string>& values, std::vector<BYTE>& encryptedOut);

    // Decrypt - array types (eklenen)
    bool DecryptByteArray(const std::vector<BYTE>& encryptedData, std::vector<BYTE>& valuesOut);
    bool DecryptCharArray(const std::vector<BYTE>& encryptedData, std::vector<char>& valuesOut);
    bool DecryptIntArray(const std::vector<BYTE>& encryptedData, std::vector<int>& valuesOut);
    bool DecryptFloatArray(const std::vector<BYTE>& encryptedData, std::vector<float>& valuesOut);
    bool DecryptDoubleArray(const std::vector<BYTE>& encryptedData, std::vector<double>& valuesOut);
    bool DecryptStringArray(const std::vector<BYTE>& encryptedData, std::vector<std::string>& valuesOut);

    // Kucuk boyutlu dosyalarda tamam ama buyuk boutlu dosyalarda hata veriyor
    bool  EncryptFile(const std::string& inputFile, const std::string& outputFile);
    bool  DecryptFile(const std::string& inputFile, const std::string& outputFile);

    // Buyuk boyutlu dosyalarda da tamam
    bool  EncryptFileChunked(const std::string& inputFile, const std::string& outputFile, size_t chunkSize);
    bool  DecryptFileChunked(const std::string& inputFile, const std::string& outputFile);


    // Encrypt - simple types (with password)
    bool EncryptByteWithPassword(BYTE value, const std::string& password, std::vector<BYTE>& encryptedOut);
    bool EncryptCharWithPassword(char value, const std::string& password, std::vector<BYTE>& encryptedOut);
    bool EncryptIntWithPassword(int value, const std::string& password, std::vector<BYTE>& encryptedOut);
    bool EncryptFloatWithPassword(float value, const std::string& password, std::vector<BYTE>& encryptedOut);
    bool EncryptDoubleWithPassword(double value, const std::string& password, std::vector<BYTE>& encryptedOut);
    bool EncryptStringWithPassword(const std::string& str, const std::string& password, std::vector<BYTE>& encryptedOut);

    // Decrypt - simple types (with password)
    bool DecryptByteWithPassword(const std::vector<BYTE>& encryptedData, const std::string& password, BYTE& valueOut);
    bool DecryptCharWithPassword(const std::vector<BYTE>& encryptedData, const std::string& password, char& valueOut);
    bool DecryptIntWithPassword(const std::vector<BYTE>& encryptedData, const std::string& password, int& valueOut);
    bool DecryptFloatWithPassword(const std::vector<BYTE>& encryptedData, const std::string& password, float& valueOut);
    bool DecryptDoubleWithPassword(const std::vector<BYTE>& encryptedData, const std::string& password, double& valueOut);
    bool DecryptStringWithPassword(const std::vector<BYTE>& encryptedData, const std::string& password, std::string& strOut);

    // Encrypt - array types (with password)
    bool EncryptByteArrayWithPassword(const std::vector<BYTE>& values, const std::string& password, std::vector<BYTE>& encryptedOut);
    bool EncryptCharArrayWithPassword(const std::vector<char>& values, const std::string& password, std::vector<BYTE>& encryptedOut);
    bool EncryptIntArrayWithPassword(const std::vector<int>& values, const std::string& password, std::vector<BYTE>& encryptedOut);
    bool EncryptFloatArrayWithPassword(const std::vector<float>& values, const std::string& password, std::vector<BYTE>& encryptedOut);
    bool EncryptDoubleArrayWithPassword(const std::vector<double>& values, const std::string& password, std::vector<BYTE>& encryptedOut);
    bool EncryptStringArrayWithPassword(const std::vector<std::string>& values, const std::string& password, std::vector<BYTE>& encryptedOut);

    // Decrypt - array types (with password)
    bool DecryptByteArrayWithPassword(const std::vector<BYTE>& encryptedData, const std::string& password, std::vector<BYTE>& valuesOut);
    bool DecryptCharArrayWithPassword(const std::vector<BYTE>& encryptedData, const std::string& password, std::vector<char>& valuesOut);
    bool DecryptIntArrayWithPassword(const std::vector<BYTE>& encryptedData, const std::string& password, std::vector<int>& valuesOut);
    bool DecryptFloatArrayWithPassword(const std::vector<BYTE>& encryptedData, const std::string& password, std::vector<float>& valuesOut);
    bool DecryptDoubleArrayWithPassword(const std::vector<BYTE>& encryptedData, const std::string& password, std::vector<double>& valuesOut);
    bool DecryptStringArrayWithPassword(const std::vector<BYTE>& encryptedData, const std::string& password, std::vector<std::string>& valuesOut);

    // Encrypt/Decrypt files (with password)
    bool EncryptFileWithPassword(const std::string& inputFile, const std::string& outputFile, const std::string& password);
    bool DecryptFileWithPassword(const std::string& inputFile, const std::string& outputFile, const std::string& password);

    bool            IsTooLargeForTpm(const std::vector<BYTE>& data);
    bool            IsTooLargeForTpm(const std::streamsize dataSize);
    bool            IsTooLargeForTpm(const uint64_t dataSize);
    std::streamsize GetFileSize(const std::string& filePath);
    uint64_t        GetFileSize2(const std::string& filePath);

    bool EncryptFileWithPasswordChunked(const std::string& inputFile, const std::string& outputFile, const std::string& password);
    bool DecryptFileWithPasswordChunked(const std::string& inputFile, const std::string& outputFile, const std::string& password);
    bool CompareFiles(const std::string& file1, const std::string& file2);
    void BuildTestFile(const std::string& inputFile);

    TPM_HANDLE              MakeStoragePrimary(AUTH_SESSION* sess);
    void                    EncryptDecryptSample();

protected:

public:
    // Chunked encrypt/decrypt
    bool EncryptDataChunked(const std::vector<BYTE>& plain, std::vector<BYTE>& encrypted);
    bool DecryptDataChunked(const std::vector<BYTE>& encrypted, std::vector<BYTE>& plain);
    // encrypt/decrypt
    bool EncryptData(const std::vector<BYTE>& plain, std::vector<BYTE>& encrypted);
    bool DecryptData(const std::vector<BYTE>& encrypted, std::vector<BYTE>& plain);
    // encrypt/decrypt internal
    bool EncryptDecryptInternal(const std::vector<BYTE>& inData, std::vector<BYTE>& outData, bool encrypt);

    // Encrypt/Decrypt with Password (PIN-protected AES key)
    // Chunked encrypt/decrypt with password
    bool EncryptDataWithPasswordChunked(const std::string& password, const std::vector<BYTE>& plain, std::vector<BYTE>& encrypted);
    bool DecryptDataWithPasswordChunked(const std::string& password, const std::vector<BYTE>& encrypted, std::vector<BYTE>& plain);
    // encrypt/decrypt with password    
    bool EncryptDataWithPassword(const std::string& password, const std::vector<BYTE>& plain, std::vector<BYTE>& encrypted);
    bool DecryptDataWithPassword(const std::string& password, const std::vector<BYTE>& encrypted, std::vector<BYTE>& plain);
    // encrypt/decrypt internal with password        
    bool EncryptDecryptInternalWithPassword(const std::string& password, const std::vector<BYTE>& inData, std::vector<BYTE>& outData, bool encrypt);



    bool GenerateAndLoadAesKeyWithPassword(const std::string& password);
    bool GenerateAndLoadAesKeyWithPassword(const std::string& password, bool usePersistentKey);
    bool UnloadAndClearAesKeyWithPassword();
    bool RemovePersistentAesKey(UINT32 persistentHandleValue = 0x81000001);
    bool IsAesKeyHandleLoaded() const;
    bool ClearAllAesKeys();

    std::vector<BYTE> ComputePasswordHash(const std::string& password);
    bool StorePasswordHashToNv(const std::vector<BYTE>& hash);
    bool ReadPasswordHashFromNv(std::vector<BYTE>& hashOut);
    bool IsPasswordValidForCurrentAesKey(const std::string& password);


    TPM_HANDLE LoadAesKey(); // Internal helper
    void       FlushAesKey();


    ByteVec m_iv;

private:
    bool m_useSharedTpmDevice;
    CTpmSharedDevice* m_sharedTpmDevice;

    TPM_HANDLE m_aesKeyHandle;  // AES anahtarı için TPM handle
};