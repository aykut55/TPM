#pragma once

#include "TpmBaseClass.h"
#include "TpmSharedDevice.h"

#include "TpmSlotDefinitions.h"

using namespace TpmCpp;

namespace TpmHashNS
{
    constexpr UINT32 BASE_SLOT_INDEX = 0x01510000;
    constexpr UINT32 SLOT_COUNT = 8;
    constexpr UINT32 SLOT_SIZE = 1024; // 1KB
}

class CTpmHash : public CTpmBaseClass
{
public:
    virtual ~CTpmHash();
             CTpmHash(CTpmSharedDevice* sharedDevice = nullptr);

    CTpmSharedDevice*        GetTpmSharedDevice(void);
    bool                     Release(void);
    bool                     Initialize(void);

    // Core hashing
    bool HashData(TPM_ALG_ID hashAlg, const std::vector<BYTE>& plain, std::vector<BYTE>& hashed);
    bool HashDataChunked(TPM_ALG_ID hashAlg, const std::vector<BYTE>& plain, std::vector<BYTE>& hashed);

    // Simple types
    bool HashByte(TPM_ALG_ID hashAlg, BYTE value, std::vector<BYTE>& hashOut);
    bool HashChar(TPM_ALG_ID hashAlg, char value, std::vector<BYTE>& hashOut);
    bool HashInt(TPM_ALG_ID hashAlg, int value, std::vector<BYTE>& hashOut);
    bool HashFloat(TPM_ALG_ID hashAlg, float value, std::vector<BYTE>& hashOut);
    bool HashDouble(TPM_ALG_ID hashAlg, double value, std::vector<BYTE>& hashOut);
    bool HashString(TPM_ALG_ID hashAlg, const std::string& str, std::vector<BYTE>& hashOut);

    // Array types
    bool HashByteArray(TPM_ALG_ID hashAlg, const std::vector<BYTE>& values, std::vector<BYTE>& hashOut);
    bool HashCharArray(TPM_ALG_ID hashAlg, const std::vector<char>& values, std::vector<BYTE>& hashOut);
    bool HashIntArray(TPM_ALG_ID hashAlg, const std::vector<int>& values, std::vector<BYTE>& hashOut);
    bool HashFloatArray(TPM_ALG_ID hashAlg, const std::vector<float>& values, std::vector<BYTE>& hashOut);
    bool HashDoubleArray(TPM_ALG_ID hashAlg, const std::vector<double>& values, std::vector<BYTE>& hashOut);
    bool HashStringArray(TPM_ALG_ID hashAlg, const std::vector<std::string>& values, std::vector<BYTE>& hashOut);

    // File hashing (non-chunked)
    bool HashFile(TPM_ALG_ID hashAlg, const std::string& inputFile, std::vector<BYTE>& hashOut);

    // Chunked - simple types
    bool HashByteChunked(TPM_ALG_ID hashAlg, BYTE value, std::vector<BYTE>& hashOut);
    bool HashCharChunked(TPM_ALG_ID hashAlg, char value, std::vector<BYTE>& hashOut);
    bool HashIntChunked(TPM_ALG_ID hashAlg, int value, std::vector<BYTE>& hashOut);
    bool HashFloatChunked(TPM_ALG_ID hashAlg, float value, std::vector<BYTE>& hashOut);
    bool HashDoubleChunked(TPM_ALG_ID hashAlg, double value, std::vector<BYTE>& hashOut);
    bool HashStringChunked(TPM_ALG_ID hashAlg, const std::string& str, std::vector<BYTE>& hashOut);

    // Chunked - array types
    bool HashByteArrayChunked(TPM_ALG_ID hashAlg, const std::vector<BYTE>& values, std::vector<BYTE>& hashOut);
    bool HashCharArrayChunked(TPM_ALG_ID hashAlg, const std::vector<char>& values, std::vector<BYTE>& hashOut);
    bool HashIntArrayChunked(TPM_ALG_ID hashAlg, const std::vector<int>& values, std::vector<BYTE>& hashOut);
    bool HashFloatArrayChunked(TPM_ALG_ID hashAlg, const std::vector<float>& values, std::vector<BYTE>& hashOut);
    bool HashDoubleArrayChunked(TPM_ALG_ID hashAlg, const std::vector<double>& values, std::vector<BYTE>& hashOut);
    bool HashStringArrayChunked(TPM_ALG_ID hashAlg, const std::vector<std::string>& values, std::vector<BYTE>& hashOut);

    // Chunked - file hashing
    bool HashFileChunked(TPM_ALG_ID hashAlg, const std::string& inputFile, std::vector<BYTE>& hashOut, size_t chunkSize, std::function<void(size_t bytesProcessed, size_t bytesTotal)> progressCallback = nullptr);

    // Base64 encode/decode
    static std::string EncodeBase64(const std::vector<BYTE>& data);
    static std::vector<BYTE> DecodeBase64(const std::string& encoded);

    // Hex encode/decode
    static std::string EncodeHex(const std::vector<BYTE>& data, bool upperCase = false);
    static std::vector<BYTE> DecodeHex(const std::string& hexStr);

protected:

private:
    bool m_useSharedTpmDevice;
    CTpmSharedDevice* m_sharedTpmDevice;
};