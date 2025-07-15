#include "TpmHash.h"

#include <string>       // std::string
#include <iostream>     // std::cout
#include <sstream>      // std::stringstream
#include <fstream>      // std::ofstream
#include <vector>       // ...

CTpmHash::~CTpmHash()
{
    try
    {
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

CTpmHash::CTpmHash(CTpmSharedDevice* sharedDevice)
    : m_useSharedTpmDevice(sharedDevice != nullptr), m_sharedTpmDevice(sharedDevice)
{
    try
    {
        if (m_useSharedTpmDevice)
        {
            m_sharedTpmDevice = sharedDevice;
            std::stringstream ss;
            ss << "[CTpmHash] uses shared CTpmSharedDevice\n";
            Log(ss.str());
        }
        else
        {
            m_sharedTpmDevice = new CTpmSharedDevice();
            std::stringstream ss;
            ss << "[CTpmHash] uses local  CTpmSharedDevice\n";
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

CTpmSharedDevice* CTpmHash::GetTpmSharedDevice(void)
{
    return m_sharedTpmDevice;
}

bool CTpmHash::Release(void)
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

bool CTpmHash::Initialize(void)
{
    bool fncReturn = false;

    try
    {
        fncReturn = true;
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

bool CTpmHash::HashData(TPM_ALG_ID hashAlg, const std::vector<BYTE>& plain, std::vector<BYTE>& hashed)
{
    try
    {
        HashResponse response = tpm->Hash(
            plain,                   // Verinin tamamı
            hashAlg,                 // Algoritma (SHA256, SHA1, vb)
            TPM_RH::_NULL            // No hierarchy
        );

        hashed = response.outHash;
        return true;
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[CTpmHash] HashData exception: " << ex.what() << std::endl;
        return false;
    }
}

bool CTpmHash::HashDataChunked(TPM_ALG_ID hashAlg, const std::vector<BYTE>& plain, std::vector<BYTE>& hashed)
{
    try
    {
        if (!tpm)
        {
            std::cerr << "[CTpmHash] TPM instance not initialized.\n";
            return false;
        }

        const size_t CHUNK_SIZE = 1024;

        // 1. Hash başlangıcını başlat
        auto startResponse = tpm->HashSequenceStart({}, hashAlg);
        TPM_HANDLE seqHandle = startResponse.handle;

        size_t offset = 0;
        while (offset < plain.size())
        {
            size_t chunkSize = std::min(CHUNK_SIZE, plain.size() - offset);
            std::vector<BYTE> chunk(plain.begin() + offset, plain.begin() + offset + chunkSize);
            tpm->SequenceUpdate(seqHandle, chunk);
            offset += chunkSize;
        }

        // 2. Bitir ve sonucu al
        SequenceCompleteResponse completeResp = tpm->SequenceComplete(
            seqHandle,
            {},                   // Kalan veri yok
            TPM_RH::_NULL         // Hierarchy = NULL (NONE)
        );

        hashed = completeResp.result;
        return true;
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[CTpmHash] HashDataChunked exception: " << ex.what() << std::endl;
        return false;
    }
}

bool CTpmHash::HashByte(TPM_ALG_ID hashAlg, BYTE value, std::vector<BYTE>& hashOut)
{
    std::vector<BYTE> buffer(1, value);
    return HashData(hashAlg, buffer, hashOut);
}

bool CTpmHash::HashChar(TPM_ALG_ID hashAlg, char value, std::vector<BYTE>& hashOut)
{
    std::vector<BYTE> buffer(1, static_cast<BYTE>(value));
    return HashData(hashAlg, buffer, hashOut);
}

bool CTpmHash::HashInt(TPM_ALG_ID hashAlg, int value, std::vector<BYTE>& hashOut)
{
    std::vector<BYTE> buffer(sizeof(int));
    std::memcpy(buffer.data(), &value, sizeof(int));
    return HashData(hashAlg, buffer, hashOut);
}

bool CTpmHash::HashFloat(TPM_ALG_ID hashAlg, float value, std::vector<BYTE>& hashOut)
{
    std::vector<BYTE> buffer(sizeof(float));
    std::memcpy(buffer.data(), &value, sizeof(float));
    return HashData(hashAlg, buffer, hashOut);
}

bool CTpmHash::HashDouble(TPM_ALG_ID hashAlg, double value, std::vector<BYTE>& hashOut)
{
    std::vector<BYTE> buffer(sizeof(double));
    std::memcpy(buffer.data(), &value, sizeof(double));
    return HashData(hashAlg, buffer, hashOut);
}

bool CTpmHash::HashString(TPM_ALG_ID hashAlg, const std::string& str, std::vector<BYTE>& hashOut)
{
    const BYTE* data = reinterpret_cast<const BYTE*>(str.data());
    std::vector<BYTE> buffer(data, data + str.size());
    return HashData(hashAlg, buffer, hashOut);
}

bool CTpmHash::HashByteArray(TPM_ALG_ID hashAlg, const std::vector<BYTE>& values, std::vector<BYTE>& hashOut)
{
    return HashData(hashAlg, values, hashOut);
}

bool CTpmHash::HashCharArray(TPM_ALG_ID hashAlg, const std::vector<char>& values, std::vector<BYTE>& hashOut)
{
    std::vector<BYTE> buffer(values.begin(), values.end());
    return HashData(hashAlg, buffer, hashOut);
}

bool CTpmHash::HashIntArray(TPM_ALG_ID hashAlg, const std::vector<int>& values, std::vector<BYTE>& hashOut)
{
    std::vector<BYTE> buffer(values.size() * sizeof(int));
    std::memcpy(buffer.data(), values.data(), buffer.size());
    return HashData(hashAlg, buffer, hashOut);
}

bool CTpmHash::HashFloatArray(TPM_ALG_ID hashAlg, const std::vector<float>& values, std::vector<BYTE>& hashOut)
{
    std::vector<BYTE> buffer(values.size() * sizeof(float));
    std::memcpy(buffer.data(), values.data(), buffer.size());
    return HashData(hashAlg, buffer, hashOut);
}

bool CTpmHash::HashDoubleArray(TPM_ALG_ID hashAlg, const std::vector<double>& values, std::vector<BYTE>& hashOut)
{
    std::vector<BYTE> buffer(values.size() * sizeof(double));
    std::memcpy(buffer.data(), values.data(), buffer.size());
    return HashData(hashAlg, buffer, hashOut);
}

bool CTpmHash::HashStringArray(TPM_ALG_ID hashAlg, const std::vector<std::string>& values, std::vector<BYTE>& hashOut)
{
    std::vector<BYTE> buffer;
    for (const auto& str : values)
    {
        uint32_t len = static_cast<uint32_t>(str.size());
        buffer.insert(buffer.end(), reinterpret_cast<BYTE*>(&len), reinterpret_cast<BYTE*>(&len) + sizeof(len));
        buffer.insert(buffer.end(), str.begin(), str.end());
    }
    return HashData(hashAlg, buffer, hashOut);
}

bool CTpmHash::HashFile(TPM_ALG_ID hashAlg, const std::string& inputFile, std::vector<BYTE>& hashOut)
{
    try
    {
        // 1. Dosyayı tamamen oku
        std::ifstream in(inputFile, std::ios::binary | std::ios::ate);
        if (!in.is_open())
        {
            std::cerr << "[CTpmHash] Failed to open input file: " << inputFile << std::endl;
            return false;
        }

        std::streamsize size = in.tellg();
        in.seekg(0, std::ios::beg);

        std::vector<BYTE> buffer(static_cast<size_t>(size));
        if (!in.read(reinterpret_cast<char*>(buffer.data()), size))
        {
            std::cerr << "[CTpmHash] Failed to read input file: " << inputFile << std::endl;
            return false;
        }

        in.close();

        // 2. Hash işlemi yap
        if (!HashData(hashAlg, buffer, hashOut))
        {
            std::cerr << "[CTpmHash] HashData failed for file: " << inputFile << std::endl;
            return false;
        }

        return true;
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[CTpmHash] HashFile exception: " << ex.what() << std::endl;
        return false;
    }
}


bool CTpmHash::HashByteChunked(TPM_ALG_ID hashAlg, BYTE value, std::vector<BYTE>& hashOut)
{
    std::vector<BYTE> buffer(1, value);
    return HashDataChunked(hashAlg, buffer, hashOut);
}

bool CTpmHash::HashCharChunked(TPM_ALG_ID hashAlg, char value, std::vector<BYTE>& hashOut)
{
    std::vector<BYTE> buffer(1, static_cast<BYTE>(value));
    return HashDataChunked(hashAlg, buffer, hashOut);
}

bool CTpmHash::HashIntChunked(TPM_ALG_ID hashAlg, int value, std::vector<BYTE>& hashOut)
{
    std::vector<BYTE> buffer(sizeof(int));
    std::memcpy(buffer.data(), &value, sizeof(int));
    return HashDataChunked(hashAlg, buffer, hashOut);
}

bool CTpmHash::HashFloatChunked(TPM_ALG_ID hashAlg, float value, std::vector<BYTE>& hashOut)
{
    std::vector<BYTE> buffer(sizeof(float));
    std::memcpy(buffer.data(), &value, sizeof(float));
    return HashDataChunked(hashAlg, buffer, hashOut);
}

bool CTpmHash::HashDoubleChunked(TPM_ALG_ID hashAlg, double value, std::vector<BYTE>& hashOut)
{
    std::vector<BYTE> buffer(sizeof(double));
    std::memcpy(buffer.data(), &value, sizeof(double));
    return HashDataChunked(hashAlg, buffer, hashOut);
}

bool CTpmHash::HashStringChunked(TPM_ALG_ID hashAlg, const std::string& str, std::vector<BYTE>& hashOut)
{
    const BYTE* data = reinterpret_cast<const BYTE*>(str.data());
    std::vector<BYTE> buffer(data, data + str.size());
    return HashDataChunked(hashAlg, buffer, hashOut);
}

bool CTpmHash::HashByteArrayChunked(TPM_ALG_ID hashAlg, const std::vector<BYTE>& values, std::vector<BYTE>& hashOut)
{
    return HashDataChunked(hashAlg, values, hashOut);
}

bool CTpmHash::HashCharArrayChunked(TPM_ALG_ID hashAlg, const std::vector<char>& values, std::vector<BYTE>& hashOut)
{
    std::vector<BYTE> buffer(values.begin(), values.end());
    return HashDataChunked(hashAlg, buffer, hashOut);
}

bool CTpmHash::HashIntArrayChunked(TPM_ALG_ID hashAlg, const std::vector<int>& values, std::vector<BYTE>& hashOut)
{
    std::vector<BYTE> buffer(values.size() * sizeof(int));
    std::memcpy(buffer.data(), values.data(), buffer.size());
    return HashDataChunked(hashAlg, buffer, hashOut);
}

bool CTpmHash::HashFloatArrayChunked(TPM_ALG_ID hashAlg, const std::vector<float>& values, std::vector<BYTE>& hashOut)
{
    std::vector<BYTE> buffer(values.size() * sizeof(float));
    std::memcpy(buffer.data(), values.data(), buffer.size());
    return HashDataChunked(hashAlg, buffer, hashOut);
}

bool CTpmHash::HashDoubleArrayChunked(TPM_ALG_ID hashAlg, const std::vector<double>& values, std::vector<BYTE>& hashOut)
{
    std::vector<BYTE> buffer(values.size() * sizeof(double));
    std::memcpy(buffer.data(), values.data(), buffer.size());
    return HashDataChunked(hashAlg, buffer, hashOut);
}

bool CTpmHash::HashStringArrayChunked(TPM_ALG_ID hashAlg, const std::vector<std::string>& values, std::vector<BYTE>& hashOut)
{
    std::vector<BYTE> buffer;
    for (const auto& str : values)
    {
        uint32_t len = static_cast<uint32_t>(str.size());
        buffer.insert(buffer.end(), reinterpret_cast<BYTE*>(&len), reinterpret_cast<BYTE*>(&len) + sizeof(len));
        buffer.insert(buffer.end(), str.begin(), str.end());
    }
    return HashDataChunked(hashAlg, buffer, hashOut);
}

bool CTpmHash::HashFileChunked(TPM_ALG_ID hashAlg, const std::string& inputFile, std::vector<BYTE>& hashOut, size_t chunkSize, std::function<void(size_t bytesProcessed, size_t bytesTotal)> progressCallback)
{
    try
    {
        std::ifstream in(inputFile, std::ios::binary | std::ios::ate);
        if (!in.is_open())
        {
            std::cerr << "[CTpmHash] Failed to open input file: " << inputFile << std::endl;
            return false;
        }

        size_t totalSize = static_cast<size_t>(in.tellg());
        in.seekg(0, std::ios::beg);

        TPM_HANDLE sequenceHandle = tpm->HashSequenceStart({}, hashAlg);
        sequenceHandle.SetAuth({});

        std::vector<BYTE> buffer(chunkSize);
        size_t totalBytesProcessed = 0;

        while (in)
        {
            in.read(reinterpret_cast<char*>(buffer.data()), chunkSize);
            std::streamsize bytesRead = in.gcount();
            if (bytesRead > 0)
            {
                std::vector<BYTE> chunk(buffer.begin(), buffer.begin() + bytesRead);
                tpm->SequenceUpdate(sequenceHandle, chunk);

                totalBytesProcessed += static_cast<size_t>(bytesRead);
                if (progressCallback)
                    progressCallback(totalBytesProcessed, totalSize);
            }
        }
        // Tamamlandıktan sonra:
        if (totalBytesProcessed <= totalSize && progressCallback)
            progressCallback(totalSize, totalSize);

        in.close();

        SequenceCompleteResponse finalHash = tpm->SequenceComplete(
            sequenceHandle,
            {},             // Ek veri (yok)
            TPM_RH::_NULL   // No hierarchy
        );

        hashOut = finalHash.result;
        return true;
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[CTpmHash] HashFileChunked exception: " << ex.what() << std::endl;
        return false;
    }
}


std::string CTpmHash::EncodeHex(const std::vector<BYTE>& data, bool upperCase)
{
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');

    for (BYTE byte : data)
        oss << std::setw(2) << (upperCase ? std::uppercase : std::nouppercase) << static_cast<int>(byte);

    return oss.str();
}

std::vector<BYTE> CTpmHash::DecodeHex(const std::string& hexStr)
{
    std::vector<BYTE> result;

    if (hexStr.length() % 2 != 0)
        return result;

    for (size_t i = 0; i < hexStr.length(); i += 2)
    {
        std::string byteString = hexStr.substr(i, 2);
        BYTE byte = static_cast<BYTE>(strtoul(byteString.c_str(), nullptr, 16));
        result.push_back(byte);
    }

    return result;
}

std::string CTpmHash::EncodeBase64(const std::vector<BYTE>& data)
{
    static const char* base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    std::string encoded;
    int val = 0, valb = -6;

    for (BYTE c : data)
    {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0)
        {
            encoded.push_back(base64_chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }

    if (valb > -6)
        encoded.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);

    while (encoded.size() % 4)
        encoded.push_back('=');

    return encoded;
}

std::vector<BYTE> CTpmHash::DecodeBase64(const std::string& encoded)
{
    static const int decoding_table[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,  // 0-7
        -1,-1,-1,-1,-1,-1,-1,-1,  // 8-15
        -1,-1,-1,-1,-1,-1,-1,-1,  // ...
        -1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,62,-1,-1,-1,63,  // '+', '/'
        52,53,54,55,56,57,58,59,60,61, // '0'–'9'
        -1,-1,-1,-1,-1,-1,-1,
        0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19, // 'A'–'T'
        20,21,22,23,24,25,
        -1,-1,-1,-1,-1,
        26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51 // 'a'–'z'
    };

    std::vector<BYTE> decoded;
    int val = 0, valb = -8;

    for (char c : encoded)
    {
        if (c == '=' || c < 0 || decoding_table[(unsigned char)c] == -1)
            break;
        val = (val << 6) + decoding_table[(unsigned char)c];
        valb += 6;
        if (valb >= 0)
        {
            decoded.push_back(static_cast<BYTE>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }

    return decoded;
}
