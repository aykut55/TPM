#include "TpmSignature.h"

#include <string>       // std::string
#include <iostream>     // std::cout
#include <sstream>      // std::stringstream

CTpmSignature::~CTpmSignature()
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

CTpmSignature::CTpmSignature(CTpmSharedDevice* sharedDevice)
    : m_useSharedTpmDevice(sharedDevice != nullptr), m_sharedTpmDevice(sharedDevice)
{
    try
    {
        if (m_useSharedTpmDevice)
        {
            m_sharedTpmDevice = sharedDevice;
            std::stringstream ss;
            ss << "[CTpmSignature] uses shared CTpmSharedDevice\n";
            Log(ss.str());
        }
        else
        {
            m_sharedTpmDevice = new CTpmSharedDevice();
            std::stringstream ss;
            ss << "[CTpmSignature] uses local  CTpmSharedDevice\n";
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

CTpmSharedDevice* CTpmSignature::GetTpmSharedDevice(void)
{
    return m_sharedTpmDevice;
}

bool CTpmSignature::Release(void)
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

bool CTpmSignature::Initialize(void)
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


std::string CTpmSignature::EncodeHex(const std::vector<BYTE>& data, bool upperCase)
{
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');

    for (BYTE byte : data)
        oss << std::setw(2) << (upperCase ? std::uppercase : std::nouppercase) << static_cast<int>(byte);

    return oss.str();
}

std::vector<BYTE> CTpmSignature::DecodeHex(const std::string& hexStr)
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

std::string CTpmSignature::EncodeBase64(const std::vector<BYTE>& data)
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

std::vector<BYTE> CTpmSignature::DecodeBase64(const std::string& encoded)
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