#include "TpmSlotReader.h"

#include <string>       // std::string
#include <iostream>     // std::cout
#include <sstream>      // std::stringstream

CTpmSlotReader::~CTpmSlotReader()
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

CTpmSlotReader::CTpmSlotReader(CTpmSharedDevice* sharedDevice)
    : m_useSharedTpmDevice(sharedDevice != nullptr), m_sharedTpmDevice(sharedDevice)
{
    try
    {
        if (m_useSharedTpmDevice)
        {
            m_sharedTpmDevice = sharedDevice;
            std::stringstream ss;
            ss << "[CTpmSlotReader] uses shared CTpmSharedDevice\n";
            Log(ss.str());
        }
        else
        {
            m_sharedTpmDevice = new CTpmSharedDevice();
            std::stringstream ss;
            ss << "[CTpmSlotReader] uses local  CTpmSharedDevice\n";
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

CTpmSharedDevice* CTpmSlotReader::GetTpmSharedDevice(void)
{
    return m_sharedTpmDevice;
}

bool CTpmSlotReader::Release(void)
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

bool CTpmSlotReader::Initialize(void)
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

BYTE CTpmSlotReader::ReadByteFromSlot(UINT32 slotNo)
{
    try
    {
        UINT32 nvIndex = TpmSlotReaderNS::BASE_SLOT_INDEX + slotNo;

        auto readData = tpm->NV_Read(TPM_RH::OWNER, nvIndex, 5, 0);
        if (readData.size() < 5)
        {
            Log("ReadByteFromSlot: insufficient data.", true);
            return 0;
        }

        uint32_t tag = (readData[0] << 24) | (readData[1] << 16) | (readData[2] << 8) | readData[3];
        if (static_cast<SlotType>(tag) != SlotType::Byte)
        {
            Log("ReadByteFromSlot: type mismatch.", true);
            return 0;
        }

        BYTE b = readData[4];
        Log("Byte read from slot.");
        return b;
    }
    catch (...)
    {
        Log("ReadByteFromSlot exception", true);
        return 0;
    }
}

char CTpmSlotReader::ReadCharFromSlot(UINT32 slotNo)
{
    try
    {
        UINT32 nvIndex = TpmSlotReaderNS::BASE_SLOT_INDEX + slotNo;

        auto readData = tpm->NV_Read(TPM_RH::OWNER, nvIndex, 5, 0);
        if (readData.size() < 5)
        {
            Log("ReadCharFromSlot: insufficient data.", true);
            return '\0';
        }

        uint32_t tag = (readData[0] << 24) | (readData[1] << 16) | (readData[2] << 8) | readData[3];
        if (static_cast<SlotType>(tag) != SlotType::Char)
        {
            Log("ReadCharFromSlot: type mismatch.", true);
            return '\0';
        }

        char c = static_cast<char>(readData[4]);
        Log("Char read from slot.");
        return c;
    }
    catch (...)
    {
        Log("ReadCharFromSlot exception", true);
        return '\0';
    }
}

int CTpmSlotReader::ReadIntFromSlot(UINT32 slotNo)
{
    try
    {
        if (slotNo >= TpmSlotReaderNS::SLOT_COUNT)
        {
            Log("Invalid slot number.", true);
            return 0;
        }

        UINT32 nvIndex = TpmSlotReaderNS::BASE_SLOT_INDEX + slotNo;

        // tanımlı mı
        auto resp = tpm->GetCapability(TPM_CAP::HANDLES, nvIndex, 1);
        auto handles = dynamic_cast<TPML_HANDLE*>(&*resp.capabilityData)->handle;
        bool exists = false;
        for (auto h : handles)
        {
            if (h == nvIndex)
            {
                exists = true;
                break;
            }
        }

        if (!exists)
        {
            Log("Slot not defined.", true);
            return 0;
        }

        // 8 byte oku (4 type + 4 int)
        auto readData = tpm->NV_Read(TPM_RH::OWNER, nvIndex, 8, 0);

        if (readData.size() < 8)
        {
            Log("ReadIntFromSlot: insufficient data.", true);
            return 0;
        }

        // type kontrolü
        uint32_t tag = 0;
        tag |= readData[0] << 24;
        tag |= readData[1] << 16;
        tag |= readData[2] << 8;
        tag |= readData[3];

        if (static_cast<SlotType>(tag) != SlotType::Int)
        {
            Log("ReadIntFromSlot: type mismatch.", true);
            return 0;
        }

        // asıl integer
        int value = 0;
        if (m_endianness == Endianness::LittleEndian)
        {
            value |= readData[4];
            value |= readData[5] << 8;
            value |= readData[6] << 16;
            value |= readData[7] << 24;
        }
        else
        {
            value |= readData[4] << 24;
            value |= readData[5] << 16;
            value |= readData[6] << 8;
            value |= readData[7];
        }

        Log("Int read from slot successfully.");
        return value;
    }
    catch (const std::exception& ex)
    {
        Log(std::string("ReadIntFromSlot exception: ") + ex.what(), true);
        return 0;
    }
    catch (...)
    {
        Log("ReadIntFromSlot unknown exception.", true);
        return 0;
    }
}

float CTpmSlotReader::ReadFloatFromSlot(UINT32 slotNo)
{
    try
    {
        UINT32 nvIndex = TpmSlotReaderNS::BASE_SLOT_INDEX + slotNo;

        auto readData = tpm->NV_Read(TPM_RH::OWNER, nvIndex, 8, 0);
        if (readData.size() < 8)
        {
            Log("ReadFloatFromSlot: insufficient data.", true);
            return 0.0f;
        }

        uint32_t tag = (readData[0] << 24) | (readData[1] << 16) | (readData[2] << 8) | readData[3];
        if (static_cast<SlotType>(tag) != SlotType::Float)
        {
            Log("ReadFloatFromSlot: type mismatch.", true);
            return 0.0f;
        }

        uint32_t raw = 0;
        if (m_endianness == Endianness::LittleEndian)
        {
            raw |= readData[4];
            raw |= readData[5] << 8;
            raw |= readData[6] << 16;
            raw |= readData[7] << 24;
        }
        else
        {
            raw |= readData[4] << 24;
            raw |= readData[5] << 16;
            raw |= readData[6] << 8;
            raw |= readData[7];
        }

        float value;
        std::memcpy(&value, &raw, sizeof(value));
        Log("Float read from slot.");
        return value;
    }
    catch (...)
    {
        Log("ReadFloatFromSlot exception", true);
        return 0.0f;
    }
}

double CTpmSlotReader::ReadDoubleFromSlot(UINT32 slotNo)
{
    try
    {
        UINT32 nvIndex = TpmSlotReaderNS::BASE_SLOT_INDEX + slotNo;

        auto readData = tpm->NV_Read(TPM_RH::OWNER, nvIndex, 12, 0);
        if (readData.size() < 12)
        {
            Log("ReadDoubleFromSlot: insufficient data.", true);
            return 0.0;
        }

        uint32_t tag = (readData[0] << 24) | (readData[1] << 16) | (readData[2] << 8) | readData[3];
        if (static_cast<SlotType>(tag) != SlotType::Double)
        {
            Log("ReadDoubleFromSlot: type mismatch.", true);
            return 0.0;
        }

        uint64_t raw = 0;
        if (m_endianness == Endianness::LittleEndian)
        {
            for (int i = 0; i < 8; ++i)
                raw |= static_cast<uint64_t>(readData[4 + i]) << (8 * i);
        }
        else
        {
            for (int i = 0; i < 8; ++i)
                raw |= static_cast<uint64_t>(readData[4 + i]) << (8 * (7 - i));
        }

        double value;
        std::memcpy(&value, &raw, sizeof(value));
        Log("Double read from slot.");
        return value;
    }
    catch (...)
    {
        Log("ReadDoubleFromSlot exception", true);
        return 0.0;
    }
}

std::string CTpmSlotReader::ReadStringFromSlot(UINT32 slotNo)
{
    try
    {
        UINT32 nvIndex = TpmSlotReaderNS::BASE_SLOT_INDEX + slotNo;

        auto readData = tpm->NV_Read(TPM_RH::OWNER, nvIndex, TpmSlotReaderNS::SLOT_SIZE, 0);
        if (readData.size() < 4)
        {
            Log("ReadStringFromSlot: insufficient data.", true);
            return "";
        }

        uint32_t tag = (readData[0] << 24) | (readData[1] << 16) | (readData[2] << 8) | readData[3];
        if (static_cast<SlotType>(tag) != SlotType::String)
        {
            Log("ReadStringFromSlot: type mismatch.", true);
            return "";
        }

        std::string s(readData.begin() + 4, readData.end());
        // trim nulls
        auto zeroPos = s.find('\0');
        if (zeroPos != std::string::npos)
            s.resize(zeroPos);

        Log("String read from slot.");
        return s;
    }
    catch (...)
    {
        Log("ReadStringFromSlot exception", true);
        return "";
    }
}

std::vector<BYTE> CTpmSlotReader::ReadByteArrayFromSlot(UINT32 slotNo, size_t count)
{
    std::vector<BYTE> result;
    try
    {
        if (slotNo >= TpmSlotReaderNS::SLOT_COUNT)
            return result;

        UINT32 nvIndex = TpmSlotReaderNS::BASE_SLOT_INDEX + slotNo;
        auto readData = tpm->NV_Read(TPM_RH::OWNER, nvIndex, TpmSlotReaderNS::SLOT_SIZE, 0);
        if (readData.size() < 4)
        {
            Log("ReadByteArrayFromSlot: insufficient data.", true);
            return result;
        }

        uint32_t tag = (readData[0] << 24) | (readData[1] << 16) | (readData[2] << 8) | readData[3];
        if (static_cast<SlotType>(tag) != SlotType::ByteArray)
        {
            Log("ReadByteArrayFromSlot: type mismatch.", true);
            return result;
        }

        result.insert(result.end(), readData.begin() + 4, readData.end());
        Log("Byte array read from slot.");
    }
    catch (...)
    {
        Log("ReadByteArrayFromSlot exception", true);
    }
    return result;
}

std::vector<char> CTpmSlotReader::ReadCharArrayFromSlot(UINT32 slotNo, size_t count)
{
    std::vector<char> result;
    try
    {
        if (slotNo >= TpmSlotReaderNS::SLOT_COUNT)
            return result;

        UINT32 nvIndex = TpmSlotReaderNS::BASE_SLOT_INDEX + slotNo;
        auto readData = tpm->NV_Read(TPM_RH::OWNER, nvIndex, TpmSlotReaderNS::SLOT_SIZE, 0);
        if (readData.size() < 4)
        {
            Log("ReadCharArrayFromSlot: insufficient data.", true);
            return result;
        }

        uint32_t tag = (readData[0] << 24) | (readData[1] << 16) | (readData[2] << 8) | readData[3];
        if (static_cast<SlotType>(tag) != SlotType::CharArray)
        {
            Log("ReadCharArrayFromSlot: type mismatch.", true);
            return result;
        }

        result.insert(result.end(), readData.begin() + 4, readData.end());
        Log("Char array read from slot.");
    }
    catch (...)
    {
        Log("ReadCharArrayFromSlot exception", true);
    }
    return result;
}

std::vector<int> CTpmSlotReader::ReadIntArrayFromSlot(UINT32 slotNo, size_t count)
{
    std::vector<int> result;
    try
    {
        if (slotNo >= TpmSlotReaderNS::SLOT_COUNT)
            return result;

        UINT32 nvIndex = TpmSlotReaderNS::BASE_SLOT_INDEX + slotNo;

        auto readData = tpm->NV_Read(TPM_RH::OWNER, nvIndex, TpmSlotReaderNS::SLOT_SIZE, 0);

        if (readData.size() < 4)
        {
            Log("ReadIntArrayFromSlot: insufficient data.", true);
            return result;
        }

        // check type
        uint32_t tag = (readData[0] << 24) | (readData[1] << 16) | (readData[2] << 8) | readData[3];
        if (static_cast<SlotType>(tag) != SlotType::IntArray)
        {
            Log("ReadIntArrayFromSlot: type mismatch.", true);
            return result;
        }

        size_t count = (readData.size() - 4) / 4;

        for (size_t i = 0; i < count; ++i)
        {
            int v = 0;
            size_t idx = 4 + i * 4;

            if (m_endianness == Endianness::LittleEndian)
            {
                v |= readData[idx];
                v |= readData[idx + 1] << 8;
                v |= readData[idx + 2] << 16;
                v |= readData[idx + 3] << 24;
            }
            else
            {
                v |= readData[idx] << 24;
                v |= readData[idx + 1] << 16;
                v |= readData[idx + 2] << 8;
                v |= readData[idx + 3];
            }
            result.push_back(v);
        }
        Log("Int array read from slot.");
    }
    catch (...)
    {
        Log("ReadIntArrayFromSlot exception", true);
    }
    return result;
}

std::vector<float> CTpmSlotReader::ReadFloatArrayFromSlot(UINT32 slotNo, size_t count)
{
    std::vector<float> result;
    try
    {
        if (slotNo >= TpmSlotReaderNS::SLOT_COUNT)
            return result;

        UINT32 nvIndex = TpmSlotReaderNS::BASE_SLOT_INDEX + slotNo;
        auto readData = tpm->NV_Read(TPM_RH::OWNER, nvIndex, TpmSlotReaderNS::SLOT_SIZE, 0);

        if (readData.size() < 4)
        {
            Log("ReadFloatArrayFromSlot: insufficient data.", true);
            return result;
        }

        uint32_t tag = (readData[0] << 24) | (readData[1] << 16) | (readData[2] << 8) | readData[3];
        if (static_cast<SlotType>(tag) != SlotType::FloatArray)
        {
            Log("ReadFloatArrayFromSlot: type mismatch.", true);
            return result;
        }

        size_t count = (readData.size() - 4) / 4;
        for (size_t i = 0; i < count; ++i)
        {
            uint32_t raw = 0;
            size_t idx = 4 + i * 4;
            if (m_endianness == Endianness::LittleEndian)
            {
                raw |= readData[idx];
                raw |= readData[idx + 1] << 8;
                raw |= readData[idx + 2] << 16;
                raw |= readData[idx + 3] << 24;
            }
            else
            {
                raw |= readData[idx] << 24;
                raw |= readData[idx + 1] << 16;
                raw |= readData[idx + 2] << 8;
                raw |= readData[idx + 3];
            }
            float f;
            std::memcpy(&f, &raw, sizeof(f));
            result.push_back(f);
        }
        Log("Float array read from slot.");
    }
    catch (...)
    {
        Log("ReadFloatArrayFromSlot exception", true);
    }
    return result;
}

std::vector<double> CTpmSlotReader::ReadDoubleArrayFromSlot(UINT32 slotNo, size_t count)
{
    std::vector<double> result;
    try
    {
        if (slotNo >= TpmSlotReaderNS::SLOT_COUNT)
            return result;

        UINT32 nvIndex = TpmSlotReaderNS::BASE_SLOT_INDEX + slotNo;
        auto readData = tpm->NV_Read(TPM_RH::OWNER, nvIndex, TpmSlotReaderNS::SLOT_SIZE, 0);
        if (readData.size() < 4)
        {
            Log("ReadDoubleArrayFromSlot: insufficient data.", true);
            return result;
        }

        uint32_t tag = (readData[0] << 24) | (readData[1] << 16) | (readData[2] << 8) | readData[3];
        if (static_cast<SlotType>(tag) != SlotType::DoubleArray)
        {
            Log("ReadDoubleArrayFromSlot: type mismatch.", true);
            return result;
        }

        size_t count = (readData.size() - 4) / 8;
        for (size_t i = 0; i < count; ++i)
        {
            uint64_t raw = 0;
            size_t idx = 4 + i * 8;
            if (m_endianness == Endianness::LittleEndian)
            {
                for (int j = 0; j < 8; ++j)
                    raw |= static_cast<uint64_t>(readData[idx + j]) << (8 * j);
            }
            else
            {
                for (int j = 0; j < 8; ++j)
                    raw |= static_cast<uint64_t>(readData[idx + j]) << (8 * (7 - j));
            }
            double d;
            std::memcpy(&d, &raw, sizeof(d));
            result.push_back(d);
        }
        Log("Double array read from slot.");
    }
    catch (...)
    {
        Log("ReadDoubleArrayFromSlot exception", true);
    }
    return result;
}

std::vector<std::string> CTpmSlotReader::ReadStringArrayFromSlot(UINT32 slotNo)
{
    std::vector<std::string> result;
    try
    {
        if (slotNo >= TpmSlotReaderNS::SLOT_COUNT)
            return result;

        UINT32 nvIndex = TpmSlotReaderNS::BASE_SLOT_INDEX + slotNo;

        auto readData = tpm->NV_Read(TPM_RH::OWNER, nvIndex, TpmSlotReaderNS::SLOT_SIZE, 0);
        if (readData.size() < 4)
        {
            Log("ReadStringArrayFromSlot: insufficient data.", true);
            return result;
        }

        uint32_t tag = (readData[0] << 24) | (readData[1] << 16) | (readData[2] << 8) | readData[3];
        if (static_cast<SlotType>(tag) != SlotType::StringArray)
        {
            Log("ReadStringArrayFromSlot: type mismatch.", true);
            return result;
        }

        std::string allStrings(readData.begin() + 4, readData.end());
        std::istringstream ss(allStrings);
        std::string token;

        while (std::getline(ss, token, '\0'))
        {
            if (!token.empty())
                result.push_back(token);
        }

        Log("String array read from slot.");
    }
    catch (...)
    {
        Log("ReadStringArrayFromSlot exception", true);
    }
    return result;
}

void CTpmSlotReader::SetEndianness(Endianness mode)
{
    m_endianness = mode;
}

Endianness CTpmSlotReader::GetEndianness() const
{
    return m_endianness;
}

bool CTpmSlotReader::SlotClear(UINT32 slotNo)
{
    try
    {
        if (slotNo >= TpmSlotReaderNS::SLOT_COUNT)
        {
            Log("Invalid slot number.", true);
            return false;
        }

        UINT32 nvIndex = TpmSlotReaderNS::BASE_SLOT_INDEX + slotNo;

        // NV alanı tanımlı mı kontrol et
        auto resp = tpm->GetCapability(TPM_CAP::HANDLES, nvIndex, 1);
        auto handles = dynamic_cast<TPML_HANDLE*>(&*resp.capabilityData)->handle;
        bool exists = false;
        for (auto h : handles)
        {
            if (h == nvIndex)
            {
                exists = true;
                break;
            }
        }

        if (!exists)
        {
            Log("Slot not defined, cannot clear.", true);
            return false;
        }

        // 0x00 buffer
        std::vector<BYTE> zeroData(TpmSlotReaderNS::SLOT_SIZE, 0x00);

        tpm->NV_Write(TPM_RH::OWNER, nvIndex, zeroData, 0);
        Log("Slot cleared successfully.");
        return true;
    }
    catch (const std::exception& ex)
    {
        m_lastError = ex.what();
        Log(std::string("SlotClear exception: ") + ex.what(), true);
        return false;
    }
    catch (...)
    {
        Log("SlotClear unknown exception.", true);
        return false;
    }
}

bool CTpmSlotReader::SlotFree(UINT32 slotNo)
{
    try
    {
        if (slotNo >= TpmSlotReaderNS::SLOT_COUNT)
        {
            Log("Invalid slot number.", true);
            return false;
        }

        UINT32 nvIndex = TpmSlotReaderNS::BASE_SLOT_INDEX + slotNo;

        // NV alanı tanımlı mı kontrol et
        auto resp = tpm->GetCapability(TPM_CAP::HANDLES, nvIndex, 1);
        auto handles = dynamic_cast<TPML_HANDLE*>(&*resp.capabilityData)->handle;
        bool exists = false;
        for (auto h : handles)
        {
            if (h == nvIndex)
            {
                exists = true;
                break;
            }
        }

        if (!exists)
        {
            Log("Slot not defined, cannot free.", true);
            return false;
        }

        tpm->NV_UndefineSpace(TPM_RH::OWNER, nvIndex);
        Log("Slot freed successfully.");
        return true;
    }
    catch (const std::exception& ex)
    {
        m_lastError = ex.what();
        Log(std::string("SlotFree exception: ") + ex.what(), true);
        return false;
    }
    catch (...)
    {
        Log("SlotFree unknown exception.", true);
        return false;
    }
}

std::vector<SlotInfo> CTpmSlotReader::SlotList()
{
    std::vector<SlotInfo> result;

    for (UINT32 slotNo = 0; slotNo < TpmSlotReaderNS::SLOT_COUNT; ++slotNo)
    {
        UINT32 nvIndex = TpmSlotReaderNS::BASE_SLOT_INDEX + slotNo;
        bool defined = false;
        SlotType type = SlotType::Unknown;

        try
        {
            auto resp = tpm->GetCapability(TPM_CAP::HANDLES, nvIndex, 1);
            auto handles = dynamic_cast<TPML_HANDLE*>(&*resp.capabilityData)->handle;

            for (auto h : handles)
            {
                if (h == nvIndex)
                {
                    defined = true;

                    // ilk 4 byte: type imzası
                    auto readData = tpm->NV_Read(TPM_RH::OWNER, nvIndex, 4, 0);
                    if (readData.size() >= 4)
                    {
                        uint32_t tag = 0;
                        tag |= readData[0] << 24;
                        tag |= readData[1] << 16;
                        tag |= readData[2] << 8;
                        tag |= readData[3];
                        type = static_cast<SlotType>(tag);
                    }
                    break;
                }
            }
        }
        catch (...)
        {
            defined = false;
            type = SlotType::Unknown;
        }

        result.push_back({ slotNo, defined, type });
    }
    return result;
}