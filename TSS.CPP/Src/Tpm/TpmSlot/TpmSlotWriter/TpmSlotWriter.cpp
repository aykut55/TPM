#include "TpmSlotWriter.h"

#include <string>       // std::string
#include <iostream>     // std::cout
#include <sstream>      // std::stringstream

CTpmSlotWriter::~CTpmSlotWriter()
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

CTpmSlotWriter::CTpmSlotWriter(CTpmSharedDevice* sharedDevice)
    : m_useSharedTpmDevice(sharedDevice != nullptr), m_sharedTpmDevice(sharedDevice)
{
    try
    {
        if (m_useSharedTpmDevice)
        {
            m_sharedTpmDevice = sharedDevice;
            std::stringstream ss;
            ss << "[CTpmSlotWriter] uses shared CTpmSharedDevice\n";
            Log(ss.str());
        }
        else
        {
            m_sharedTpmDevice = new CTpmSharedDevice();
            std::stringstream ss;
            ss << "[CTpmSlotWriter] uses local  CTpmSharedDevice\n";
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

CTpmSharedDevice* CTpmSlotWriter::GetTpmSharedDevice(void)
{
    return m_sharedTpmDevice;
}

bool CTpmSlotWriter::Release(void)
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

bool CTpmSlotWriter::Initialize(void)
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

bool CTpmSlotWriter::WriteByteToSlot(UINT32 slotNo, BYTE value)
{
    try
    {
        UINT32 nvIndex = TpmSlotWriterNS::BASE_SLOT_INDEX + slotNo;

        std::vector<BYTE> data(5, 0x00);
        uint32_t typeTag = static_cast<uint32_t>(SlotType::Byte);
        data[0] = (typeTag >> 24) & 0xFF;
        data[1] = (typeTag >> 16) & 0xFF;
        data[2] = (typeTag >> 8) & 0xFF;
        data[3] = typeTag & 0xFF;

        data[4] = value;

        // define
        auto resp = tpm->GetCapability(TPM_CAP::HANDLES, nvIndex, 1);
        auto handles = dynamic_cast<TPML_HANDLE*>(&*resp.capabilityData)->handle;
        bool defined = false;
        for (auto h : handles)
            if (h == nvIndex) { defined = true; break; }
        if (!defined)
        {
            TPMS_NV_PUBLIC nvPub(
                nvIndex, TPM_ALG_ID::SHA256,
                TPMA_NV::AUTHWRITE | TPMA_NV::AUTHREAD | TPMA_NV::OWNERWRITE | TPMA_NV::OWNERREAD,
                {},
                TpmSlotWriterNS::SLOT_SIZE
            );
            tpm->NV_DefineSpace(TPM_RH::OWNER, {}, nvPub);
        }

        tpm->NV_Write(TPM_RH::OWNER, nvIndex, data, 0);
        Log("Byte with type tag written to slot.");
        return true;
    }
    catch (...)
    {
        Log("WriteByteToSlot exception", true);
        return false;
    }
}

bool CTpmSlotWriter::WriteCharToSlot(UINT32 slotNo, char value)
{
    try
    {
        UINT32 nvIndex = TpmSlotWriterNS::BASE_SLOT_INDEX + slotNo;

        std::vector<BYTE> data(5, 0x00);
        uint32_t typeTag = static_cast<uint32_t>(SlotType::Char);
        data[0] = (typeTag >> 24) & 0xFF;
        data[1] = (typeTag >> 16) & 0xFF;
        data[2] = (typeTag >> 8) & 0xFF;
        data[3] = typeTag & 0xFF;

        data[4] = static_cast<BYTE>(value);

        // define
        auto resp = tpm->GetCapability(TPM_CAP::HANDLES, nvIndex, 1);
        auto handles = dynamic_cast<TPML_HANDLE*>(&*resp.capabilityData)->handle;
        bool defined = false;
        for (auto h : handles)
            if (h == nvIndex) { defined = true; break; }
        if (!defined)
        {
            TPMS_NV_PUBLIC nvPub(
                nvIndex, TPM_ALG_ID::SHA256,
                TPMA_NV::AUTHWRITE | TPMA_NV::AUTHREAD | TPMA_NV::OWNERWRITE | TPMA_NV::OWNERREAD,
                {},
                TpmSlotWriterNS::SLOT_SIZE
            );
            tpm->NV_DefineSpace(TPM_RH::OWNER, {}, nvPub);
        }

        tpm->NV_Write(TPM_RH::OWNER, nvIndex, data, 0);
        Log("Char with type tag written to slot.");
        return true;
    }
    catch (...)
    {
        Log("WriteCharToSlot exception", true);
        return false;
    }
}

bool CTpmSlotWriter::WriteIntToSlot(UINT32 slotNo, int value) 
{
    try
    {
        UINT32 nvIndex = TpmSlotWriterNS::BASE_SLOT_INDEX + slotNo;

        std::vector<BYTE> data(8, 0x00);
        uint32_t typeTag = static_cast<uint32_t>(SlotType::Int);

        // type tag
        data[0] = (typeTag >> 24) & 0xFF;
        data[1] = (typeTag >> 16) & 0xFF;
        data[2] = (typeTag >> 8) & 0xFF;
        data[3] = typeTag & 0xFF;

        // int
        if (m_endianness == Endianness::LittleEndian)
        {
            data[4] = value & 0xFF;
            data[5] = (value >> 8) & 0xFF;
            data[6] = (value >> 16) & 0xFF;
            data[7] = (value >> 24) & 0xFF;
        }
        else
        {
            data[4] = (value >> 24) & 0xFF;
            data[5] = (value >> 16) & 0xFF;
            data[6] = (value >> 8) & 0xFF;
            data[7] = value & 0xFF;
        }

        // define
        auto resp = tpm->GetCapability(TPM_CAP::HANDLES, nvIndex, 1);
        auto handles = dynamic_cast<TPML_HANDLE*>(&*resp.capabilityData)->handle;
        bool defined = false;
        for (auto h : handles)
            if (h == nvIndex) { defined = true; break; }

        if (!defined)
        {
            TPMS_NV_PUBLIC nvPub(
                nvIndex, TPM_ALG_ID::SHA256,
                TPMA_NV::AUTHWRITE | TPMA_NV::AUTHREAD | TPMA_NV::OWNERWRITE | TPMA_NV::OWNERREAD,
                {},
                TpmSlotWriterNS::SLOT_SIZE
            );
            tpm->NV_DefineSpace(TPM_RH::OWNER, {}, nvPub);
        }

        tpm->NV_Write(TPM_RH::OWNER, nvIndex, data, 0);
        Log("Int with type tag written to slot successfully.");
        return true;
    }
    catch (...)
    {
        Log("WriteIntToSlot with type tag exception", true);
        return false;
    }
}

bool CTpmSlotWriter::WriteFloatToSlot(UINT32 slotNo, float value)
{
    try
    {
        UINT32 nvIndex = TpmSlotWriterNS::BASE_SLOT_INDEX + slotNo;

        std::vector<BYTE> data(8, 0x00);

        uint32_t typeTag = static_cast<uint32_t>(SlotType::Float);
        data[0] = (typeTag >> 24) & 0xFF;
        data[1] = (typeTag >> 16) & 0xFF;
        data[2] = (typeTag >> 8) & 0xFF;
        data[3] = typeTag & 0xFF;

        uint32_t raw;
        std::memcpy(&raw, &value, sizeof(raw));

        if (m_endianness == Endianness::LittleEndian)
        {
            data[4] = raw & 0xFF;
            data[5] = (raw >> 8) & 0xFF;
            data[6] = (raw >> 16) & 0xFF;
            data[7] = (raw >> 24) & 0xFF;
        }
        else
        {
            data[4] = (raw >> 24) & 0xFF;
            data[5] = (raw >> 16) & 0xFF;
            data[6] = (raw >> 8) & 0xFF;
            data[7] = raw & 0xFF;
        }

        // define
        auto resp = tpm->GetCapability(TPM_CAP::HANDLES, nvIndex, 1);
        auto handles = dynamic_cast<TPML_HANDLE*>(&*resp.capabilityData)->handle;
        bool defined = false;
        for (auto h : handles)
            if (h == nvIndex) { defined = true; break; }
        if (!defined)
        {
            TPMS_NV_PUBLIC nvPub(
                nvIndex, TPM_ALG_ID::SHA256,
                TPMA_NV::AUTHWRITE | TPMA_NV::AUTHREAD | TPMA_NV::OWNERWRITE | TPMA_NV::OWNERREAD,
                {},
                TpmSlotWriterNS::SLOT_SIZE
            );
            tpm->NV_DefineSpace(TPM_RH::OWNER, {}, nvPub);
        }

        tpm->NV_Write(TPM_RH::OWNER, nvIndex, data, 0);
        Log("Float with type tag written to slot.");
        return true;
    }
    catch (...)
    {
        Log("WriteFloatToSlot exception", true);
        return false;
    }
}

bool CTpmSlotWriter::WriteDoubleToSlot(UINT32 slotNo, double value)
{
    try
    {
        UINT32 nvIndex = TpmSlotWriterNS::BASE_SLOT_INDEX + slotNo;

        std::vector<BYTE> data(12, 0x00);

        uint32_t typeTag = static_cast<uint32_t>(SlotType::Double);
        data[0] = (typeTag >> 24) & 0xFF;
        data[1] = (typeTag >> 16) & 0xFF;
        data[2] = (typeTag >> 8) & 0xFF;
        data[3] = typeTag & 0xFF;

        uint64_t raw;
        std::memcpy(&raw, &value, sizeof(raw));

        if (m_endianness == Endianness::LittleEndian)
        {
            for (int i = 0; i < 8; ++i)
                data[4 + i] = (raw >> (8 * i)) & 0xFF;
        }
        else
        {
            for (int i = 0; i < 8; ++i)
                data[4 + i] = (raw >> (8 * (7 - i))) & 0xFF;
        }

        // define
        auto resp = tpm->GetCapability(TPM_CAP::HANDLES, nvIndex, 1);
        auto handles = dynamic_cast<TPML_HANDLE*>(&*resp.capabilityData)->handle;
        bool defined = false;
        for (auto h : handles)
            if (h == nvIndex) { defined = true; break; }
        if (!defined)
        {
            TPMS_NV_PUBLIC nvPub(
                nvIndex, TPM_ALG_ID::SHA256,
                TPMA_NV::AUTHWRITE | TPMA_NV::AUTHREAD | TPMA_NV::OWNERWRITE | TPMA_NV::OWNERREAD,
                {},
                TpmSlotWriterNS::SLOT_SIZE
            );
            tpm->NV_DefineSpace(TPM_RH::OWNER, {}, nvPub);
        }

        tpm->NV_Write(TPM_RH::OWNER, nvIndex, data, 0);
        Log("Double with type tag written to slot.");
        return true;
    }
    catch (...)
    {
        Log("WriteDoubleToSlot exception", true);
        return false;
    }
}


bool CTpmSlotWriter::WriteStringToSlot(UINT32 slotNo, const std::string& str)
{
    try
    {
        UINT32 nvIndex = TpmSlotWriterNS::BASE_SLOT_INDEX + slotNo;

        std::vector<BYTE> data;
        uint32_t typeTag = static_cast<uint32_t>(SlotType::String);

        data.push_back((typeTag >> 24) & 0xFF);
        data.push_back((typeTag >> 16) & 0xFF);
        data.push_back((typeTag >> 8) & 0xFF);
        data.push_back(typeTag & 0xFF);

        data.insert(data.end(), str.begin(), str.end());

        if (data.size() > TpmSlotWriterNS::SLOT_SIZE)
        {
            Log("String too big for slot.", true);
            return false;
        }

        // define
        auto resp = tpm->GetCapability(TPM_CAP::HANDLES, nvIndex, 1);
        auto handles = dynamic_cast<TPML_HANDLE*>(&*resp.capabilityData)->handle;
        bool defined = false;
        for (auto h : handles)
            if (h == nvIndex) { defined = true; break; }
        if (!defined)
        {
            TPMS_NV_PUBLIC nvPub(
                nvIndex, TPM_ALG_ID::SHA256,
                TPMA_NV::AUTHWRITE | TPMA_NV::AUTHREAD | TPMA_NV::OWNERWRITE | TPMA_NV::OWNERREAD,
                {},
                TpmSlotWriterNS::SLOT_SIZE
            );
            tpm->NV_DefineSpace(TPM_RH::OWNER, {}, nvPub);
        }

        tpm->NV_Write(TPM_RH::OWNER, nvIndex, data, 0);
        Log("String with type tag written to slot.");
        return true;
    }
    catch (...)
    {
        Log("WriteStringToSlot exception", true);
        return false;
    }
}

bool CTpmSlotWriter::WriteByteArrayToSlot(UINT32 slotNo, const std::vector<BYTE>& values)
{
    try
    {
        if (slotNo >= TpmSlotWriterNS::SLOT_COUNT)
            return false;

        UINT32 nvIndex = TpmSlotWriterNS::BASE_SLOT_INDEX + slotNo;
        std::vector<BYTE> data;

        uint32_t typeTag = static_cast<uint32_t>(SlotType::ByteArray);
        data.push_back((typeTag >> 24) & 0xFF);
        data.push_back((typeTag >> 16) & 0xFF);
        data.push_back((typeTag >> 8) & 0xFF);
        data.push_back(typeTag & 0xFF);

        data.insert(data.end(), values.begin(), values.end());

        if (data.size() > TpmSlotWriterNS::SLOT_SIZE)
        {
            Log("Byte array too big.", true);
            return false;
        }

        auto resp = tpm->GetCapability(TPM_CAP::HANDLES, nvIndex, 1);
        auto handles = dynamic_cast<TPML_HANDLE*>(&*resp.capabilityData)->handle;
        bool defined = false;
        for (auto h : handles)
            if (h == nvIndex) { defined = true; break; }
        if (!defined)
        {
            TPMS_NV_PUBLIC nvPub(
                nvIndex, TPM_ALG_ID::SHA256,
                TPMA_NV::AUTHWRITE | TPMA_NV::AUTHREAD | TPMA_NV::OWNERWRITE | TPMA_NV::OWNERREAD,
                {},
                TpmSlotWriterNS::SLOT_SIZE
            );
            tpm->NV_DefineSpace(TPM_RH::OWNER, {}, nvPub);
        }

        tpm->NV_Write(TPM_RH::OWNER, nvIndex, data, 0);
        Log("Byte array with type tag written to slot.");
        return true;
    }
    catch (...)
    {
        Log("WriteByteArrayToSlot exception", true);
        return false;
    }
}

bool CTpmSlotWriter::WriteCharArrayToSlot(UINT32 slotNo, const std::vector<char>& values)
{
    try
    {
        if (slotNo >= TpmSlotWriterNS::SLOT_COUNT)
            return false;

        UINT32 nvIndex = TpmSlotWriterNS::BASE_SLOT_INDEX + slotNo;
        std::vector<BYTE> data;

        uint32_t typeTag = static_cast<uint32_t>(SlotType::CharArray);
        data.push_back((typeTag >> 24) & 0xFF);
        data.push_back((typeTag >> 16) & 0xFF);
        data.push_back((typeTag >> 8) & 0xFF);
        data.push_back(typeTag & 0xFF);

        data.insert(data.end(), values.begin(), values.end());

        if (data.size() > TpmSlotWriterNS::SLOT_SIZE)
        {
            Log("Char array too big.", true);
            return false;
        }

        auto resp = tpm->GetCapability(TPM_CAP::HANDLES, nvIndex, 1);
        auto handles = dynamic_cast<TPML_HANDLE*>(&*resp.capabilityData)->handle;
        bool defined = false;
        for (auto h : handles)
            if (h == nvIndex) { defined = true; break; }
        if (!defined)
        {
            TPMS_NV_PUBLIC nvPub(
                nvIndex, TPM_ALG_ID::SHA256,
                TPMA_NV::AUTHWRITE | TPMA_NV::AUTHREAD | TPMA_NV::OWNERWRITE | TPMA_NV::OWNERREAD,
                {},
                TpmSlotWriterNS::SLOT_SIZE
            );
            tpm->NV_DefineSpace(TPM_RH::OWNER, {}, nvPub);
        }

        tpm->NV_Write(TPM_RH::OWNER, nvIndex, data, 0);
        Log("Char array with type tag written to slot.");
        return true;
    }
    catch (...)
    {
        Log("WriteCharArrayToSlot exception", true);
        return false;
    }
}

bool CTpmSlotWriter::WriteIntArrayToSlot(UINT32 slotNo, const std::vector<int>& values)
{
    try
    {
        if (slotNo >= TpmSlotWriterNS::SLOT_COUNT)
            return false;

        UINT32 nvIndex = TpmSlotWriterNS::BASE_SLOT_INDEX + slotNo;

        std::vector<BYTE> data;

        // type signature
        uint32_t typeTag = static_cast<uint32_t>(SlotType::IntArray);
        data.push_back((typeTag >> 24) & 0xFF);
        data.push_back((typeTag >> 16) & 0xFF);
        data.push_back((typeTag >> 8) & 0xFF);
        data.push_back(typeTag & 0xFF);

        // each int
        for (auto v : values)
        {
            if (m_endianness == Endianness::LittleEndian)
            {
                data.push_back(v & 0xFF);
                data.push_back((v >> 8) & 0xFF);
                data.push_back((v >> 16) & 0xFF);
                data.push_back((v >> 24) & 0xFF);
            }
            else
            {
                data.push_back((v >> 24) & 0xFF);
                data.push_back((v >> 16) & 0xFF);
                data.push_back((v >> 8) & 0xFF);
                data.push_back(v & 0xFF);
            }
        }

        if (data.size() > TpmSlotWriterNS::SLOT_SIZE)
        {
            Log("Int array too large for slot.", true);
            return false;
        }

        // define
        auto resp = tpm->GetCapability(TPM_CAP::HANDLES, nvIndex, 1);
        auto handles = dynamic_cast<TPML_HANDLE*>(&*resp.capabilityData)->handle;
        bool defined = false;
        for (auto h : handles)
            if (h == nvIndex) { defined = true; break; }
        if (!defined)
        {
            TPMS_NV_PUBLIC nvPub(
                nvIndex, TPM_ALG_ID::SHA256,
                TPMA_NV::AUTHWRITE | TPMA_NV::AUTHREAD | TPMA_NV::OWNERWRITE | TPMA_NV::OWNERREAD,
                {},
                TpmSlotWriterNS::SLOT_SIZE
            );
            tpm->NV_DefineSpace(TPM_RH::OWNER, {}, nvPub);
        }

        tpm->NV_Write(TPM_RH::OWNER, nvIndex, data, 0);
        Log("Int array with type tag written to slot.");
        return true;
    }
    catch (...)
    {
        Log("WriteIntArrayToSlot exception", true);
        return false;
    }
}

bool CTpmSlotWriter::WriteFloatArrayToSlot(UINT32 slotNo, const std::vector<float>& values)
{
    try
    {
        if (slotNo >= TpmSlotWriterNS::SLOT_COUNT)
            return false;

        UINT32 nvIndex = TpmSlotWriterNS::BASE_SLOT_INDEX + slotNo;
        std::vector<BYTE> data;

        uint32_t typeTag = static_cast<uint32_t>(SlotType::FloatArray);
        data.push_back((typeTag >> 24) & 0xFF);
        data.push_back((typeTag >> 16) & 0xFF);
        data.push_back((typeTag >> 8) & 0xFF);
        data.push_back(typeTag & 0xFF);

        for (auto f : values)
        {
            uint32_t raw;
            std::memcpy(&raw, &f, sizeof(raw));
            if (m_endianness == Endianness::LittleEndian)
            {
                data.push_back(raw & 0xFF);
                data.push_back((raw >> 8) & 0xFF);
                data.push_back((raw >> 16) & 0xFF);
                data.push_back((raw >> 24) & 0xFF);
            }
            else
            {
                data.push_back((raw >> 24) & 0xFF);
                data.push_back((raw >> 16) & 0xFF);
                data.push_back((raw >> 8) & 0xFF);
                data.push_back(raw & 0xFF);
            }
        }

        if (data.size() > TpmSlotWriterNS::SLOT_SIZE)
        {
            Log("Float array too large for slot.", true);
            return false;
        }

        auto resp = tpm->GetCapability(TPM_CAP::HANDLES, nvIndex, 1);
        auto handles = dynamic_cast<TPML_HANDLE*>(&*resp.capabilityData)->handle;
        bool defined = false;
        for (auto h : handles)
            if (h == nvIndex) { defined = true; break; }
        if (!defined)
        {
            TPMS_NV_PUBLIC nvPub(
                nvIndex, TPM_ALG_ID::SHA256,
                TPMA_NV::AUTHWRITE | TPMA_NV::AUTHREAD | TPMA_NV::OWNERWRITE | TPMA_NV::OWNERREAD,
                {},
                TpmSlotWriterNS::SLOT_SIZE
            );
            tpm->NV_DefineSpace(TPM_RH::OWNER, {}, nvPub);
        }

        tpm->NV_Write(TPM_RH::OWNER, nvIndex, data, 0);
        Log("Float array with type tag written to slot.");
        return true;
    }
    catch (...)
    {
        Log("WriteFloatArrayToSlot exception", true);
        return false;
    }
}

bool CTpmSlotWriter::WriteDoubleArrayToSlot(UINT32 slotNo, const std::vector<double>& values)
{
    try
    {
        if (slotNo >= TpmSlotWriterNS::SLOT_COUNT)
            return false;

        UINT32 nvIndex = TpmSlotWriterNS::BASE_SLOT_INDEX + slotNo;
        std::vector<BYTE> data;

        uint32_t typeTag = static_cast<uint32_t>(SlotType::DoubleArray);
        data.push_back((typeTag >> 24) & 0xFF);
        data.push_back((typeTag >> 16) & 0xFF);
        data.push_back((typeTag >> 8) & 0xFF);
        data.push_back(typeTag & 0xFF);

        for (auto d : values)
        {
            uint64_t raw;
            std::memcpy(&raw, &d, sizeof(raw));
            if (m_endianness == Endianness::LittleEndian)
            {
                for (int i = 0; i < 8; ++i)
                    data.push_back((raw >> (8 * i)) & 0xFF);
            }
            else
            {
                for (int i = 0; i < 8; ++i)
                    data.push_back((raw >> (8 * (7 - i))) & 0xFF);
            }
        }

        if (data.size() > TpmSlotWriterNS::SLOT_SIZE)
        {
            Log("Double array too large.", true);
            return false;
        }

        auto resp = tpm->GetCapability(TPM_CAP::HANDLES, nvIndex, 1);
        auto handles = dynamic_cast<TPML_HANDLE*>(&*resp.capabilityData)->handle;
        bool defined = false;
        for (auto h : handles)
            if (h == nvIndex) { defined = true; break; }
        if (!defined)
        {
            TPMS_NV_PUBLIC nvPub(
                nvIndex, TPM_ALG_ID::SHA256,
                TPMA_NV::AUTHWRITE | TPMA_NV::AUTHREAD | TPMA_NV::OWNERWRITE | TPMA_NV::OWNERREAD,
                {},
                TpmSlotWriterNS::SLOT_SIZE
            );
            tpm->NV_DefineSpace(TPM_RH::OWNER, {}, nvPub);
        }
        tpm->NV_Write(TPM_RH::OWNER, nvIndex, data, 0);
        Log("Double array with type tag written to slot.");
        return true;
    }
    catch (...)
    {
        Log("WriteDoubleArrayToSlot exception", true);
        return false;
    }
}

bool CTpmSlotWriter::WriteStringArrayToSlot(UINT32 slotNo, const std::vector<std::string>& values)
{
    try
    {
        if (slotNo >= TpmSlotWriterNS::SLOT_COUNT)
            return false;

        UINT32 nvIndex = TpmSlotWriterNS::BASE_SLOT_INDEX + slotNo;

        std::vector<BYTE> data;

        uint32_t typeTag = static_cast<uint32_t>(SlotType::StringArray);
        data.push_back((typeTag >> 24) & 0xFF);
        data.push_back((typeTag >> 16) & 0xFF);
        data.push_back((typeTag >> 8) & 0xFF);
        data.push_back(typeTag & 0xFF);

        for (const auto& str : values)
        {
            data.insert(data.end(), str.begin(), str.end());
            data.push_back('\0');  // null terminator
        }

        if (data.size() > TpmSlotWriterNS::SLOT_SIZE)
        {
            Log("String array too big for slot.", true);
            return false;
        }

        auto resp = tpm->GetCapability(TPM_CAP::HANDLES, nvIndex, 1);
        auto handles = dynamic_cast<TPML_HANDLE*>(&*resp.capabilityData)->handle;
        bool defined = false;
        for (auto h : handles)
            if (h == nvIndex) { defined = true; break; }
        if (!defined)
        {
            TPMS_NV_PUBLIC nvPub(
                nvIndex, TPM_ALG_ID::SHA256,
                TPMA_NV::AUTHWRITE | TPMA_NV::AUTHREAD | TPMA_NV::OWNERWRITE | TPMA_NV::OWNERREAD,
                {},
                TpmSlotWriterNS::SLOT_SIZE
            );
            tpm->NV_DefineSpace(TPM_RH::OWNER, {}, nvPub);
        }

        tpm->NV_Write(TPM_RH::OWNER, nvIndex, data, 0);
        Log("String array with type tag written to slot.");
        return true;
    }
    catch (...)
    {
        Log("WriteStringArrayToSlot exception", true);
        return false;
    }
}

void CTpmSlotWriter::SetEndianness(Endianness mode)
{
    m_endianness = mode;
}

Endianness CTpmSlotWriter::GetEndianness() const
{
    return m_endianness;
}

bool CTpmSlotWriter::SlotClear(UINT32 slotNo)
{
    try
    {
        if (slotNo >= TpmSlotWriterNS::SLOT_COUNT)
        {
            Log("Invalid slot number.", true);
            return false;
        }

        UINT32 nvIndex = TpmSlotWriterNS::BASE_SLOT_INDEX + slotNo;

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
        std::vector<BYTE> zeroData(TpmSlotWriterNS::SLOT_SIZE, 0x00);

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

bool CTpmSlotWriter::SlotFree(UINT32 slotNo)
{
    try
    {
        if (slotNo >= TpmSlotWriterNS::SLOT_COUNT)
        {
            Log("Invalid slot number.", true);
            return false;
        }

        UINT32 nvIndex = TpmSlotWriterNS::BASE_SLOT_INDEX + slotNo;

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

std::vector<SlotInfo> CTpmSlotWriter::SlotList()
{
    std::vector<SlotInfo> result;

    for (UINT32 slotNo = 0; slotNo < TpmSlotWriterNS::SLOT_COUNT; ++slotNo)
    {
        UINT32 nvIndex = TpmSlotWriterNS::BASE_SLOT_INDEX + slotNo;
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