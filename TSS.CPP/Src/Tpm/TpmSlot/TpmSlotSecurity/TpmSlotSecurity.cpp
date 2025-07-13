#include "TpmSlotSecurity.h"

#include <string>       // std::string
#include <iostream>     // std::cout
#include <sstream>      // std::stringstream
#include <fstream>      // std::ofstream
#include <vector>

CTpmSlotSecurity::~CTpmSlotSecurity()
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

CTpmSlotSecurity::CTpmSlotSecurity(CTpmSharedDevice* sharedDevice)
    : m_useSharedTpmDevice(sharedDevice != nullptr), m_sharedTpmDevice(sharedDevice)
{
    try
    {
        if (m_useSharedTpmDevice)
        {
            m_sharedTpmDevice = sharedDevice;
            std::stringstream ss;
            ss << "[CTpmSlotSecurity] uses shared CTpmSharedDevice\n";
            Log(ss.str());
        }
        else
        {
            m_sharedTpmDevice = new CTpmSharedDevice();
            std::stringstream ss;
            ss << "[CTpmSlotSecurity] uses local  CTpmSharedDevice\n";
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

CTpmSharedDevice* CTpmSlotSecurity::GetTpmSharedDevice(void)
{
    return m_sharedTpmDevice;
}

bool CTpmSlotSecurity::Release(void)
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

bool CTpmSlotSecurity::Initialize(void)
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


bool CTpmSlotSecurity::DefineSlotWithPin(UINT32 slotNo, UINT32 slotSize, const std::string& pin)
{
    try
    {
        // PIN
        TPM2B_AUTH authValue;
        authValue.buffer = std::vector<BYTE>(pin.begin(), pin.end());
        /*
        TPMA_NV attributes = 0;
        attributes |= 0x00040000; // AUTHREAD
        attributes |= 0x00020000; // AUTHWRITE
        attributes |= 0x00000400; // WRITE_STCLEAR
        attributes |= 0x00000200; // READ_STCLEAR
        */

        TPM2B_NV_PUBLIC nvPub;
        nvPub.nvPublic.nvIndex = 0x01000000 | slotNo;
        nvPub.nvPublic.nameAlg = TPM_ALG_ID::SHA256;
        nvPub.nvPublic.attributes = 0x00040000 | // AUTHREAD
            0x00020000 | // AUTHWRITE
            0x00000400 | // WRITE_STCLEAR
            0x00000200;  // READ_STCLEAR
        nvPub.nvPublic.authPolicy = TPM2B_DIGEST();
        nvPub.nvPublic.dataSize = slotSize;
        tpm->NV_DefineSpace(
            TPM_RH::OWNER,
            authValue.buffer,
            nvPub.nvPublic
        );

        std::cout << "[CTpmSlotSecurity] Slot defined with PIN successfully." << std::endl;
        return true;
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[CTpmSlotSecurity] DefineSlotWithPin error: " << ex.what() << std::endl;
        return false;
    }
}

bool CTpmSlotSecurity::WritePinProtectedSlot(UINT32 slotNo, const std::string& pin, const std::vector<BYTE>& data)
{
    try
    {
        TPM_HANDLE nvHandle(0x01000000 | slotNo);

        nvHandle.SetAuth(std::vector<BYTE>(pin.begin(), pin.end()));

        tpm->NV_Write(
            nvHandle,  // authHandle
            nvHandle,  // nvIndex
            data,
            0
        );

        std::cout << "[CTpmSlotSecurity] PIN protected slot write OK." << std::endl;
        return true;
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[CTpmSlotSecurity] WritePinProtectedSlot error: " << ex.what() << std::endl;
        return false;
    }
}

std::vector<BYTE> CTpmSlotSecurity::ReadPinProtectedSlot(UINT32 slotNo, const std::string& pin, UINT32 readSize)
{
    try
    {
        TPM_HANDLE nvHandle(0x01000000 | slotNo);

        nvHandle.SetAuth(std::vector<BYTE>(pin.begin(), pin.end()));

        auto result = tpm->NV_Read(
            nvHandle,  // authHandle
            nvHandle,  // nvIndex
            readSize,
            0
        );

        std::cout << "[CTpmSlotSecurity] PIN protected slot read OK." << std::endl;
        return result;
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[CTpmSlotSecurity] ReadPinProtectedSlot error: " << ex.what() << std::endl;
        return {};
    }
}

bool CTpmSlotSecurity::DefinePinProtectedSlot(UINT32 slotNo, UINT32 slotSize, const std::string& pin)
{
    try
    {
        TPM2B_AUTH authValue;
        authValue.buffer = std::vector<BYTE>(pin.begin(), pin.end());
        //authValue.size = static_cast<UINT16>(authValue.buffer.size());

/*
        TPMA_NV attributes = 0;
        attributes |= 0x00020000; // AUTHWRITE
        attributes |= 0x00040000; // AUTHREAD
        attributes |= 0x00000400; // WRITE_STCLEAR
        attributes |= 0x00000200; // READ_STCLEAR
        attributes |= 0x00008000; // NO_DA
*/
        TPM2B_NV_PUBLIC nvPub;
        nvPub.nvPublic.nvIndex = 0x01000000 | slotNo;
        nvPub.nvPublic.nameAlg = TPM_ALG_ID::SHA256;
        nvPub.nvPublic.attributes = TPMA_NV::AUTHWRITE | TPMA_NV::AUTHREAD | TPMA_NV::WRITE_STCLEAR | TPMA_NV::READ_STCLEAR;
        nvPub.nvPublic.authPolicy = TPM2B_DIGEST();
        nvPub.nvPublic.dataSize = slotSize;

        tpm->NV_DefineSpace(
            TPM_RH::OWNER,
            authValue.buffer,
            nvPub.nvPublic
        );

        std::cout << "[CTpmSlotSecurity] PIN protected slot defined successfully." << std::endl;
        return true;
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[CTpmSlotSecurity] DefinePinProtectedSlot error: " << ex.what() << std::endl;
        return false;
    }
}

bool CTpmSlotSecurity::UndefinePinProtectedSlot(UINT32 slotNo, const std::string& pin)
{
    try
    {
        // Slot index (NV handle)
        TPM_HANDLE nvIndex = TPM_HANDLE(0x01000000 | slotNo);

        // PIN → authValue
        ByteVec authValue(pin.begin(), pin.end());

        // NV_UndefineSpace(authHandle, nvIndex, auth)
        tpm->NV_UndefineSpace(TPM_RH::OWNER, nvIndex);

        std::cout << "[CTpmSlotSecurity] PIN protected slot undefined successfully." << std::endl;
        return true;
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[CTpmSlotSecurity] UndefinePinProtectedSlot error: " << ex.what() << std::endl;
        return false;
    }
}

bool CTpmSlotSecurity::IsSlotDefined(UINT32 slotNo)
{
    try
    {
        TPM_HANDLE nvIndex = TPM_HANDLE(0x01000000 | slotNo);

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
            return false;
        }

        return true;
    }
    catch (...)
    {
        return false;
    }
}

bool CTpmSlotSecurity::WriteVersionedSlot(UINT32 slotNo, const std::string& pin, UINT32 version, const std::vector<BYTE>& payload)
{
    try
    {
        TPM_HANDLE nvHandle(0x01000000 | slotNo);
        nvHandle.SetAuth(std::vector<BYTE>(pin.begin(), pin.end()));

        // versiyon + payload
        std::vector<BYTE> buffer;
        buffer.push_back((version >> 24) & 0xFF);
        buffer.push_back((version >> 16) & 0xFF);
        buffer.push_back((version >> 8) & 0xFF);
        buffer.push_back(version & 0xFF);

        buffer.insert(buffer.end(), payload.begin(), payload.end());

        tpm->NV_Write(
            nvHandle,
            nvHandle,
            buffer,
            0
        );

        std::cout << "[CTpmSlotSecurity] WriteVersionedSlot OK." << std::endl;
        return true;
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[CTpmSlotSecurity] WriteVersionedSlot error: " << ex.what() << std::endl;
        return false;
    }
}

std::pair<UINT32, std::vector<BYTE>> CTpmSlotSecurity::ReadVersionedSlot(UINT32 slotNo, const std::string& pin, UINT32 readSize)
{
    try
    {
        TPM_HANDLE nvHandle(0x01000000 | slotNo);
        nvHandle.SetAuth(std::vector<BYTE>(pin.begin(), pin.end()));

        auto rawData = tpm->NV_Read(
            nvHandle,
            nvHandle,
            readSize,
            0
        );

        if (rawData.size() < 4)
        {
            std::cerr << "[CTpmSlotSecurity] ReadVersionedSlot error: data too small." << std::endl;
            return { 0, {} };
        }

        UINT32 version = (rawData[0] << 24) |
            (rawData[1] << 16) |
            (rawData[2] << 8) |
            (rawData[3]);

        std::vector<BYTE> payload(rawData.begin() + 4, rawData.end());

        std::cout << "[CTpmSlotSecurity] ReadVersionedSlot OK, version=" << version << std::endl;
        return { version, payload };
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[CTpmSlotSecurity] ReadVersionedSlot error: " << ex.what() << std::endl;
        return { 0, {} };
    }
}

bool CTpmSlotSecurity::BackupSlot(UINT32 slotNo, const std::string& pin, const std::string& backupFile)
{
    try
    {
        TPM_HANDLE nvHandle(0x01000000 | slotNo);
        nvHandle.SetAuth(std::vector<BYTE>(pin.begin(), pin.end()));

        // slot boyutunu almak için
        auto nvInfo = tpm->NV_ReadPublic(nvHandle);
        UINT16 size = nvInfo.nvPublic.dataSize;

        auto slotData = tpm->NV_Read(
            nvHandle,
            nvHandle,
            size,
            0
        );

        // dosyaya yaz
        std::ofstream out(backupFile, std::ios::binary);
        if (out.fail())
        {
            std::cerr << "[CTpmSlotSecurity] BackupSlot: cannot open file" << std::endl;
            return false;
        }
        out.write((const char*)slotData.data(), slotData.size());
        out.close();

        std::cout << "[CTpmSlotSecurity] BackupSlot: backup OK to " << backupFile << std::endl;
        return true;
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[CTpmSlotSecurity] BackupSlot error: " << ex.what() << std::endl;
        return false;
    }
}


bool CTpmSlotSecurity::RestoreSlot(UINT32 slotNo, const std::string& pin, const std::string& backupFile)
{
    try
    {
        // dosyadan oku
        std::ifstream in(backupFile, std::ios::binary);
        if (in.fail())
        {
            std::cerr << "[CTpmSlotSecurity] RestoreSlot: cannot open file" << std::endl;
            return false;
        }

        std::vector<BYTE> data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        in.close();

        TPM_HANDLE nvHandle(0x01000000 | slotNo);
        nvHandle.SetAuth(std::vector<BYTE>(pin.begin(), pin.end()));

        // TPM'e geri yaz
        tpm->NV_Write(
            nvHandle,
            nvHandle,
            data,
            0
        );

        std::cout << "[CTpmSlotSecurity] RestoreSlot: restore OK from " << backupFile << std::endl;
        return true;
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[CTpmSlotSecurity] RestoreSlot error: " << ex.what() << std::endl;
        return false;
    }
}

bool CTpmSlotSecurity::BackupAllSlots(const std::string& backupFolder)
{
    try
    {
        // NV indeksleri listele
        auto caps = tpm->GetCapability(
            TPM_CAP::HANDLES,
            TPM_HT::NV_INDEX << 24,
            0xFFFFFF
        );
        auto handles = dynamic_cast<TPML_HANDLE*>(&*caps.capabilityData)->handle;

        for (auto nvIndex : handles)
        {
            // slot bilgisi
            auto nvPub = tpm->NV_ReadPublic(nvIndex);
            UINT16 size = nvPub.nvPublic.dataSize;

            // okuma
            auto data = tpm->NV_Read(
                nvIndex,
                nvIndex,
                size,
                0
            );

            // dosya ismi
            std::stringstream fname;
            fname << backupFolder << "/slot_" << std::hex << nvIndex << ".bin";

            std::ofstream out(fname.str(), std::ios::binary);
            if (out.fail())
            {
                std::cerr << "[CTpmSlotSecurity] cannot open backup file for " << nvIndex << std::endl;
                continue;
            }
            out.write((const char*)data.data(), data.size());
            out.close();

            std::cout << "[CTpmSlotSecurity] backed up NV index 0x"
                << std::hex << nvIndex << " to " << fname.str() << std::endl;
        }

        return true;
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[CTpmSlotSecurity] BackupAllSlots error: " << ex.what() << std::endl;
        return false;
    }
}

bool CTpmSlotSecurity::RestoreAllSlots(const std::string& backupFolder)
{
    try
    {
        // NV indeksleri listele
        auto caps = tpm->GetCapability(
            TPM_CAP::HANDLES,
            TPM_HT::NV_INDEX << 24,
            0xFFFFFF
        );

        auto handles = dynamic_cast<TPML_HANDLE*>(&*caps.capabilityData)->handle;

        for (auto nvIndex : handles)
        {
            // slot bilgisi
            auto nvPub = tpm->NV_ReadPublic(nvIndex);
            UINT16 size = nvPub.nvPublic.dataSize;

            // dosya ismi
            std::stringstream fname;
            fname << backupFolder << "/slot_" << std::hex << nvIndex << ".bin";

            std::ifstream in(fname.str(), std::ios::binary);
            if (in.fail())
            {
                std::cerr << "[CTpmSlotSecurity] cannot open restore file for " << nvIndex << std::endl;
                continue;
            }
            std::vector<BYTE> data((std::istreambuf_iterator<char>(in)),
                std::istreambuf_iterator<char>());
            in.close();

            if (data.size() != size)
            {
                std::cerr << "[CTpmSlotSecurity] size mismatch for " << nvIndex << std::endl;
                continue;
            }

            // geri yaz
            tpm->NV_Write(
                nvIndex,
                nvIndex,
                data,
                0
            );

            std::cout << "[CTpmSlotSecurity] restored NV index 0x"
                << std::hex << nvIndex << " from " << fname.str() << std::endl;
        }

        return true;
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[CTpmSlotSecurity] RestoreAllSlots error: " << ex.what() << std::endl;
        return false;
    }
}