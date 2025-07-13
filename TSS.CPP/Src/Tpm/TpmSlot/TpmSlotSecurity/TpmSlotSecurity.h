#pragma once

#include "TpmBaseClass.h"
#include "TpmSharedDevice.h"

using namespace TpmCpp;

namespace TpmSlotSecurityNS
{
    constexpr UINT32 BASE_SLOT_INDEX = 0x01510000;
    constexpr UINT32 SLOT_COUNT = 8;
    constexpr UINT32 SLOT_SIZE = 1024; // 1KB
}

class CTpmSlotSecurity : public CTpmBaseClass
{
public:
    virtual ~CTpmSlotSecurity();
             CTpmSlotSecurity(CTpmSharedDevice* sharedDevice = nullptr);

    CTpmSharedDevice* GetTpmSharedDevice(void);
    bool              Release(void);
    bool              Initialize(void);

    bool                                 DefineSlotWithPin(UINT32 slotNo, UINT32 slotSize, const std::string& pin);
    bool                                 WritePinProtectedSlot(UINT32 slotNo, const std::string& pin, const std::vector<BYTE>& data);
    std::vector<BYTE>                    ReadPinProtectedSlot(UINT32 slotNo, const std::string& pin, UINT32 readSize);
    bool                                 DefinePinProtectedSlot(UINT32 slotNo, UINT32 slotSize, const std::string& pin);
    bool                                 UndefinePinProtectedSlot(UINT32 slotNo, const std::string& pin);
    bool                                 IsSlotDefined(UINT32 slotNo);
    bool                                 WriteVersionedSlot(UINT32 slotNo, const std::string& pin, UINT32 version, const std::vector<BYTE>& payload);
    std::pair<UINT32, std::vector<BYTE>> ReadVersionedSlot(UINT32 slotNo, const std::string& pin, UINT32 readSize);
    // crypto / hash / signature
    bool                                 LoadAesKey();
    std::vector<BYTE>                    EncryptData(const std::vector<BYTE>& plaintext);
    std::vector<BYTE>                    DecryptData(const std::vector<BYTE>& ciphertext);
    std::vector<BYTE>                    ComputeSlotHash(UINT32 slotNo);
    std::vector<BYTE>                    SignSlotData(UINT32 slotNo);    
    void                                 FlushAesKey();

    bool BackupSlot(UINT32 slotNo, const std::string& pin, const std::string& backupFile);
    bool RestoreSlot(UINT32 slotNo, const std::string& pin, const std::string& backupFile);

    bool BackupAllSlots(const std::string& backupFolder);
    bool RestoreAllSlots(const std::string& backupFolder);

protected:

private:
    bool m_useSharedTpmDevice;
    CTpmSharedDevice* m_sharedTpmDevice;

    TPM_HANDLE m_aesKeyHandle = TPM_RH_NULL;
};