#pragma once

#include "TpmBaseClass.h"
#include "TpmSharedDevice.h"

#include "TpmSlotDefinitions.h"

using namespace TpmCpp;

namespace TpmSlotWriterNS
{
    constexpr UINT32 BASE_SLOT_INDEX = 0x01510000;
    constexpr UINT32 SLOT_COUNT = 8;
    constexpr UINT32 SLOT_SIZE = 1024; // 1KB
}

class CTpmSlotWriter : public CTpmBaseClass
{
public:
    virtual ~CTpmSlotWriter();
             CTpmSlotWriter(CTpmSharedDevice* sharedDevice = nullptr);

    CTpmSharedDevice* GetTpmSharedDevice(void);
    bool              Release(void);
    bool              Initialize(void);

    bool              WriteByteToSlot(UINT32 slotNo, BYTE value);
    bool              WriteCharToSlot(UINT32 slotNo, char value);
    bool              WriteIntToSlot(UINT32 slotNo, int value);
    bool              WriteFloatToSlot(UINT32 slotNo, float value);
    bool              WriteDoubleToSlot(UINT32 slotNo, double value);
    bool              WriteStringToSlot(UINT32 slotNo, const std::string& str);
    bool              WriteByteArrayToSlot(UINT32 slotNo, const std::vector<BYTE>& values);
    bool              WriteCharArrayToSlot(UINT32 slotNo, const std::vector<char>& values);
    bool              WriteIntArrayToSlot(UINT32 slotNo, const std::vector<int>& values);
    bool              WriteFloatArrayToSlot(UINT32 slotNo, const std::vector<float>& values);
    bool              WriteDoubleArrayToSlot(UINT32 slotNo, const std::vector<double>& values);
    bool              WriteStringArrayToSlot(UINT32 slotNo, const std::vector<std::string>& values);
    void              SetEndianness(Endianness mode);
    Endianness        GetEndianness() const;
    bool              SlotClear(UINT32 slotNo);  // seçili slotu komple 0x00 verisiyle doldurur
    bool              SlotFree(UINT32 slotNo);   // slotu NV alandan tamamen siler
    std::vector<SlotInfo> SlotList();

protected:


private:
    bool m_useSharedTpmDevice;
    CTpmSharedDevice* m_sharedTpmDevice;

    Endianness m_endianness = Endianness::LittleEndian; // default
};