#pragma once

#include "TpmBaseClass.h"
#include "TpmSharedDevice.h"

#include "TpmSlotDefinitions.h"

using namespace TpmCpp;

namespace TpmSlotReaderNS
{
    constexpr UINT32 BASE_SLOT_INDEX = 0x01510000;
    constexpr UINT32 SLOT_COUNT = 8;
    constexpr UINT32 SLOT_SIZE = 1024; // 1KB
}

class CTpmSlotReader : public CTpmBaseClass
{
public:
    virtual ~CTpmSlotReader();
             CTpmSlotReader(CTpmSharedDevice* sharedDevice = nullptr);

    CTpmSharedDevice*        GetTpmSharedDevice(void);
    bool                     Release(void);
    bool                     Initialize(void);

    BYTE                     ReadByteFromSlot(UINT32 slotNo);
    char                     ReadCharFromSlot(UINT32 slotNo);
    int                      ReadIntFromSlot(UINT32 slotNo);
    float                    ReadFloatFromSlot(UINT32 slotNo);
    double                   ReadDoubleFromSlot(UINT32 slotNo);
    std::string              ReadStringFromSlot(UINT32 slotNo);
    std::vector<BYTE>        ReadByteArrayFromSlot(UINT32 slotNo, size_t count);
    std::vector<char>        ReadCharArrayFromSlot(UINT32 slotNo, size_t count);
    std::vector<int>         ReadIntArrayFromSlot(UINT32 slotNo, size_t count);
    std::vector<float>       ReadFloatArrayFromSlot(UINT32 slotNo, size_t count);
    std::vector<double>      ReadDoubleArrayFromSlot(UINT32 slotNo, size_t count);
    std::vector<std::string> ReadStringArrayFromSlot(UINT32 slotNo);
    void                     SetEndianness(Endianness mode);
    Endianness               GetEndianness() const;
    std::vector<SlotInfo>    SlotList();

protected:
    bool SlotClear(UINT32 slotNo);  // seçili slotu komple 0x00 verisiyle doldurur
    bool SlotFree(UINT32 slotNo);   // slotu NV alandan tamamen siler

private:
    bool m_useSharedTpmDevice;
    CTpmSharedDevice* m_sharedTpmDevice;

    Endianness m_endianness = Endianness::LittleEndian; // default
};