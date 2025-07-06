#include "TpmOrdinaryTimer.h"

#include <string>       // std::string
#include <iostream>     // std::cout
#include <sstream>      // std::stringstream

CTpmOrdinaryTimer::~CTpmOrdinaryTimer()
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

CTpmOrdinaryTimer::CTpmOrdinaryTimer(CTpmSharedDevice* sharedDevice)
    : m_useSharedTpmDevice(sharedDevice != nullptr), m_sharedTpmDevice(sharedDevice)
{
    try
    {
        if (m_useSharedTpmDevice)
        {
            m_sharedTpmDevice = sharedDevice;
            std::stringstream ss;
            ss << "[CTpmOrdinaryTimer] uses shared CTpmSharedDevice\n";
            Log(ss.str());
        }
        else
        {
            m_sharedTpmDevice = new CTpmSharedDevice();
            std::stringstream ss;
            ss << "[CTpmOrdinaryTimer] uses local  CTpmSharedDevice\n";
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

CTpmSharedDevice* CTpmOrdinaryTimer::GetTpmSharedDevice(void)
{
    return m_sharedTpmDevice;
}

bool CTpmOrdinaryTimer::Release(void)
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

bool CTpmOrdinaryTimer::Initialize(void)
{
    bool fncReturn = false;

    try
    {
        if (!tpm) return false;

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

bool CTpmOrdinaryTimer::StartWatchdog(int intervalSeconds)
{
    bool fncReturn = false;

    try
    {
        if (!tpm) return false;

        if (m_watchdogRunning)
        {
            Log("Watchdog already running.");
            return false;
        }

        m_watchdogRunning = true;
        m_watchdogThread = std::thread([this, intervalSeconds]()
            {
                while (m_watchdogRunning)
                {
                    try
                    {
                        Log("[Watchdog] Checking TPM availability...");

                        if (!m_sharedTpmDevice->IsTpmAvailable())
                        {
                            Log("[Watchdog] TPM unavailable! Attempting recovery...", true);
                            m_sharedTpmDevice->RecoverTpm(5);
                        }
                        else
                        {
                            Log("[Watchdog] TPM OK.");

                            // ordinary counter increment
                            m_watchdogCounter++;

                            // 8-byte big endian buffer
                            std::vector<BYTE> writeData(8, 0x00);
                            UINT64 tmp = m_watchdogCounter;
                            for (int i = 7; i >= 0; --i)
                            {
                                writeData[i] = tmp & 0xFF;
                                tmp >>= 8;
                            }

                            // write to NV
                            tpm->NV_Write(TPM_RH::OWNER, TpmOrdinaryTimerNS::ORDINARY_COUNTER_NV_INDEX, writeData, 0);

                            // read back
                            auto readVal = tpm->NV_Read(TPM_RH::OWNER, TpmOrdinaryTimerNS::ORDINARY_COUNTER_NV_INDEX, 8, 0);
                            UINT64 newCounter = 0;
                            if (readVal.size() >= 8)
                            {
                                for (int i = 0; i < 8; ++i)
                                {
                                    newCounter <<= 8;
                                    newCounter |= readVal[i];
                                }
                            }

                            Log("[Watchdog] Ordinary counter value: " + std::to_string(newCounter));

                            if (newCounter != m_watchdogCounter)
                            {
                                Log("[Watchdog] Ordinary counter mismatch! Triggering recovery.", true);
                                m_sharedTpmDevice->RecoverTpm(5);
                            }
                        }
                    }
                    catch (const std::exception& ex)
                    {
                        Log(std::string("[Watchdog] exception: ") + ex.what(), true);
                    }
                    catch (...)
                    {
                        Log("[Watchdog] unknown exception", true);
                    }

                    std::this_thread::sleep_for(std::chrono::seconds(intervalSeconds));
                }
            });

        Log("Watchdog started.");

        fncReturn = true;
    }
    catch (const std::exception& ex)
    {
        std::stringstream ss;
        ss << "StartWatchdog exception: " << ex.what() << std::endl;
        Log(ss.str(), true);
        fncReturn = false;
    }
    catch (...)
    {
        std::stringstream ss;
        ss << "StartWatchdog unknown exception." << std::endl;
        Log(ss.str(), true);
        fncReturn = false;
    }

    return fncReturn;
}

bool CTpmOrdinaryTimer::StopWatchdog(void)
{
    bool fncReturn = false;

    try
    {
        if (!tpm) return false;

        m_watchdogRunning = false;
        if (m_watchdogThread.joinable())
        {
            m_watchdogThread.join();
        }

        Log("Watchdog stopped.");

        fncReturn = true;
    }
    catch (const std::exception& ex)
    {
        std::stringstream ss;
        ss << "StopWatchdog exception: " << ex.what() << std::endl;
        Log(ss.str(), true);
        fncReturn = false;
    }
    catch (...)
    {
        std::stringstream ss;
        ss << "StopWatchdog unknown exception." << std::endl;
        Log(ss.str(), true);
        fncReturn = false;
    }

    return fncReturn;
}

bool CTpmOrdinaryTimer::OrdinaryDefineWatchdogCounter(UINT32 nvIndex)
{
    bool fncReturn = false;

    try
    {
        if (!tpm) return false;

        // NV index var mı diye kontrol et
        auto resp = tpm->GetCapability(TPM_CAP::HANDLES, nvIndex, 1);
        auto handles = dynamic_cast<TPML_HANDLE*>(&*resp.capabilityData)->handle;
        for (auto h : handles)
        {
            if (h == nvIndex)
            {
                Log("Ordinary NV Counter already defined at index " + std::to_string(nvIndex));
                return true;
            }
        }

        // attributes
        /*
        TPMA_NV nvAttrs;
        nvAttrs.val = 0;
        nvAttrs |= TPMA_NV::AUTHWRITE;
        nvAttrs |= TPMA_NV::AUTHREAD;
        nvAttrs |= TPMA_NV::OWNERWRITE;
        nvAttrs |= TPMA_NV::OWNERREAD;

        // define
        TPMS_NV_PUBLIC nvPub(nvIndex, TPM_ALG_ID::SHA256, nvAttrs, {}, 8);*/
        TPMS_NV_PUBLIC nvPub(
            nvIndex,
            TPM_ALG_ID::SHA256,
            TPMA_NV::AUTHWRITE | TPMA_NV::AUTHREAD | TPMA_NV::OWNERWRITE | TPMA_NV::OWNERREAD,
            {},
            8 // 8-byte
        );

        tpm->NV_DefineSpace(TPM_RH::OWNER, {}, nvPub);
        Log("Ordinary NV Counter defined successfully at index " + std::to_string(nvIndex));

        // 8-byte sıfır
        std::vector<BYTE> zeroData(8, 0x00);
        tpm->NV_Write(TPM_RH::OWNER, nvIndex, zeroData, 0);
        Log("Ordinary NV Counter initialized to 0 at index " + std::to_string(nvIndex));

        fncReturn = true;
    }
    catch (const std::exception& ex)
    {
        std::stringstream ss;
        ss << "OrdinaryDefineWatchdogCounter exception: " << ex.what();
        Log(ss.str(), true);
        fncReturn = false;
    }
    catch (...)
    {
        Log("OrdinaryDefineWatchdogCounter unknown exception.", true);
        fncReturn = false;
    }

    return fncReturn;
}

bool CTpmOrdinaryTimer::OrdinaryUndefineWatchdogCounter(UINT32 nvIndex)
{
    bool fncReturn = false;

    try
    {
        if (!tpm) return false;

        // NV index var mı diye kontrol et
        auto resp = tpm->GetCapability(TPM_CAP::HANDLES, nvIndex, 1);
        auto handles = dynamic_cast<TPML_HANDLE*>(&*resp.capabilityData)->handle;

        bool found = false;
        for (auto h : handles)
        {
            if (h == nvIndex)
            {
                found = true;
                break;
            }
        }

        if (!found)
        {
            Log("Ordinary NV Counter does not exist at index " + std::to_string(nvIndex) + ", undefine skipped.");
            return true;
        }

        tpm->NV_UndefineSpace(TPM_RH::OWNER, nvIndex);
        Log("Ordinary NV Counter successfully undefined at index " + std::to_string(nvIndex));

        fncReturn = true;
    }
    catch (const std::exception& ex)
    {
        std::stringstream ss;
        ss << "OrdinaryUndefineWatchdogCounter exception: " << ex.what();
        Log(ss.str(), true);
        fncReturn = false;
    }
    catch (...)
    {
        Log("OrdinaryUndefineWatchdogCounter unknown exception.", true);
        fncReturn = false;
    }

    return fncReturn;
}

bool CTpmOrdinaryTimer::OrdinaryDefineWatchdogCounter(void)
{
    return OrdinaryDefineWatchdogCounter(TpmOrdinaryTimerNS::ORDINARY_COUNTER_NV_INDEX);
}

bool CTpmOrdinaryTimer::OrdinaryUndefineWatchdogCounter(void)
{
    return OrdinaryUndefineWatchdogCounter(TpmOrdinaryTimerNS::ORDINARY_COUNTER_NV_INDEX);
}

#if 0
bool CTpmOrdinaryTimer::OrdinaryDefineWatchdogCounter(void)
{
    bool fncReturn = false;

    try
    {
        if (!tpm) return false;

        UINT32 nvIndex = TpmOrdinaryTimerNS::ORDINARY_COUNTER_NV_INDEX;

        // NV index var mı diye kontrol et
        auto resp = tpm->GetCapability(TPM_CAP::HANDLES, nvIndex, 1);
        auto handles = dynamic_cast<TPML_HANDLE*>(&*resp.capabilityData)->handle;
        for (auto h : handles)
        {
            if (h == nvIndex)
            {
                Log("Ordinary NV Counter already defined.");
                return true;
            }
        }

        // attributes
        /*
        TPMA_NV nvAttrs;
        nvAttrs.val = 0;
        nvAttrs |= TPMA_NV::AUTHWRITE;
        nvAttrs |= TPMA_NV::AUTHREAD;
        nvAttrs |= TPMA_NV::OWNERWRITE;
        nvAttrs |= TPMA_NV::OWNERREAD;

        // define
        TPMS_NV_PUBLIC nvPub(nvIndex, TPM_ALG_ID::SHA256, nvAttrs, {}, 8);*/
        TPMS_NV_PUBLIC nvPub(TpmOrdinaryTimerNS::ORDINARY_COUNTER_NV_INDEX, TPM_ALG_ID::SHA256,
            TPMA_NV::AUTHWRITE | TPMA_NV::AUTHREAD | TPMA_NV::OWNERWRITE | TPMA_NV::OWNERREAD, {}, 8);

        tpm->NV_DefineSpace(TPM_RH::OWNER, {}, nvPub);
        Log("Ordinary NV Counter defined successfully.");

        // ilk değer olarak 0 yaz
        std::vector<BYTE> zeroData(8, 0x00);
        tpm->NV_Write(TPM_RH::OWNER, nvIndex, zeroData, 0);
        Log("Ordinary NV Counter initialized to 0.");

        fncReturn = true;
    }
    catch (const std::exception& ex)
    {
        std::stringstream ss;
        ss << "OrdinaryDefineWatchdogCounter exception: " << ex.what() << std::endl;
        Log(ss.str(), true);
        fncReturn = false;
    }
    catch (...)
    {
        std::stringstream ss;
        ss << "OrdinaryDefineWatchdogCounter unknown exception." << std::endl;
        Log(ss.str(), true);
        fncReturn = false;
    }

    return fncReturn;
}

bool CTpmOrdinaryTimer::OrdinaryUndefineWatchdogCounter(void)
{
    bool fncReturn = false;

    try
    {
        if (!tpm) return false;

        UINT32 nvIndex = TpmOrdinaryTimerNS::ORDINARY_COUNTER_NV_INDEX;

        // NV index var mı diye kontrol et
        auto resp = tpm->GetCapability(TPM_CAP::HANDLES, nvIndex, 1);
        auto handles = dynamic_cast<TPML_HANDLE*>(&*resp.capabilityData)->handle;

        bool found = false;
        for (auto h : handles)
        {
            if (h == nvIndex)
            {
                found = true;
                break;
            }
        }

        if (!found)
        {
            Log("Ordinary NV Counter does not exist, no undefine needed.");
            return true;
        }

        // NV_UndefineSpace
        tpm->NV_UndefineSpace(TPM_RH::OWNER, nvIndex);
        Log("Ordinary NV Counter successfully undefined.");

        fncReturn = true;
    }
    catch (const std::exception& ex)
    {
        std::stringstream ss;
        ss << "OrdinaryUndefineWatchdogCounter exception: " << ex.what() << std::endl;
        Log(ss.str(), true);
        fncReturn = false;
    }
    catch (...)
    {
        std::stringstream ss;
        ss << "OrdinaryUndefineWatchdogCounter unknown exception." << std::endl;
        Log(ss.str(), true);
        fncReturn = false;
    }

    return fncReturn;
}
#endif

#if 0
bool CTpmOrdinaryTimer::InitWatchdogCounter(void)
{
    bool fncReturn = false;

    try
    {
        if (!tpm) return false;

        if (!OrdinaryDefineWatchdogCounter())
        {
            Log("Ordinary counter define failed.", true);
            return false;
        }

        // oku
        auto readVal = tpm->NV_Read(TPM_RH::OWNER, TpmOrdinaryTimerNS::ORDINARY_COUNTER_NV_INDEX, 8, 0);
        UINT64 value = 0;
        if (readVal.size() >= 8)
        {
            for (int i = 0; i < 8; ++i)
            {
                value <<= 8;
                value |= readVal[i];
            }
        }

        m_watchdogCounter = value;

        Log("[Watchdog] Ordinary counter initial value: " + std::to_string(m_watchdogCounter));

        fncReturn = true;
    }
    catch (const std::exception& ex)
    {
        std::stringstream ss;
        ss << "InitWatchdogCounter exception: " << ex.what() << std::endl;
        Log(ss.str(), true);
        fncReturn = false;
    }
    catch (...)
    {
        std::stringstream ss;
        ss << "InitWatchdogCounter unknown exception." << std::endl;
        Log(ss.str(), true);
        fncReturn = false;
    }

    return fncReturn;
}
#endif
bool CTpmOrdinaryTimer::InitWatchdogCounter(UINT32 nvIndex)
{
    bool fncReturn = false;

    try
    {
        if (!tpm) return false;

        if (!OrdinaryDefineWatchdogCounter(nvIndex))
        {
            Log("Ordinary counter define failed at index " + std::to_string(nvIndex), true);
            return false;
        }

        // oku
        auto readVal = tpm->NV_Read(TPM_RH::OWNER, nvIndex, 8, 0);
        UINT64 value = 0;
        if (readVal.size() >= 8)
        {
            for (int i = 0; i < 8; ++i)
            {
                value <<= 8;
                value |= readVal[i];
            }
        }

        m_watchdogCounter = value;

        Log("[Watchdog] Ordinary counter initial value at index " + std::to_string(nvIndex) + ": " + std::to_string(m_watchdogCounter));

        fncReturn = true;
    }
    catch (const std::exception& ex)
    {
        std::stringstream ss;
        ss << "InitWatchdogCounter exception: " << ex.what();
        Log(ss.str(), true);
        fncReturn = false;
    }
    catch (...)
    {
        Log("InitWatchdogCounter unknown exception.", true);
        fncReturn = false;
    }

    return fncReturn;
}

bool CTpmOrdinaryTimer::InitWatchdogCounter(void)
{
    return InitWatchdogCounter(TpmOrdinaryTimerNS::ORDINARY_COUNTER_NV_INDEX);
}


#if 0
bool CTpmOrdinaryTimer::ResetWatchdogCounter(void)
{
    bool fncReturn = false;

    try
    {
        if (!tpm) return false;

        UINT32 nvIndex = TpmOrdinaryTimerNS::ORDINARY_COUNTER_NV_INDEX;

        // 8-byte sıfır
        std::vector<BYTE> zeroData(8, 0x00);

        tpm->NV_Write(TPM_RH::OWNER, nvIndex, zeroData, 0);

        m_watchdogCounter = 0;

        Log("Ordinary NV Counter reset to 0.");
        return true;

        fncReturn = true;
    }
    catch (const std::exception& ex)
    {
        std::stringstream ss;
        ss << "ResetWatchdogCounter exception: " << ex.what() << std::endl;
        Log(ss.str(), true);
        fncReturn = false;
    }
    catch (...)
    {
        std::stringstream ss;
        ss << "ResetWatchdogCounter unknown exception." << std::endl;
        Log(ss.str(), true);
        fncReturn = false;
    }

    return fncReturn;
}
#endif
bool CTpmOrdinaryTimer::ResetWatchdogCounter(UINT32 nvIndex)
{
    bool fncReturn = false;

    try
    {
        if (!tpm) return false;

        // 8-byte sıfır buffer
        std::vector<BYTE> zeroData(8, 0x00);

        tpm->NV_Write(TPM_RH::OWNER, nvIndex, zeroData, 0);

        m_watchdogCounter = 0;

        Log("Ordinary NV Counter reset to 0 at index " + std::to_string(nvIndex));
        fncReturn = true;
    }
    catch (const std::exception& ex)
    {
        std::stringstream ss;
        ss << "ResetWatchdogCounter exception: " << ex.what();
        Log(ss.str(), true);
        fncReturn = false;
    }
    catch (...)
    {
        Log("ResetWatchdogCounter unknown exception.", true);
        fncReturn = false;
    }

    return fncReturn;
}

bool CTpmOrdinaryTimer::ResetWatchdogCounter(void)
{
    return ResetWatchdogCounter(TpmOrdinaryTimerNS::ORDINARY_COUNTER_NV_INDEX);
}

#if 0
bool CTpmOrdinaryTimer::ReadWatchdogCounter(int& value)
{
    bool fncReturn = false;

    try
    {
        if (!tpm) return false;

        UINT32 nvIndex = TpmOrdinaryTimerNS::ORDINARY_COUNTER_NV_INDEX;

        auto readVal = tpm->NV_Read(TPM_RH::OWNER, nvIndex, 8, 0);
        UINT64 counterValue = 0;

        if (readVal.size() >= 8)
        {
            for (int i = 0; i < 8; ++i)
            {
                counterValue <<= 8;
                counterValue |= readVal[i];
            }
        }

        value = static_cast<int>(counterValue);
        m_watchdogCounter = counterValue;

        Log("Ordinary NV Counter read: " + std::to_string(value));
        fncReturn = true;
    }
    catch (const std::exception& ex)
    {
        std::stringstream ss;
        ss << "ReadWatchdogCounter exception: " << ex.what() << std::endl;
        Log(ss.str(), true);
        fncReturn = false;
    }
    catch (...)
    {
        std::stringstream ss;
        ss << "ReadWatchdogCounter unknown exception." << std::endl;
        Log(ss.str(), true);
        fncReturn = false;
    }

    return fncReturn;
}

bool CTpmOrdinaryTimer::WriteWatchdogCounter(int& value)
{
    bool fncReturn = false;

    try
    {
        if (!tpm) return false;

        UINT32 nvIndex = TpmOrdinaryTimerNS::ORDINARY_COUNTER_NV_INDEX;

        // int'i 8-byte big endian'e çevir
        std::vector<BYTE> data(8, 0x00);
        UINT64 val64 = static_cast<UINT64>(value);
        for (int i = 7; i >= 0; --i)
        {
            data[i] = val64 & 0xFF;
            val64 >>= 8;
        }

        tpm->NV_Write(TPM_RH::OWNER, nvIndex, data, 0);

        m_watchdogCounter = value;

        Log("Ordinary NV Counter written to: " + std::to_string(value));
        fncReturn = true;
    }
    catch (const std::exception& ex)
    {
        std::stringstream ss;
        ss << "WriteWatchdogCounter exception: " << ex.what() << std::endl;
        Log(ss.str(), true);
        fncReturn = false;
    }
    catch (...)
    {
        std::stringstream ss;
        ss << "WriteWatchdogCounter unknown exception." << std::endl;
        Log(ss.str(), true);
        fncReturn = false;
    }

    return fncReturn;
}
#endif
bool CTpmOrdinaryTimer::ReadWatchdogCounter(UINT32 nvIndex, UINT64& value)
{
    bool fncReturn = false;

    try
    {
        if (!tpm) return false;

        auto readVal = tpm->NV_Read(TPM_RH::OWNER, nvIndex, 8, 0);
        UINT64 counterValue = 0;

        if (readVal.size() >= 8)
        {
            for (int i = 0; i < 8; ++i)
            {
                counterValue <<= 8;
                counterValue |= readVal[i];
            }
        }

        value = static_cast<int>(counterValue);
        m_watchdogCounter = counterValue;

        Log("Ordinary NV Counter read from index " + std::to_string(nvIndex) + " value: " + std::to_string(value));
        fncReturn = true;
    }
    catch (const std::exception& ex)
    {
        std::stringstream ss;
        ss << "ReadWatchdogCounter exception: " << ex.what();
        Log(ss.str(), true);
        fncReturn = false;
    }
    catch (...)
    {
        Log("ReadWatchdogCounter unknown exception.", true);
        fncReturn = false;
    }

    return fncReturn;
}

bool CTpmOrdinaryTimer::WriteWatchdogCounter(UINT32 nvIndex, UINT64& value)
{
    bool fncReturn = false;

    try
    {
        if (!tpm) return false;

        // int'i 8-byte big endian'e çevir
        std::vector<BYTE> data(8, 0x00);
        UINT64 val64 = static_cast<UINT64>(value);
        for (int i = 7; i >= 0; --i)
        {
            data[i] = val64 & 0xFF;
            val64 >>= 8;
        }

        tpm->NV_Write(TPM_RH::OWNER, nvIndex, data, 0);

        m_watchdogCounter = value;

        Log("Ordinary NV Counter written to index " + std::to_string(nvIndex) + " value: " + std::to_string(value));
        fncReturn = true;
    }
    catch (const std::exception& ex)
    {
        std::stringstream ss;
        ss << "WriteWatchdogCounter exception: " << ex.what();
        Log(ss.str(), true);
        fncReturn = false;
    }
    catch (...)
    {
        Log("WriteWatchdogCounter unknown exception.", true);
        fncReturn = false;
    }

    return fncReturn;
}


bool CTpmOrdinaryTimer::ReadWatchdogCounter(UINT64& value)
{
    return ReadWatchdogCounter(TpmOrdinaryTimerNS::ORDINARY_COUNTER_NV_INDEX, value);
}

bool CTpmOrdinaryTimer::WriteWatchdogCounter(UINT64& value)
{
    return WriteWatchdogCounter(TpmOrdinaryTimerNS::ORDINARY_COUNTER_NV_INDEX, value);
}
