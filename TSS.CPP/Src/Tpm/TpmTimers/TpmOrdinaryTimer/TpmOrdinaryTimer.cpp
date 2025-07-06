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
        if (m_watchdogRunning)
        {
            std::cout << "Watchdog already running." << std::endl;
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
                            m_ordinaryWatchdogCounter++;

                            // 8-byte big endian buffer
                            std::vector<BYTE> writeData(8, 0x00);
                            UINT64 tmp = m_ordinaryWatchdogCounter;
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

                            if (newCounter != m_ordinaryWatchdogCounter)
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


        std::cout << "Watchdog started." << std::endl;

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
        m_watchdogRunning = false;
        if (m_watchdogThread.joinable())
        {
            m_watchdogThread.join();
        }
        std::cout << "Watchdog stopped." << std::endl;

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

        return true;

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


bool CTpmOrdinaryTimer::InitWatchdogCounter(void)
{
    bool fncReturn = false;

    try
    {
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

        m_ordinaryWatchdogCounter = value;

        Log("[Watchdog] Ordinary counter initial value: " + std::to_string(m_ordinaryWatchdogCounter));

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

bool CTpmOrdinaryTimer::ResetWatchdogCounter(void)
{
    bool fncReturn = false;

    try
    {
        UINT32 nvIndex = TpmOrdinaryTimerNS::ORDINARY_COUNTER_NV_INDEX;

        // 8-byte sıfır
        std::vector<BYTE> zeroData(8, 0x00);

        tpm->NV_Write(TPM_RH::OWNER, nvIndex, zeroData, 0);

        m_ordinaryWatchdogCounter = 0;

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