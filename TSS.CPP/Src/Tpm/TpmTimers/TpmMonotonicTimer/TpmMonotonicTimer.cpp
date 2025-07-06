#include "TpmMonotonicTimer.h"

#include <string>       // std::string
#include <iostream>     // std::cout
#include <sstream>      // std::stringstream

CTpmMonotonicTimer::~CTpmMonotonicTimer()
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

CTpmMonotonicTimer::CTpmMonotonicTimer(CTpmSharedDevice* sharedDevice)
    : m_useSharedTpmDevice(sharedDevice != nullptr), m_sharedTpmDevice(sharedDevice)
{
    try
    {
        if (m_useSharedTpmDevice)
        {
            m_sharedTpmDevice = sharedDevice;
            std::stringstream ss;
            ss << "[CTpmMonotonicTimer] uses shared CTpmSharedDevice\n";
            Log(ss.str());
        }
        else
        {
            m_sharedTpmDevice = new CTpmSharedDevice();
            std::stringstream ss;
            ss << "[CTpmMonotonicTimer] uses local  CTpmSharedDevice\n";
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

CTpmSharedDevice* CTpmMonotonicTimer::GetTpmSharedDevice(void)
{
    return m_sharedTpmDevice;
}

bool CTpmMonotonicTimer::Release(void)
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

bool CTpmMonotonicTimer::Initialize(void)
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

bool CTpmMonotonicTimer::StartWatchdog(int intervalSeconds /*=5*/)
{
    bool fncReturn = false;

    try
    {
        if (!tpm) return false;

        if (m_watchdogRunning)
        {
            Log("Monotonic Watchdog already running.");
            return false;
        }

        m_watchdogRunning = true;

        m_watchdogThread = std::thread([this, intervalSeconds]()
            {
                while (m_watchdogRunning)
                {
                    try
                    {
                        Log("[Monotonic Watchdog] Checking TPM availability...");

                        if (!m_sharedTpmDevice->IsTpmAvailable())
                        {
                            Log("[Monotonic Watchdog] TPM unavailable! Attempting recovery...", true);
                            m_sharedTpmDevice->RecoverTpm(5);
                        }
                        else
                        {
                            Log("[Monotonic Watchdog] TPM OK.");

                            // increment
                            tpm->NV_Increment(TPM_RH::OWNER, TpmMonotonicTimerNS::MONOTONIC_COUNTER_NV_INDEX);

                            // read back
                            auto readVal = tpm->NV_Read(TPM_RH::OWNER, TpmMonotonicTimerNS::MONOTONIC_COUNTER_NV_INDEX, 8, 0);
                            UINT64 newCounter = 0;
                            if (readVal.size() >= 8)
                            {
                                for (int i = 0; i < 8; ++i)
                                {
                                    newCounter <<= 8;
                                    newCounter |= readVal[i];
                                }
                            }

                            Log("[Monotonic Watchdog] Counter value: " + std::to_string(newCounter));

                            if (newCounter != m_watchdogCounter + 1)
                            {
                                Log("[Monotonic Watchdog] Counter mismatch! Triggering recovery.", true);
                                m_sharedTpmDevice->RecoverTpm(5);
                            }

                            m_watchdogCounter = newCounter;
                        }
                    }
                    catch (const std::exception& ex)
                    {
                        std::stringstream ss;
                        ss << "[Monotonic Watchdog] exception: " << ex.what();
                        Log(ss.str(), true);
                    }
                    catch (...)
                    {
                        Log("[Monotonic Watchdog] unknown exception.", true);
                    }

                    std::this_thread::sleep_for(std::chrono::seconds(intervalSeconds));
                }
            });

        Log("Monotonic Watchdog started.");

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

bool CTpmMonotonicTimer::StopWatchdog(void)
{
    bool fncReturn = false;

    try
    {
        if (!tpm) return false;

        if (!m_watchdogRunning)
        {
            Log("Monotonic Watchdog not running.");
            return false;
        }

        m_watchdogRunning = false;

        if (m_watchdogThread.joinable())
        {
            m_watchdogThread.join();
            Log("Monotonic Watchdog stopped.");
        }

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

bool CTpmMonotonicTimer::NVDefineWatchdogCounter(void)
{
    bool fncReturn = false;

    try
    {
        if (!tpm) return false;

        UINT32 nvIndex = TpmMonotonicTimerNS::MONOTONIC_COUNTER_NV_INDEX;

        // NV index var mı diye kontrol et
        auto resp = tpm->GetCapability(TPM_CAP::HANDLES, nvIndex, 1);
        auto handles = dynamic_cast<TPML_HANDLE*>(&*resp.capabilityData)->handle;
        for (auto h : handles)
        {
            if (h == nvIndex)
            {
                Log("Monotonic NV Counter already defined.");
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
        nvAttrs |= TPMA_NV::COUNTER;

        // define
        TPMS_NV_PUBLIC nvPub(nvIndex, TPM_ALG_ID::SHA256, nvAttrs, {}, 8);*/
        TPMS_NV_PUBLIC nvPub(TpmMonotonicTimerNS::MONOTONIC_COUNTER_NV_INDEX, TPM_ALG_ID::SHA256,
            TPMA_NV::AUTHWRITE | TPMA_NV::AUTHREAD | TPMA_NV::COUNTER | TPMA_NV::OWNERWRITE | TPMA_NV::OWNERREAD, {}, 8);

        tpm->NV_DefineSpace(TPM_RH::OWNER, {}, nvPub);
        Log("Monotonic NV Counter defined successfully.");

        // Monotonic counter için NV_Write yapılamaz!
        //std::vector<BYTE> zeroData(8, 0x00);
        //tpm->NV_Write(TPM_RH::OWNER, nvIndex, zeroData, 0);
        //Log("Monotonic NV Counter initialized to 0.");

        fncReturn = true;
    }
    catch (const std::exception& ex)
    {
        std::stringstream ss;
        ss << "MonotonicDefineWatchdogCounter exception: " << ex.what() << std::endl;
        Log(ss.str(), true);
        fncReturn = false;
    }
    catch (...)
    {
        std::stringstream ss;
        ss << "MonotonicDefineWatchdogCounter unknown exception." << std::endl;
        Log(ss.str(), true);
        fncReturn = false;
    }

    return fncReturn;
}

bool CTpmMonotonicTimer::NVUndefineWatchdogCounter(bool fullFactoryReset)
{
    bool fncReturn = false;

    try
    {
        if (!tpm) return false;

        if (!fullFactoryReset)
        {
            Log("NVUndefineWatchdogCounter skipped (fullFactoryReset == false).");
            return true;
        }

        UINT32 nvIndex = TpmMonotonicTimerNS::MONOTONIC_COUNTER_NV_INDEX;

        // NV index var mı kontrol
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

        if (found)
        {
            tpm->NV_UndefineSpace(TPM_RH::OWNER, nvIndex);
            Log("Monotonic NV Counter successfully undefined.");
        }
        else
        {
            Log("Monotonic NV Counter does not exist, undefine skipped.");
        }

        fncReturn = true;
    }
    catch (const std::exception& ex)
    {
        std::stringstream ss;
        ss << "NVUndefineWatchdogCounter exception: " << ex.what() << std::endl;
        Log(ss.str(), true);
        fncReturn = false;
    }
    catch (...)
    {
        Log("NVUndefineWatchdogCounter unknown exception.", true);
        fncReturn = false;
    }

    return fncReturn;
}


bool CTpmMonotonicTimer::InitWatchdogCounter(void)
{
    bool fncReturn = false;

    try
    {
        if (!tpm) return false;

        UINT32 nvIndex = TpmMonotonicTimerNS::MONOTONIC_COUNTER_NV_INDEX;

        // define etmeyi garantile
        if (!NVDefineWatchdogCounter())
        {
            Log("Monotonic counter define failed.", true);
            return false;
        }

        // monotonic counter'da:
        // define edildikten sonra ilk NV_Increment çağrılmadan NV_Read yapılamaz
        // bu yüzden önce increment edip, sonra okumak zorundayız

        // ilk increment
        tpm->NV_Increment(TPM_RH::OWNER, nvIndex);
        Log("Monotonic NV Counter incremented for initialization.");

        // oku
        auto readVal = tpm->NV_Read(TPM_RH::OWNER, TpmMonotonicTimerNS::MONOTONIC_COUNTER_NV_INDEX, 8, 0);
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

        Log("[Watchdog] Monotonic counter initial value: " + std::to_string(m_watchdogCounter));

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

bool CTpmMonotonicTimer::ResetWatchdogCounter(void)
{
    bool fncReturn = false;

    try
    {
        if (!tpm) return false;

        UINT32 nvIndex = TpmMonotonicTimerNS::MONOTONIC_COUNTER_NV_INDEX;

        // önce index tanımlı mı bak
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

        if (found)
        {
            tpm->NV_UndefineSpace(TPM_RH::OWNER, nvIndex);
            Log("Monotonic NV Counter undefined for reset.");
        }

        // tekrar define
        if (!NVDefineWatchdogCounter())
        {
            Log("Monotonic NV Counter redefine failed after reset.", true);
            return false;
        }

        // ilk increment
        tpm->NV_Increment(TPM_RH::OWNER, nvIndex);
        Log("Monotonic NV Counter re-incremented after reset.");

        // read
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

        Log("Monotonic NV Counter reset to value: " + std::to_string(m_watchdogCounter));
        fncReturn = true;

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