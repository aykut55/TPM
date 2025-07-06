#include "TpmClockReader.h"

#include <string>       // std::string
#include <iostream>     // std::cout
#include <sstream>      // std::stringstream

CTpmClockReader::~CTpmClockReader()
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

CTpmClockReader::CTpmClockReader(CTpmSharedDevice* sharedDevice)
    : m_useSharedTpmDevice(sharedDevice != nullptr), m_sharedTpmDevice(sharedDevice)
{
    try 
    {
        if (m_useSharedTpmDevice)
        {
            m_sharedTpmDevice = sharedDevice;
            std::stringstream ss;
            ss << "[CTpmClockReader] uses shared CTpmSharedDevice\n"; 
            Log(ss.str());
        }
        else
        {
            m_sharedTpmDevice = new CTpmSharedDevice();
            std::stringstream ss;
            ss << "[CTpmClockReader] uses local  CTpmSharedDevice\n";
            Log(ss.str());
        }

        tpm = m_sharedTpmDevice->GetTpm();
        device = m_sharedTpmDevice->GetDevice();

        memset(&clockInfo, 0, sizeof(TPMS_TIME_INFO));
    }
    catch (...) 
    {
        std::stringstream ss;
        ss << "Constructor unknown exception." << std::endl;
        Log(ss.str(), true);
    }
}

CTpmSharedDevice* CTpmClockReader::GetTpmSharedDevice(void)
{
    return m_sharedTpmDevice;
}

bool CTpmClockReader::Release(void)
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

bool CTpmClockReader::Initialize(void)
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

bool CTpmClockReader::ReadClock(void)
{
    try
    {
        if (!tpm) return false;

        clockInfo = tpm->ReadClock();

        return true;
    }
    catch (const std::exception& ex)
    {
        std::stringstream ss;
        ss << "ReadClock exception: " << ex.what() << std::endl;
        Log(ss.str(), true);
        return false;
    }
    catch (...)
    {
        std::stringstream ss;
        ss << "ReadClock unknown exception." << std::endl;
        Log(ss.str(), true);
        return false;
    }
}

uint64_t CTpmClockReader::GetClockTime(void)
{
    try
    {
        if (!tpm) return -1;

        return clockInfo.time;
    }
    catch (...)
    {
        std::stringstream ss;
        ss << "GetClockAsString unknown exception." << std::endl;
        Log(ss.str(), true);
        return -1;
    }
}

std::string CTpmClockReader::FormatClockAsDuration(uint64_t ms)
{
    uint64_t total_seconds = ms / 1000;

    uint64_t days = total_seconds / (24 * 3600);
    total_seconds %= (24 * 3600);

    uint64_t hours = total_seconds / 3600;
    total_seconds %= 3600;

    uint64_t minutes = total_seconds / 60;
    uint64_t seconds = total_seconds % 60;

    std::ostringstream oss;
    oss << days << " days, "
        << hours << " hours, "
        << minutes << " minutes, "
        << seconds << " seconds";

    return oss.str();
}

std::string CTpmClockReader::GetClockTimeAsString(void)
{
    try
    {
        if (!tpm) return "";

        std::ostringstream oss;

        oss << FormatClockAsDuration(clockInfo.time);

        return oss.str();
    }
    catch (const std::exception& ex)
    {
        std::stringstream ss;
        ss << "GetClockAsString exception: " << ex.what() << std::endl;
        Log(ss.str(), true);
        return "";
    }
    catch (...)
    {
        std::stringstream ss;
        ss << "GetClockAsString unknown exception." << std::endl;
        Log(ss.str(), true);
        return "";
    }
}

bool CTpmClockReader::ResetClock(bool fullFactoryReset)
{
    try
    {
        if (!tpm)
        {
            std::stringstream ss;
            ss << "Invalid TPM." << std::endl;
            Log(ss.str(), true);
            return false;
        }

        if (!device)
        {
            std::stringstream ss;
            ss << "No TPM device to reset." << std::endl;
            Log(ss.str(), true);
            return false;
        }

        if (fullFactoryReset)
        {
            // Bu Tüm TPM persistent ve NV verilerini temizler!
            tpm->Clear(TPM_RH::LOCKOUT);

            std::stringstream ss;
            ss << "[TPM] Factory reset (TPM2_Clear) performed." << std::endl;
            Log(ss.str());
        }
        else
        {
            if (!device->PowerCtlAvailable())
            {
                std::stringstream ss;
                ss << "[TPM] Power control not available on this device." << std::endl;
                Log(ss.str(), true);
                return false;
            }
            // Sadece power-cycle + startup
            device->PowerCycle();
            tpm->Startup(TPM_SU::CLEAR);

            std::stringstream ss;
            ss << "[TPM] Power-cycle reset performed." << std::endl;
            Log(ss.str());
        }

        return true;
    }
    catch (const std::exception& ex)
    {
        std::stringstream ss;
        ss << "ResetClock exception: " << ex.what() << std::endl;
        Log(ss.str(), true);
        return false;
    }
    catch (...)
    {
        std::stringstream ss;
        ss << "ResetClock unknown exception." << std::endl;
        Log(ss.str(), true);
        return false;
    }
}