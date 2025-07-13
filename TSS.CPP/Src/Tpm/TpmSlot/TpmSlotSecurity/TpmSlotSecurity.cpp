#include "TpmSlotSecurity.h"

#include <string>       // std::string
#include <iostream>     // std::cout
#include <sstream>      // std::stringstream

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

