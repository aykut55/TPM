#include "TpmSharedDevice.h"

CTpmSharedDevice::~CTpmSharedDevice()
{
    try 
    {
        StopHealthCheckLoop();

        Shutdown();

        if (m_useSimulator)
        {
            // A clean shutdown results in fewer lockout errors.
            tpm->Shutdown(TPM_SU::CLEAR);
            device->PowerOff();
        }

        // The following routine finalizes and prints the function stats.
        FinishCallbacks();

        delete device;

        delete tpm;
    }
    catch (...) 
    {

    }
}

CTpmSharedDevice::CTpmSharedDevice(bool useSimulator)
{
    try 
    {
        m_useSimulator = useSimulator;
        tpm = new Tpm2();
    }
    catch (...) 
    {

    }
}

bool CTpmSharedDevice::Shutdown(void)
{
    bool fncReturn = false;

    try
    {
        if (tpm)
        {
            if (m_useSimulator)
            {
                // A clean shutdown results in fewer lockout errors.
                tpm->Shutdown(TPM_SU::CLEAR);
                device->PowerOff();
            }

            // The following routine finalizes and prints the function stats.
            FinishCallbacks();

            std::cout << "[CTpmSharedDevice] TPM closed." << std::endl;

            fncReturn = true;
        }
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[CTpmSharedDevice] Shutdown exception: " << ex.what() << std::endl;
        fncReturn = false;
    }
    catch (...)
    {
        std::cerr << "[CTpmSharedDevice] Shutdown unknown exception." << std::endl;
        fncReturn = false;
    }

    return fncReturn;
}

bool CTpmSharedDevice::Initialize(void)
{
    bool fncReturn = false;

    try
    {
        device = m_useSimulator ? new TpmTcpDevice("127.0.0.1", 2321) : (TpmDevice*) new TpmTbsDevice();

        if (!device || !device->Connect())
        {
            device = nullptr;
            throw std::runtime_error("Could not connect to TPM device.");
        }

        tpm->_SetDevice(*device);

        if (m_useSimulator)
        {
            // Bu kod normalde sistem TPM'inde gerekmez
            assert(device->PlatformAvailable() &&
                device->ImplementsPhysicalPresence() &&
                device->PowerCtlAvailable() &&
                device->LocalityCtlAvailable());

            device->PowerCycle();

            // TPM'i başlat
            tpm->Startup(TPM_SU::CLEAR);
        }

        RecoverTpm(1);

        StartCallbacks();

        myTpmConfig::Init(*tpm);

        fncReturn = true;
    }
    catch (const std::exception& ex)
    {
        // m_lastError = ex.what();
        // Log(std::string("Initialize exception: ") + ex.what(), true);

        std::cerr << "Initialize exception: " << ex.what() << std::endl;
        fncReturn = false;
    }
    catch (...)
    {
        std::cerr << "Initialize unknown exception." << std::endl;
        fncReturn = false;
    }

    return fncReturn;
}

bool CTpmSharedDevice::IsTpmAvailable(void)
{
    bool fncReturn = false;

    try
    {
        if (!device) return false;

        // Sadece gerekliyse startup yap
        auto caps = tpm->GetCapability(TPM_CAP::TPM_PROPERTIES, 0, 1); //tpm->GetCapability(TPM_CAP::TPM_PROPERTIES, TPM_PT::TOTAL_COMMANDS, 1); 
        if (tpm->_GetLastResponseCode() == TPM_RC::SUCCESS)
        {
            return true;
        }
        else 
        {
            tpm->Startup(TPM_SU::STATE);  // sadece gerekiyorsa
            return true;
        }
    }
    catch (...)
    {
        return false;
    }

    return fncReturn;
}

void CTpmSharedDevice::StartHealthCheckLoop(int periodSeconds)
{
    try
    {
        if (m_healthThread.joinable())
        {
            std::cout << "[CTpmSharedDevice] Health check already running." << std::endl;
            return;
        }

        m_healthStopFlag = false;

        m_healthThread = std::thread([this, periodSeconds]()
            {
                int recoverAttempts = 0;

                int healthCheckCount = 0;

                while (!m_healthStopFlag)
                {
                    if (IsTpmAvailable())
                    {
                        std::cout << "[CTpmSharedDevice] HealthCheck: TPM available [ " << healthCheckCount << " ] " << std::endl;
                        recoverAttempts = 0;
                    }
                    else
                    {
                        std::cerr << "[CTpmSharedDevice] HealthCheck ALERT: TPM NOT available!" << std::endl;

                        if (recoverAttempts < 3)
                        {
                            std::cerr << "[CTpmSharedDevice] Attempting TPM recovery..." << std::endl;
                            RecoverTpm(recoverAttempts + 1);
                            recoverAttempts++;
                        }
                        else
                        {
                            std::cerr << "[CTpmSharedDevice] Recovery failed after 3 attempts." << std::endl;
                            if (m_recoverCallback)
                            {
                                m_recoverCallback("Recovery failed after 3 attempts.", recoverAttempts);
                            }
                        }
                    }

                    std::this_thread::sleep_for(std::chrono::seconds(periodSeconds));

                    healthCheckCount++;
                }
            });

        std::cout << "[CTpmSharedDevice] Health check thread started." << std::endl;
    }
    catch (...)
    {

    }
}

void CTpmSharedDevice::StopHealthCheckLoop(void)
{
    try
    {
        m_healthStopFlag = true;
        if (m_healthThread.joinable())
        {
            m_healthThread.join();
            std::cout << "[CTpmSharedDevice] Health check thread stopped." << std::endl;
        }
    }
    catch (...)
    {

    }
}

void CTpmSharedDevice::SetRecoverCallback(std::function<void(const std::string&, int attemptCount)> cb)
{
    try
    {
        m_recoverCallback = cb;
    }
    catch (...)
    {

    }
}

void CTpmSharedDevice::CleanHandlesOfType(Tpm2* tpm, TPM_HT handleType, UINT32 rangeBegin, UINT32 rangeEnd)
{
    UINT32  startHandle = (handleType << 24) + rangeBegin, rangeSize = rangeEnd - rangeBegin;
    GetCapabilityResponse resp;
    size_t count = 0;
    for (;;)
    {
        resp = tpm->GetCapability(TPM_CAP::HANDLES, startHandle, rangeSize);
        auto handles = dynamic_cast<TPML_HANDLE*>(&*resp.capabilityData)->handle;

        for (auto& h : handles)
        {
            if ((h.handle & 0x00FFFFFF) >= rangeEnd)
                break;
            if (handleType == TPM_HT::NV_INDEX)
            {
                tpm->_AllowErrors().NV_UndefineSpace(TPM_RH::OWNER, h);
                if (!tpm->_LastCommandSucceeded())
                    fprintf(stderr, "Failed to clean NV index 0x%08X: error %s\n", h.handle, EnumToStr(tpm->_GetLastResponseCode()).c_str());
            }
            else if (handleType == TPM_HT::PERSISTENT)
            {
                tpm->_AllowErrors().EvictControl(TPM_RH::OWNER, h, h);
                if (!tpm->_LastCommandSucceeded())
                    fprintf(stderr, "Failed to clean persistent object 0x%08X: error %s\n", h.handle, EnumToStr(tpm->_GetLastResponseCode()).c_str());
            }
            else
                tpm->_AllowErrors().FlushContext(h);
            ++count;
        }

        if (!resp.moreData)
            break;
        auto newStart = (UINT32)handles.back().handle + 1;
        rangeSize -= newStart - startHandle;
        startHandle = newStart;
    }

    if (count)
        cout << "Cleaned " << count << " dangling " << EnumToStr(handleType) << " handle" << (count == 1 ? "" : "s") << endl;
    else
        cout << "No dangling " << EnumToStr(handleType) << " handles" << endl;
}

void CTpmSharedDevice::RecoverTpm(int attemptCount)
{
    try
    {
        TPMLockoutReset();
        
        // Lockout reset attempt
        tpm->_AllowErrors().DictionaryAttackLockReset(TPM_RH::LOCKOUT);

        if (!tpm->_LastCommandSucceeded())
        {
            if (m_recoverCallback)
            {
                m_recoverCallback("[CTpmSharedDevice] Lockout reset failed.", attemptCount);
            }
        }
        else
        {
            if (m_recoverCallback)
            {
                m_recoverCallback("[CTpmSharedDevice] Lockout reset successful.", attemptCount);
            }
        }

        if (m_recoverCallback)
        {
            m_recoverCallback("RecoverTpm: DictionaryAttackLockReset attempted.", attemptCount);
        }

        if (!tpm->_LastCommandSucceeded() && m_useSimulator)
        {
            if (m_recoverCallback)
            {
                m_recoverCallback("RecoverTpm: LockReset failed, entering simulator recovery.", attemptCount);
            }

            tpm->_AllowErrors().Shutdown(TPM_SU::CLEAR);

            if (m_recoverCallback)
            {
                m_recoverCallback("RecoverTpm: TPM shutdown issued.", attemptCount);
            }

            device->PowerCycle();

            if (m_recoverCallback)
            {
                m_recoverCallback("RecoverTpm: Simulator power-cycled.", attemptCount);
            }

            tpm->Startup(TPM_SU::CLEAR);

            if (m_recoverCallback)
            {
                m_recoverCallback("RecoverTpm: TPM startup issued.", attemptCount);
            }

            // Clearing the TPM:
            // - Deletes persistent and transient objects in the Storage and Endorsement hierarchies;
            // - Deletes non-platform NV indices;
            // - Generates new Storage Primary Seed;
            // - Re-enables disabled hierarchies;
            // - Resets Owner, Endorsement, and Lockout auth values and auth policies;
            // - Resets clock, reset and restart counters.            
            tpm->Clear(TPM_RH::PLATFORM);

            if (m_recoverCallback)
            {
                m_recoverCallback("RecoverTpm: TPM cleared successfully.", attemptCount);
            }
        }

        /*CleanHandlesOfType(tpm, TPM_HT::LOADED_SESSION);
        CleanHandlesOfType(tpm, TPM_HT::TRANSIENT);
        CleanHandlesOfType(tpm, TPM_HT::PERSISTENT, TpmSharedDeviceNS::PersRangeBegin, TpmSharedDeviceNS::PersRangeEnd);
        CleanHandlesOfType(tpm, TPM_HT::NV_INDEX, TpmSharedDeviceNS::NvRangeBegin, TpmSharedDeviceNS::NvRangeEnd);*/
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[CTpmSharedDevice] RecoverTpm exception: " << ex.what() << std::endl;
        if (m_recoverCallback)
        {
            m_recoverCallback(std::string("RecoverTpm exception: ") + ex.what(), attemptCount);
        }
    }
    catch (...)
    {
        std::cerr << "[CTpmSharedDevice] RecoverTpm unknown exception." << std::endl;
        if (m_recoverCallback)
        {
            m_recoverCallback("RecoverTpm unknown exception.", attemptCount);
        }
    }
}

void CTpmSharedDevice::StartCallbacks(bool announceCallbacks)
{
    if (announceCallbacks)
    {
        Announce("Installing callback");

        // Install a callback that is invoked after the TPM command has been executed
        tpm->_SetResponseCallback(&CTpmSharedDevice::TpmCallbackStatic, this);

#if 0
        // chatgpt onerdi
        tpm->_SetCommandCallbacks(
            [](const std::string& cmdName) {
                std::cout << "[TPM] Command START: " << cmdName << std::endl;
            },
            [](const std::string& cmdName, const TpmBuffer& cmdBuf, const TpmBuffer& rspBuf) {
                std::cout << "[TPM] Command FINISH: " << cmdName
                    << ", ReqSize=" << cmdBuf.size()
                    << ", RspSize=" << rspBuf.size()
                    << std::endl;
            }
        );
#endif
    }
}

void CTpmSharedDevice::FinishCallbacks(bool announceCallbacks)
{
    if (announceCallbacks)
    {
        Announce("Processing callback data");

        cout << "Commands invoked:" << endl;
        for (auto it = commandsInvoked.begin(); it != commandsInvoked.end(); ++it)
            cout << dec << setfill(' ') << setw(32) << EnumToStr(it->first) << ": count = " << it->second << endl;

        cout << endl << "Responses received:" << endl;
        for (auto it = responses.begin(); it != responses.end(); ++it)
            cout << dec << setfill(' ') << setw(32) << EnumToStr(it->first) << ": count = " << it->second << endl;

        cout << endl << "Commands not exercised:" << endl;
        for (auto it = commandsImplemented.begin(); it != commandsImplemented.end(); ++it)
        {
            if (commandsInvoked.find(*it) == commandsInvoked.end())
                cout << dec << setfill(' ') << setw(1) << EnumToStr(*it) << " ";
        }
        cout << endl;
    }

    tpm->_SetResponseCallback(NULL, NULL);
}

void CTpmSharedDevice::TpmCallback(const ByteVec& command, const ByteVec& response)
{
    // Extract the command and responses codes from the buffers.
    // Both are 4 bytes long starting at byte 6
    UINT32* commandCodePtr = (UINT32*)&command[6];
    UINT32* responseCodePtr = (UINT32*)&response[6];

    TPM_CC cmdCode = (TPM_CC)ntohl(*commandCodePtr);
    TPM_RC rcCode = (TPM_RC)ntohl(*responseCodePtr);

    // Strip any parameter decorations
    rcCode = Tpm2::ResponseCodeFromTpmError(rcCode);

    commandsInvoked[cmdCode]++;
    responses[rcCode]++;
}

void CTpmSharedDevice::TPMLockoutReset(void)
{
    TPM_HANDLE lockoutHandle = TPM_RH::LOCKOUT;
    std::string lockoutPassword = "mypassword";  // Eğer böyle bir auth atandıysa

    bool pinIsDefined = false;
    if (!pinIsDefined)
    {
        lockoutHandle.SetAuth({}); // Eğer parola atanmadıysa (default TPM konfigürasyonu)
        tpm->Clear(lockoutHandle);
    }
    else
    {
        lockoutHandle.SetAuth(std::vector<BYTE>(lockoutPassword.begin(), lockoutPassword.end()));
        tpm->Clear(lockoutHandle);
    }

    tpm->_AllowErrors().DictionaryAttackLockReset(TPM_RH::LOCKOUT);
    if (!tpm->_LastCommandSucceeded()) 
    {
        std::cerr << "Lockout reset failed. May need platform auth or simulator restart." << std::endl;
    }
}

// The TPM maintains global dictionary attack remediation logic. A special
// authValue is needed to control it. This is LockoutAuth.
// Reset the lockout
// And set the TPM to be fairly forgiving for running the tests 
void CTpmSharedDevice::DictionaryAttackLockReset(void)
{
    // The TPM maintains global dictionary attack remediation logic. A special
    // authValue is needed to control it. This is LockoutAuth.

    // Reset the lockout
    tpm->DictionaryAttackLockReset(TPM_RH::LOCKOUT);

    // And set the TPM to be fairly forgiving for running the tests
    UINT32 newMaxTries = 1000, newRecoverTime = 1, lockoutAuthFailRecoveryTime = 1;
    tpm->DictionaryAttackParameters(TPM_RH::LOCKOUT, newMaxTries, newRecoverTime, lockoutAuthFailRecoveryTime);
}


