#pragma once

#include "TpmBaseClass.h"

class CTpmSharedDevice : public CTpmBaseClass
{
    static void TpmCallbackStatic(const ByteVec& command, const ByteVec& response, void* context)
    {
        static_cast<CTpmSharedDevice*>(context)->TpmCallback(command, response);
    }

public:
    virtual ~CTpmSharedDevice();
             CTpmSharedDevice(bool useSimulator = false);

    bool    Shutdown(void);
    bool    Initialize(void);
    bool    IsTpmAvailable(void);
    void    StartHealthCheckLoop(int periodSeconds = 5);
    void    StopHealthCheckLoop(void);
    void    SetRecoverCallback(std::function<void(const std::string&, int attemptCount)> cb);
    void    RecoverTpm(int attemptCount);

protected:

private:
    std::function<void(const std::string&, int)> m_recoverCallback = nullptr;

    void CleanHandlesOfType(Tpm2* tpm, TPM_HT handleType, UINT32 rangeBegin = 0, UINT32 rangeEnd = 0x00FFFFFF);
    void StartCallbacks(bool announceCallbacks = false);
    void FinishCallbacks(bool announceCallbacks = false);

    void TpmCallback(const ByteVec& command, const ByteVec& response);
    std::map<_TPMCPP TPM_CC, int> commandsInvoked;
    std::map<_TPMCPP TPM_RC, int> responses;
    std::vector<_TPMCPP TPM_CC> commandsImplemented;

    // health check
    std::thread m_healthThread;
    std::atomic<bool> m_healthStopFlag{ false };
};