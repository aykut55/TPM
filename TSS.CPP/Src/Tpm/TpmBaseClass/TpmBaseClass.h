#pragma once

#include <string>       // std::string
#include <iostream>     // std::cout
#include <sstream>      // std::stringstream
#include <iomanip>
#include <thread>
#include <atomic>
#include <functional>

#include "Tpm2.h"
#include "TpmDevice.h"
#include "myTpmConfig.h"
#include "Tss.h"

using namespace TpmCpp;

class CTpmBaseClass
{
public:
    virtual ~CTpmBaseClass();
             CTpmBaseClass();

    Tpm2*       GetTpm(void);
    TpmDevice*  GetDevice(void);
    void        SetLogCallback(std::function<void(const std::string&, const bool&)> cb);
    std::string GetLastError(void) const;
    void        Log(const std::string& msg, bool isError = false);
    //void        ClearStringstream(std::stringstream& ss);

protected:
    bool m_useSimulator;
    _TPMCPP Tpm2* tpm;
    _TPMCPP TpmDevice* device = nullptr;

    std::function<void(const std::string&, const bool&)> m_logCallback = nullptr;
    std::string m_lastError;

    void Announce(const char* testName);
    void SetColor(UINT16 col);

    //std::stringstream ss;

private:

};

// .h file
// void SetLogger(std::shared_ptr<std::ostream> logger);
// std::shared_ptr<std::ostream> m_logger;

// .cpp file
// if (m_logger && !m_silentButton)
// (*m_logger) << "Joystick ID " << m_joystickId << " initialized.\n";

// main.cpp
// auto logger = std::make_shared<std::ostream>(std::cout.rdbuf());
// joystick.SetLogger(logger);

