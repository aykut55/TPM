#include "TpmBaseClass.h"

CTpmBaseClass::~CTpmBaseClass()
{
    try 
    {

    }
    catch (...) 
    {

    }
}

CTpmBaseClass::CTpmBaseClass()
{
    try 
    {
        m_useSimulator = false;
        tpm = nullptr;
        device = nullptr;
    }
    catch (...) 
    {

    }
}

Tpm2* CTpmBaseClass::GetTpm(void)
{
    return tpm;
}

TpmDevice* CTpmBaseClass::GetDevice(void)
{
    return device;
}

void CTpmBaseClass::SetLogCallback(std::function<void(const std::string&, const bool&)> cb)
{
    try
    {
        m_logCallback = cb;
    }
    catch (...)
    {

    }
}

std::string CTpmBaseClass::GetLastError(void) const
{
    return m_lastError;
}

void CTpmBaseClass::Log(const std::string& msg, bool isError)
{
    if (m_logCallback)
    {
        m_logCallback(msg, isError);
    }
    else
    {
        if (isError)
            std::cerr << msg << std::endl;
        else
            std::cout << msg << std::endl;
    }
}

void CTpmBaseClass::Announce(const char* testName)
{
    SetColor(0);
    cout << endl;
    cout << "================================================================================" << endl;
    cout << "        " << testName << endl;
    cout << "================================================================================" << endl;
    cout << endl << flush;
    SetColor(1);
}

void CTpmBaseClass::SetColor(UINT16 col)
{
#ifdef _WIN32
    UINT16 fColor;
    switch (col) {
    case 0:
        fColor = FOREGROUND_GREEN;
        break;
    case 1:
        fColor = FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_RED;
        break;
    };
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), fColor);
#endif
}

/*void CTpmBaseClass::ClearStringstream(std::stringstream& ss)
{
    ss.str("");
    ss.clear();
}*/